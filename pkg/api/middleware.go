package api

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"

	"github.com/dollarshaveclub/acyl/pkg/ghclient"
	"github.com/dollarshaveclub/acyl/pkg/models"
	"github.com/dollarshaveclub/acyl/pkg/persistence"
)

type middleware func(http.HandlerFunc) http.HandlerFunc

// middlewareChain is used to chain middlewares on a request handler.
// Usage: router.HandleFunc("/foo", middlewareChain(myhandler, authMiddleware.authRequest, waitMiddleware.waitOnRequest))
func middlewareChain(f http.HandlerFunc, m ...middleware) http.HandlerFunc {
	if len(m) < 1 {
		return f
	}
	return m[0](middlewareChain(f, m[1:cap(m)]...))
}

const (
	apiKeyHeader = "API-Key"
)

// authMiddleware checks for correct API key header or aborts with Unauthorized
var authMiddleware = reqAuthorizor{}

type reqAuthorizor struct {
	apiKeys []string
	DL      persistence.APIKeyDataLayer
}

func (ra reqAuthorizor) tokenAuth(f http.HandlerFunc, minPermission models.PermissionLevel) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := func(msg string, args ...interface{}) {
			log.Printf("tokenAuth: "+msg, args...)
		}
		key := r.Header.Get(apiKeyHeader)
		if key != "" {
			for _, k := range ra.apiKeys {
				if key == k {
					f(w, r)
					return
				}
			}
			keyID, err := uuid.Parse(key)
			if err != nil {
				log("error parsing api key id: %v", err)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			apikey, err := authMiddleware.DL.GetAPIKeyById(r.Context(), keyID)
			if err != nil {
				log("error getting api key: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if apikey != nil {
				if apikey.PermissionLevel >= minPermission {
					err = authMiddleware.DL.UpdateAPIKeyLastUsed(r.Context(), keyID)
					if err != nil {
						log("error updating api key: %v", err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					f(w, r)
					return
				}
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
	}
}

// waitMiddleware increments a waitgroup for the duration of the request
var waitMiddleware = waitOnRequests{}

type waitOnRequests struct {
	wg sync.WaitGroup
}

func (wr *waitOnRequests) waitOnRequest(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		wr.wg.Add(1)
		f(w, r)
		wr.wg.Done()
	}
}

var ipWhitelistMiddleware = ipWhitelistChecker{}

type ipWhitelistChecker struct {
	ipwl []*net.IPNet
}

func (iwc *ipWhitelistChecker) checkIPWhitelist(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		addr := net.ParseIP(host)
		for _, cidr := range iwc.ipwl {
			if cidr.Contains(addr) {
				f(w, r)
				return
			}
		}
		w.WriteHeader(http.StatusForbidden)
	}
}

// globals are a bad idea but this is how all the other middlewares work, so...
var sessionAuthMiddleware = &sessionAuthenticator{}

// these are used to store the UI session in the request context
const sessionContextKeyVal = "ctx_acyl_session"

type sessionContextKey string

func withSession(ctx context.Context, uis models.UISession) context.Context {
	return context.WithValue(ctx, sessionContextKey(sessionContextKeyVal), uis)
}

func getSessionFromContext(ctx context.Context) (models.UISession, error) {
	uis, ok := ctx.Value(sessionContextKey(sessionContextKeyVal)).(models.UISession)
	if !ok {
		return models.UISession{}, fmt.Errorf("session missing from context")
	}
	if !uis.Authenticated || uis.GitHubUser == "" {
		return models.UISession{}, fmt.Errorf("unauthenticated session or empty GitHub user")
	}
	return uis, nil
}

// sessionAuthenticator is a middleware that authenticates UI API calls with session cookies
type sessionAuthenticator struct {
	Enforce     bool
	CookieStore sessions.Store
	DL          persistence.UISessionsDataLayer
}

func (sa *sessionAuthenticator) sessionAuth(f http.HandlerFunc) http.HandlerFunc {
	if sa.CookieStore == nil || sa.DL == nil {
		return f
	}
	if !sa.Enforce {
		return f
	}
	log := func(msg string, args ...interface{}) {
		log.Printf("sessionAuth: "+msg, args...)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		accessDenied := func() {
			w.WriteHeader(http.StatusForbidden)
		}
		// Get returns the session from the cookie or creates a new session if missing
		sess, err := sa.CookieStore.Get(r, uiSessionName)
		if err != nil {
			// invalid cookie or failure to authenticate/decrypt
			log("error getting session, access denied: %v", err)
			accessDenied()
			return
		}
		if sess.IsNew {
			log("session missing from request, access denied")
			accessDenied()
			return
		}
		id, ok := sess.Values[cookieIDkey].(int)
		if !ok {
			// missing id
			log("session id is missing from cookie")
			accessDenied()
			return
		}
		uis, err := sa.DL.GetUISession(id)
		if err != nil {
			log("error getting session by id: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if uis == nil {
			// not found in db
			log("session %v not found in db, access denied", id)
			accessDenied()
			return
		}
		if !uis.IsValid() {
			if err := sa.DL.DeleteUISession(id); err != nil {
				log("error deleting session: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			log("session %v isn't valid, access denied", id)
			accessDenied()
			return
		}
		f(w, r.Clone(withSession(r.Context(), *uis)))
	}
}

type userPermissions struct {
	instID int64
	deckey [32]byte
	gcfunc func(tkn string) ghclient.GitHubAppInstallationClient
}

func userPermissionsClient(oauth OAuthConfig) *userPermissions {
	return &userPermissions{
		instID: oauth.AppInstallationID,
		deckey: oauth.UserTokenEncKey,
		gcfunc: oauth.AppGHClientFactoryFunc,
	}
}

// GetUserVisibleRepos returns the names of all repos (owner/repo) for which the authenticated user has "pull" permissions
func (up *userPermissions) GetUserVisibleRepos(ctx context.Context, uis models.UISession) ([]string, error) {
	tkn, err := uis.GetUserToken(up.deckey)
	if err != nil {
		return nil, errors.Wrap(err, "error decrypting user token")
	}

	ghc := up.gcfunc(tkn)

	rps, err := ghc.GetUserAppRepoPermissions(ctx, up.instID)
	if err != nil {
		return nil, errors.Wrap(err, "error getting user visible repos")
	}
	out := []string{}
	for _, r := range rps {
		if r.Pull {
			out = append(out, r.Repo)
		}
	}
	return out, nil
}

// GetUserWritableRepos returns the names of all repos (owner/repo) for which the authenticated user has "admin" or "push" permissions
func (up *userPermissions) GetUserWritableRepos(ctx context.Context, uis models.UISession) (map[string]ghclient.AppRepoPermissions, error) {
	tkn, err := uis.GetUserToken(up.deckey)
	if err != nil {
		return nil, errors.Wrap(err, "error decrypting user token")
	}

	ghc := up.gcfunc(tkn)

	rps, err := ghc.GetUserAppRepoPermissions(ctx, up.instID)
	if err != nil {
		return nil, errors.Wrap(err, "error getting user repos")
	}
	out := make(map[string]ghclient.AppRepoPermissions, len(rps))
	for _, r := range rps {
		if r.Admin || r.Push {
			out[r.Repo] = r
		}
	}
	return out, nil
}
