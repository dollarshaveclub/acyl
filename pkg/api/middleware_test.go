package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dollarshaveclub/acyl/pkg/models"
	"github.com/gorilla/securecookie"

	"github.com/dollarshaveclub/acyl/pkg/persistence"
)

const (
	testValidMasterAPIKey = "foo"
	testInvalidAPIKey     = "24c1ea12-0a99-11eb-adc1-0242ac120002"
	testCIDR              = "10.10.0.0/16"
)

func TestMiddlewareIPWhitelistSuccess(t *testing.T) {
	_, cn, err := net.ParseCIDR(testCIDR)
	if err != nil {
		t.Fatalf("error parsing CIDR: %v", err)
	}
	ipWhitelistMiddleware.ipwl = []*net.IPNet{cn}
	rc := httptest.NewRecorder()
	h := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	mh := middlewareChain(h, ipWhitelistMiddleware.checkIPWhitelist)
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.10.100.1:34567"
	mh(rc, req)
	if rc.Code != http.StatusNoContent {
		t.Fatalf("should have succeeded: %v", rc.Code)
	}
}

func TestMiddlewareIPWhitelistFailure(t *testing.T) {
	_, cn, err := net.ParseCIDR(testCIDR)
	if err != nil {
		t.Fatalf("error parsing CIDR: %v", err)
	}
	ipWhitelistMiddleware.ipwl = []*net.IPNet{cn}
	rc := httptest.NewRecorder()
	h := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	mh := middlewareChain(h, ipWhitelistMiddleware.checkIPWhitelist)
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.20.10"
	mh(rc, req)
	if rc.Code != http.StatusForbidden {
		t.Fatalf("should have succeeded")
	}
}

func TestMiddlewareMasterAPIKeyAuthSuccess(t *testing.T) {
	dl := persistence.NewFakeDataLayer()
	authMiddleware.apiKeys = []string{testValidMasterAPIKey}
	authMiddleware.DL = dl
	rc := httptest.NewRecorder()
	h := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	mh := middlewareChain(authMiddleware.tokenAuth(h, models.ReadOnlyPermission))
	req, _ := http.NewRequest("GET", "/envs/", nil)
	req.Header.Add(apiKeyHeader, testValidMasterAPIKey)
	mh(rc, req)
	if rc.Code != http.StatusNoContent {
		t.Fatalf("should have succeeded")
	}
}

func TestMiddlewareInvalidMasterAPIKeyAuthFailure(t *testing.T) {
	dl := persistence.NewFakeDataLayer()
	authMiddleware.apiKeys = []string{testValidMasterAPIKey}
	authMiddleware.DL = dl
	rc := httptest.NewRecorder()
	h := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	mh := middlewareChain(authMiddleware.tokenAuth(h, models.ReadOnlyPermission))
	req, _ := http.NewRequest("GET", "/envs/", nil)
	req.Header.Add(apiKeyHeader, testInvalidAPIKey)
	mh(rc, req)
	if rc.Code != http.StatusUnauthorized {
		t.Fatalf("should have succeeded")
	}
}

func TestMiddlewareValidAPIKeyAuthGetSuccess(t *testing.T) {
	dl := persistence.NewFakeDataLayer()
	id, _ := dl.CreateAPIKey(context.Background(), models.ReadOnlyPermission, "foo", "foo description", "jackhandy")
	authMiddleware.apiKeys = []string{testValidMasterAPIKey}
	authMiddleware.DL = dl
	rc := httptest.NewRecorder()
	h := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	mh := middlewareChain(authMiddleware.tokenAuth(h, models.ReadOnlyPermission))
	req, _ := http.NewRequest("GET", "/envs/some-environment", nil)
	req.Header.Add(apiKeyHeader, id.String())
	mh(rc, req)
	if rc.Code != http.StatusNoContent {
		t.Fatalf("should have succeeded")
	}
}

func TestMiddlewareInvalidAPIKeyAuthParseFailure(t *testing.T) {
	dl := persistence.NewFakeDataLayer()
	authMiddleware.apiKeys = []string{testValidMasterAPIKey}
	authMiddleware.DL = dl
	rc := httptest.NewRecorder()
	h := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	mh := middlewareChain(authMiddleware.tokenAuth(h, models.ReadOnlyPermission))
	req, _ := http.NewRequest("GET", "/envs/some-environment", nil)
	req.Header.Add(apiKeyHeader, "invalid-key")
	mh(rc, req)
	if rc.Code != http.StatusForbidden {
		t.Fatalf("should have succeeded")
	}
}

func TestMiddlewareValidAPIKeyAuthReadOnlyDeleteFailure(t *testing.T) {
	dl := persistence.NewFakeDataLayer()
	id, _ := dl.CreateAPIKey(context.Background(), models.WritePermission, "foo", "foo description", "johnsmith")
	authMiddleware.apiKeys = []string{testValidMasterAPIKey}
	authMiddleware.DL = dl
	rc := httptest.NewRecorder()
	h := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	mh := middlewareChain(authMiddleware.tokenAuth(h, models.AdminPermission))
	req, _ := http.NewRequest("DELETE", "/envs/some-environment", nil)
	req.Header.Add(apiKeyHeader, id.String())
	mh(rc, req)
	if rc.Code != http.StatusUnauthorized {
		t.Fatalf("should have succeeded")
	}
}

func TestMiddlewareValidAPIKeyAuthAdminGetSuccess(t *testing.T) {
	dl := persistence.NewFakeDataLayer()
	id, _ := dl.CreateAPIKey(context.Background(), models.AdminPermission, "foo", "foo description", "janejones")
	authMiddleware.apiKeys = []string{testValidMasterAPIKey}
	authMiddleware.DL = dl
	rc := httptest.NewRecorder()
	h := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	mh := middlewareChain(authMiddleware.tokenAuth(h, models.ReadOnlyPermission))
	req, _ := http.NewRequest("GET", "/envs/some-environment", nil)
	req.Header.Add(apiKeyHeader, id.String())
	mh(rc, req)
	if rc.Code != http.StatusNoContent {
		t.Fatalf("should have succeeded")
	}
}

func TestMiddlewareWaitGroupDelay(t *testing.T) {
	authMiddleware.apiKeys = []string{testValidMasterAPIKey}
	rc := httptest.NewRecorder()
	h := func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(250 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}
	mh := middlewareChain(h, waitMiddleware.waitOnRequest)
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add(apiKeyHeader, testValidMasterAPIKey)

	start := time.Now()
	go mh(rc, req)
	time.Sleep(5 * time.Millisecond)
	waitMiddleware.wg.Wait()
	elapsed := time.Since(start)

	if rc.Code != http.StatusNoContent {
		t.Fatalf("should have succeeded")
	}
	if elapsed.Seconds() < 0.2499999 {
		t.Fatalf("should have waited")
	}
}

func TestMiddleware_SessionAuth(t *testing.T) {
	type fields struct {
		cookiekeys [2][32]byte
	}
	var sessID int64
	authKey := randomCookieKey()
	encKey := randomCookieKey()
	defaultHandler := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	expectStatus := func(rc *httptest.ResponseRecorder, status int) error {
		if rc.Result().StatusCode != status {
			return fmt.Errorf("unexpected status code: %v (wanted %v)", rc.Result().StatusCode, status)
		}
		return nil
	}
	expectOK := func(rc *httptest.ResponseRecorder, dl persistence.UISessionsDataLayer) error {
		return expectStatus(rc, 200)
	}
	expectForbidden := func(rc *httptest.ResponseRecorder, dl persistence.UISessionsDataLayer) error {
		return expectStatus(rc, 403)
	}
	tests := []struct {
		name        string
		fields      fields
		enforce     bool
		wantErr     bool
		handler     func(w http.ResponseWriter, r *http.Request)
		dbSetupFunc func(dl persistence.UISessionsDataLayer)
		requestFunc func() *http.Request
		verifyfunc  func(*httptest.ResponseRecorder, persistence.UISessionsDataLayer) error
	}{
		{
			name: "authenticated",
			fields: fields{
				cookiekeys: [2][32]byte{authKey, encKey},
			},
			enforce: true,
			handler: func(w http.ResponseWriter, r *http.Request) {
				if _, err := getSessionFromContext(r.Context()); err != nil {
					t.Fatalf("session missing from context: %v", err)
				}
				w.WriteHeader(http.StatusOK)
			},
			dbSetupFunc: func(dl persistence.UISessionsDataLayer) {
				id, _ := dl.CreateUISession("/some/other/path", []byte("asdf"), net.ParseIP("10.0.0.0"), "some agent", time.Now().UTC().Add(24*time.Hour))
				dl.UpdateUISession(id, "johndoe", []byte(`asdf`), true)
				atomic.StoreInt64(&sessID, int64(id))
			},
			requestFunc: func() *http.Request {
				s := securecookie.New(authKey[:], encKey[:])
				enc, _ := s.Encode(uiSessionName, map[interface{}]interface{}{cookieIDkey: int(atomic.LoadInt64(&sessID))})
				req, _ := http.NewRequest("GET", "https://example.com/some/path", nil)
				req.AddCookie(&http.Cookie{
					Name:  uiSessionName,
					Value: enc,
					Path:  "/",
				})
				return req
			},
			verifyfunc: expectOK,
		},
		{
			name: "unauthenticated",
			fields: fields{
				cookiekeys: [2][32]byte{authKey, encKey},
			},
			enforce:     true,
			dbSetupFunc: func(dl persistence.UISessionsDataLayer) {},
			requestFunc: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/some/path", nil)
				return req
			},
			verifyfunc: expectForbidden,
		},
		{
			name: "unauthenticated-enforce-false",
			fields: fields{
				cookiekeys: [2][32]byte{authKey, encKey},
			},
			enforce:     false,
			dbSetupFunc: func(dl persistence.UISessionsDataLayer) {},
			requestFunc: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/some/path", nil)
				return req
			},
			verifyfunc: expectOK,
		},
		{
			name: "bad keys",
			fields: fields{
				cookiekeys: [2][32]byte{authKey, encKey},
			},
			enforce:     true,
			dbSetupFunc: func(dl persistence.UISessionsDataLayer) {},
			requestFunc: func() *http.Request {
				badAuthKey, badEncKey := randomCookieKey(), randomCookieKey()
				s := securecookie.New(badAuthKey[:], badEncKey[:])
				enc, _ := s.Encode(uiSessionName, map[interface{}]interface{}{cookieIDkey: int(atomic.LoadInt64(&sessID))})
				req, _ := http.NewRequest("GET", "https://example.com/some/path", nil)
				req.AddCookie(&http.Cookie{
					Name:  uiSessionName,
					Value: enc,
					Path:  "/",
				})
				return req
			},
			verifyfunc: expectForbidden,
		},
		{
			name: "missing id",
			fields: fields{
				cookiekeys: [2][32]byte{authKey, encKey},
			},
			enforce:     true,
			dbSetupFunc: func(dl persistence.UISessionsDataLayer) {},
			requestFunc: func() *http.Request {
				s := securecookie.New(authKey[:], encKey[:])
				cookieKey := "invalid"
				enc, _ := s.Encode(uiSessionName, map[interface{}]interface{}{cookieKey: 0})
				req, _ := http.NewRequest("GET", "https://example.com/some/path", nil)
				req.AddCookie(&http.Cookie{
					Name:  uiSessionName,
					Value: enc,
					Path:  "/",
				})
				return req
			},
			verifyfunc: expectForbidden,
		},
		{
			name: "missing session in db",
			fields: fields{
				cookiekeys: [2][32]byte{authKey, encKey},
			},
			enforce:     true,
			dbSetupFunc: func(dl persistence.UISessionsDataLayer) {},
			requestFunc: func() *http.Request {
				s := securecookie.New(authKey[:], encKey[:])
				enc, _ := s.Encode(uiSessionName, map[interface{}]interface{}{cookieIDkey: int(atomic.LoadInt64(&sessID))})
				req, _ := http.NewRequest("GET", "https://example.com/some/path", nil)
				req.AddCookie(&http.Cookie{
					Name:  uiSessionName,
					Value: enc,
					Path:  "/",
				})
				return req
			},
			verifyfunc: expectForbidden,
		},
		{
			name: "expired session",
			fields: fields{
				cookiekeys: [2][32]byte{authKey, encKey},
			},
			enforce: true,
			dbSetupFunc: func(dl persistence.UISessionsDataLayer) {
				id, _ := dl.CreateUISession("/some/other/path", []byte("asdf"), net.ParseIP("10.0.0.0"), "some agent", time.Now().UTC().Add(1*time.Millisecond))
				dl.UpdateUISession(id, "johndoe", []byte(`asdf`), true)
				atomic.StoreInt64(&sessID, int64(id))
			},
			requestFunc: func() *http.Request {
				s := securecookie.New(authKey[:], encKey[:])
				enc, _ := s.Encode(uiSessionName, map[interface{}]interface{}{cookieIDkey: int(atomic.LoadInt64(&sessID))})
				req, _ := http.NewRequest("GET", "https://example.com/some/path", nil)
				req.AddCookie(&http.Cookie{
					Name:  uiSessionName,
					Value: enc,
					Path:  "/",
				})
				time.Sleep(2 * time.Millisecond)
				return req
			},
			verifyfunc: expectForbidden,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dl := persistence.NewFakeDataLayer()
			tt.dbSetupFunc(dl)
			sauth := &sessionAuthenticator{
				Enforce:     tt.enforce,
				CookieStore: newSessionsCookieStore(OAuthConfig{CookieAuthKey: tt.fields.cookiekeys[0], CookieEncKey: tt.fields.cookiekeys[1]}),
				DL:          dl,
			}
			rc := httptest.NewRecorder()
			h := tt.handler
			if h == nil {
				h = defaultHandler
			}
			mh := middlewareChain(h, sauth.sessionAuth)
			mh(rc, tt.requestFunc())
			if err := tt.verifyfunc(rc, dl); err != nil {
				if !tt.wantErr {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
