package api

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/dollarshaveclub/acyl/pkg/config"
	"github.com/dollarshaveclub/acyl/pkg/ghclient"
	"github.com/dollarshaveclub/acyl/pkg/ghevent"
	"github.com/dollarshaveclub/acyl/pkg/nitro/metahelm"
	"github.com/dollarshaveclub/acyl/pkg/persistence"
	"github.com/dollarshaveclub/acyl/pkg/spawner"
	"github.com/pkg/errors"
	muxtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
)

const DefaultPodContainerLogLines = 100

type apiBase struct {
	logger *log.Logger
	wg     sync.WaitGroup
}

func (api *apiBase) httpError(w http.ResponseWriter, err error, code int) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	msg := fmt.Sprintf(`{"error_details":"%v"}`, err)
	w.Write([]byte(msg))
	api.logger.Println(msg)
}

func (api *apiBase) badRequestError(w http.ResponseWriter, err error) {
	api.httpError(w, err, http.StatusBadRequest)
}

func (api *apiBase) internalError(w http.ResponseWriter, err error) {
	api.httpError(w, err, http.StatusInternalServerError)
}

func (api *apiBase) notfoundError(w http.ResponseWriter) {
	api.httpError(w, fmt.Errorf("not found"), http.StatusNotFound)
}

func (api *apiBase) forbiddenError(w http.ResponseWriter, msg string) {
	api.httpError(w, fmt.Errorf("forbidden: %v", msg), http.StatusForbidden)
}

type routeLogger struct {
	route  string
	logger *log.Logger
}

// Logf logs a log string to the base logger prefixed by the request route
func (r routeLogger) Logf(msg string, args ...interface{}) {
	if r.logger == nil {
		r.logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	r.logger.Printf(r.route+": "+msg, args...)
}

// rlogger returns a new route logger for a request
func (api *apiBase) rlogger(r *http.Request) routeLogger {
	return routeLogger{
		logger: api.logger,
		route:  r.URL.Path,
	}
}

// Dependencies are the dependencies required for the API
type Dependencies struct {
	DataLayer          persistence.DataLayer
	GitHubEventWebhook *ghevent.GitHubEventWebhook
	EnvironmentSpawner spawner.EnvironmentSpawner
	RepoClient         ghclient.RepoClient
	ServerConfig       config.ServerConfig
	DatadogServiceName string
	Logger             *log.Logger
	KubernetesReporter metahelm.KubernetesReporter
}

// Manager describes an object capable of registering API versions and waiting on requests
type Manager interface {
	RegisterVersions(deps *Dependencies)
	Wait()
}

type uiRegisterOptions struct {
	reload           bool
	apiBaseURL       string
	assetsPath       string
	routePrefix      string
	branding         config.UIBrandingConfig
	dummySessionUser string
}

type registerOptions struct {
	debugEndpoints bool
	apiKeys        []string
	ipWhitelist    []*net.IPNet
	uiOptions      uiRegisterOptions
	ghConfig       config.GithubConfig
}

// RegisterOption is an option for RegisterVersions()
type RegisterOption func(*registerOptions)

// WithDebugEndpoints causes RegisterVersions to register debug pprof endpoints
func WithDebugEndpoints() RegisterOption {
	return func(ropts *registerOptions) {
		ropts.debugEndpoints = true
	}
}

// WithAPIKeys supplies API keys for protected endpoints
func WithAPIKeys(keys []string) RegisterOption {
	if keys == nil {
		keys = []string{}
	}
	return func(ropts *registerOptions) {
		ropts.apiKeys = keys
	}
}

// WithIPWhitelist supplies IP CIDRs for whitelisted endpoints. Invalid CIDRs are ignored.
func WithIPWhitelist(ips []string) RegisterOption {
	ipwl := []*net.IPNet{}
	for _, cidr := range ips {
		_, cn, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		ipwl = append(ipwl, cn)
	}
	return func(ropts *registerOptions) {
		ropts.ipWhitelist = ipwl
	}
}

func WithUIBaseURL(baseURL string) RegisterOption {
	return func(ropts *registerOptions) {
		ropts.uiOptions.apiBaseURL = baseURL
	}
}

func WithUIAssetsPath(assetsPath string) RegisterOption {
	return func(ropts *registerOptions) {
		ropts.uiOptions.assetsPath = assetsPath
	}
}

func WithUIRoutePrefix(routePrefix string) RegisterOption {
	return func(ropts *registerOptions) {
		ropts.uiOptions.routePrefix = routePrefix
	}
}

func WithUIReload() RegisterOption {
	return func(ropts *registerOptions) {
		ropts.uiOptions.reload = true
	}
}

func WithUIBranding(branding config.UIBrandingConfig) RegisterOption {
	return func(ropts *registerOptions) {
		ropts.uiOptions.branding = branding
	}
}

func WithUIDummySessionUser(user string) RegisterOption {
	return func(ropts *registerOptions) {
		ropts.uiOptions.dummySessionUser = user
	}
}

func WithGitHubConfig(ghconfig config.GithubConfig) RegisterOption {
	return func(ropts *registerOptions) {
		ropts.ghConfig = ghconfig
	}
}

// Dispatcher is the concrete implementation of Manager
type Dispatcher struct {
	AppGHClientFactoryFunc func(tkn string) ghclient.GitHubAppInstallationClient
	s                      *http.Server
	waitgroups             []*sync.WaitGroup
	uiapi                  *uiapi
}

// NewDispatcher returns an initialized Dispatcher.
// s should be preconfigured to be able to run ListenAndServeTLS()
func NewDispatcher(s *http.Server) *Dispatcher {
	return &Dispatcher{s: s}
}

// Stop stops any async processes such as UI sessions cleanup
func (d *Dispatcher) Stop() {
	if d.uiapi != nil {
		d.uiapi.Close()
	}
}

// RegisterVersions registers all API versions with the supplied http.Server
func (d *Dispatcher) RegisterVersions(deps *Dependencies, ro ...RegisterOption) error {
	if d.s == nil || deps == nil {
		return fmt.Errorf("one of s (%v) or deps (%v) is nil", d.s, deps)
	}
	ropts := &registerOptions{}
	for _, opt := range ro {
		opt(ropts)
	}

	if d.AppGHClientFactoryFunc == nil {
		d.AppGHClientFactoryFunc = func(tkn string) ghclient.GitHubAppInstallationClient { return ghclient.NewGitHubClient(tkn) }
	}

	oauthcfg := OAuthConfig{
		Enforce:                ropts.ghConfig.OAuth.Enforce,
		DummySessionUser:       ropts.uiOptions.dummySessionUser,
		AppInstallationID:      int64(ropts.ghConfig.OAuth.AppInstallationID),
		ClientID:               ropts.ghConfig.OAuth.ClientID,
		ClientSecret:           ropts.ghConfig.OAuth.ClientSecret,
		AppGHClientFactoryFunc: d.AppGHClientFactoryFunc,
		CookieAuthKey:          ropts.ghConfig.OAuth.CookieAuthKey,
		CookieEncKey:           ropts.ghConfig.OAuth.CookieEncKey,
		UserTokenEncKey:        ropts.ghConfig.OAuth.UserTokenEncKey,
	}
	if err := oauthcfg.SetValidateURL("https://github.com/login/oauth/access_token"); err != nil {
		return errors.Wrap(err, "error parsing validate URL")
	}
	if err := oauthcfg.SetAuthURL("https://github.com/login/oauth/authorize"); err != nil {
		return errors.Wrap(err, "error parsing validate URL")
	}

	authMiddleware.apiKeys = ropts.apiKeys
	authMiddleware.DL = deps.DataLayer
	ipWhitelistMiddleware.ipwl = ropts.ipWhitelist
	sessionAuthMiddleware.Enforce = oauthcfg.Enforce
	sessionAuthMiddleware.CookieStore = newSessionsCookieStore(oauthcfg)
	sessionAuthMiddleware.DL = deps.DataLayer

	r := muxtrace.NewRouter(muxtrace.WithServiceName(deps.DatadogServiceName))
	r.HandleFunc("/health", d.healthHandler).Methods("GET")

	apiv0, err := newV0API(deps.DataLayer, deps.GitHubEventWebhook, deps.EnvironmentSpawner, deps.RepoClient, ropts.ghConfig, deps.ServerConfig, deps.Logger)
	if err != nil {
		return fmt.Errorf("error creating api v0: %v", err)
	}
	err = apiv0.register(r)
	if err != nil {
		return fmt.Errorf("error registering api v0: %v", err)
	}
	d.waitgroups = append(d.waitgroups, &apiv0.wg)

	apiv1, err := newV1API(deps.DataLayer, deps.GitHubEventWebhook, deps.EnvironmentSpawner, deps.ServerConfig, deps.Logger)
	if err != nil {
		return fmt.Errorf("error creating api v1: %v", err)
	}
	err = apiv1.register(r)
	if err != nil {
		return fmt.Errorf("error registering api v1: %v", err)
	}
	d.waitgroups = append(d.waitgroups, &apiv1.wg)

	apiv2, err := newV2API(
		deps.DataLayer,
		deps.GitHubEventWebhook,
		deps.EnvironmentSpawner,
		deps.ServerConfig,
		oauthcfg,
		deps.Logger,
		deps.KubernetesReporter)
	if err != nil {
		return fmt.Errorf("error creating api v2: %v", err)
	}
	err = apiv2.register(r)
	if err != nil {
		return fmt.Errorf("error registering api v2: %v", err)
	}
	d.waitgroups = append(d.waitgroups, &apiv2.wg)

	// The UI API does not participate in the wait group
	uiapi, err := newUIAPI(ropts.uiOptions.apiBaseURL,
		ropts.uiOptions.assetsPath,
		ropts.uiOptions.routePrefix,
		ropts.uiOptions.reload,
		ropts.uiOptions.branding,
		deps.DataLayer,
		oauthcfg,
		deps.Logger)
	if err != nil {
		return fmt.Errorf("error creating UI api: %v", err)
	}
	err = uiapi.register(r)
	if err != nil {
		return fmt.Errorf("error registering UI api: %v", err)
	}
	uiapi.StartSessionsCleanup()
	d.uiapi = uiapi

	if ropts.debugEndpoints {
		dbg := newDebugEndpoints()
		err = dbg.register(r)
		if err != nil {
			return fmt.Errorf("error registering debug endpoints: %v", err)
		}
	}
	d.s.Handler = r
	return nil
}

// WaitHandlers waits for any handlers that have used waitMiddleware to finish
func (d *Dispatcher) WaitForHandlers() {
	waitMiddleware.wg.Wait()
}

// WaitAsync waits for any async goroutines to finish
func (d *Dispatcher) WaitForAsync() {
	for i := range d.waitgroups {
		d.waitgroups[i].Wait()
	}
}

func (d *Dispatcher) healthHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	w.WriteHeader(http.StatusOK)
}
