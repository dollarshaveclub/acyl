package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dollarshaveclub/acyl/pkg/ghapp"
	"github.com/dollarshaveclub/acyl/pkg/ghclient"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/rs/zerolog"

	"github.com/dollarshaveclub/acyl/pkg/config"
	"github.com/dollarshaveclub/acyl/pkg/eventlogger"
	"github.com/dollarshaveclub/acyl/pkg/ghevent"
	"github.com/dollarshaveclub/acyl/pkg/models"
	ncontext "github.com/dollarshaveclub/acyl/pkg/nitro/context"
	"github.com/dollarshaveclub/acyl/pkg/persistence"
	"github.com/dollarshaveclub/acyl/pkg/spawner"
	"github.com/gorilla/mux"
	muxtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/ext"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

// API output schema
type v0QAEnvironment struct {
	Name                     string                      `json:"name"`
	Created                  time.Time                   `json:"created"`
	RawEvents                []string                    `json:"-"`
	Events                   []models.QAEnvironmentEvent `json:"events"`
	Hostname                 string                      `json:"hostname"`
	QAType                   string                      `json:"qa_type"`
	User                     string                      `json:"user"`
	Repo                     string                      `json:"repo"`
	PullRequest              uint                        `json:"pull_request"`
	SourceSHA                string                      `json:"source_sha"`
	BaseSHA                  string                      `json:"base_sha"`
	SourceBranch             string                      `json:"source_branch"`
	BaseBranch               string                      `json:"base_branch"`
	RawStatus                string                      `json:"status"`
	Status                   models.EnvironmentStatus    `json:"status_int"`
	RefMap                   models.RefMap               `json:"ref_map"`
	AminoServiceToPort       map[string]int64            `json:"amino_service_to_port"`
	AminoKubernetesNamespace string                      `json:"amino_kubernetes_namespace"`
	AminoEnvironmentID       int                         `json:"amino_environment_id"`
}

func v0QAEnvironmentFromQAEnvironment(qae *models.QAEnvironment) *v0QAEnvironment {
	return &v0QAEnvironment{
		Name:                     qae.Name,
		Created:                  qae.Created,
		RawEvents:                qae.RawEvents,
		Events:                   qae.Events,
		Hostname:                 qae.Hostname,
		QAType:                   qae.QAType,
		User:                     qae.User,
		Repo:                     qae.Repo,
		PullRequest:              qae.PullRequest,
		SourceSHA:                qae.SourceSHA,
		BaseSHA:                  qae.BaseSHA,
		SourceBranch:             qae.SourceBranch,
		BaseBranch:               qae.BaseBranch,
		RawStatus:                qae.RawStatus,
		Status:                   qae.Status,
		RefMap:                   qae.RefMap,
		AminoServiceToPort:       qae.AminoServiceToPort,
		AminoKubernetesNamespace: qae.AminoKubernetesNamespace,
		AminoEnvironmentID:       qae.AminoEnvironmentID,
	}
}

type v0api struct {
	apiBase
	dl  persistence.DataLayer
	ge  *ghevent.GitHubEventWebhook
	es  spawner.EnvironmentSpawner
	sc  config.ServerConfig
	gha *ghapp.GitHubApp
	rc  ghclient.RepoClient
}

func newV0API(dl persistence.DataLayer, ge *ghevent.GitHubEventWebhook, es spawner.EnvironmentSpawner, rc ghclient.RepoClient, ghc config.GithubConfig, sc config.ServerConfig, logger *stdlog.Logger) (*v0api, error) {
	api := &v0api{
		apiBase: apiBase{
			logger: logger,
		},
		dl: dl,
		ge: ge,
		es: es,
		sc: sc,
		rc: rc,
	}
	gha, err := ghapp.NewGitHubApp(ghc.PrivateKeyPEM, ghc.AppID, ghc.AppHookSecret, []string{"opened", "reopened", "closed", "synchronize"}, api.processWebhook, dl)
	if err != nil {
		return nil, errors.Wrap(err, "error creating GitHub app")
	}
	api.gha = gha
	return api, nil
}

func (api *v0api) register(r *muxtrace.Router) error {
	if r == nil {
		return fmt.Errorf("router is nil")
	}
	// backwards-compatible routes
	r.HandleFunc("/spawn", middlewareChain(api.legacyGithubWebhookHandler, waitMiddleware.waitOnRequest)).Methods("POST")
	r.HandleFunc("/webhook", middlewareChain(api.legacyGithubWebhookHandler, waitMiddleware.waitOnRequest)).Methods("POST")
	r.HandleFunc("/envs/_search", middlewareChain(authMiddleware.tokenAuth(api.envSearchHandler, models.ReadOnlyPermission))).Methods("GET")
	r.HandleFunc("/envs/{name}", middlewareChain(authMiddleware.tokenAuth(api.envDetailHandler, models.ReadOnlyPermission))).Methods("GET")
	r.HandleFunc("/envs/{name}", middlewareChain(authMiddleware.tokenAuth(api.envDestroyHandler, models.AdminPermission), waitMiddleware.waitOnRequest)).Methods("DELETE")
	ghahandler := api.gha.Handler()
	r.HandleFunc("/ghapp/webhook", middlewareChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// allow request logging by bundling a zerolog logger into the request context
		logger := zerolog.New(os.Stdout)
		r = r.Clone(logger.WithContext(r.Context()))
		ghahandler.ServeHTTP(w, r)
	}), waitMiddleware.waitOnRequest)).Methods("POST")

	// DEPRECATED: no longer supported, please use /envs/_search
	r.HandleFunc("/envs", middlewareChain(authMiddleware.tokenAuth(api.envListHandler, models.ReadOnlyPermission))).Methods("GET")
	r.HandleFunc("/envs/", middlewareChain(authMiddleware.tokenAuth(api.envListHandler, models.ReadOnlyPermission))).Methods("GET")

	// DEPRECATED: original Lambda-based DQA implementation, no longer supported
	r.HandleFunc("/envs/{name}/success", middlewareChain(authMiddleware.tokenAuth(api.envSuccessHandler, models.WritePermission))).Methods("POST")
	r.HandleFunc("/envs/{name}/failure", middlewareChain(authMiddleware.tokenAuth(api.envFailureHandler, models.WritePermission))).Methods("POST")
	r.HandleFunc("/envs/{name}/event", middlewareChain(authMiddleware.tokenAuth(api.envEventHandler, models.WritePermission))).Methods("POST")

	// v0 routes
	r.HandleFunc("/v0/spawn", middlewareChain(api.legacyGithubWebhookHandler, waitMiddleware.waitOnRequest)).Methods("POST")
	r.HandleFunc("/v0/webhook", middlewareChain(api.legacyGithubWebhookHandler, waitMiddleware.waitOnRequest)).Methods("POST")
	r.HandleFunc("/v0/envs/_search", middlewareChain(authMiddleware.tokenAuth(api.envSearchHandler, models.ReadOnlyPermission))).Methods("GET")
	r.HandleFunc("/v0/envs/{name}", middlewareChain(authMiddleware.tokenAuth(api.envDetailHandler, models.ReadOnlyPermission))).Methods("GET")
	r.HandleFunc("/v0/envs/{name}", middlewareChain(authMiddleware.tokenAuth(api.envDestroyHandler, models.AdminPermission), waitMiddleware.waitOnRequest)).Methods("DELETE")

	// DEPRECATED: no longer supported, please use /v0/envs/_search
	r.HandleFunc("/v0/envs", middlewareChain(authMiddleware.tokenAuth(api.envListHandler, models.ReadOnlyPermission))).Methods("GET")
	r.HandleFunc("/v0/envs/", middlewareChain(authMiddleware.tokenAuth(api.envListHandler, models.ReadOnlyPermission))).Methods("GET")

	// DEPRECATED: original Lambda-based DQA implementation, no longer supported
	r.HandleFunc("/v0/envs/{name}/success", middlewareChain(authMiddleware.tokenAuth(api.envSuccessHandler, models.WritePermission))).Methods("POST")
	r.HandleFunc("/v0/envs/{name}/failure", middlewareChain(authMiddleware.tokenAuth(api.envFailureHandler, models.WritePermission))).Methods("POST")
	r.HandleFunc("/v0/envs/{name}/event", middlewareChain(authMiddleware.tokenAuth(api.envEventHandler, models.WritePermission))).Methods("POST")

	return nil
}

// MaxAsyncActionTimeout is the maximum amount of time an asynchronous action can take before it's forcibly cancelled
// This is mainly a failsafe against leaking goroutines, additional more strict timeout logic is implemented by environment operations code.
// If this timeout occurs, no notifications will be sent to the user.
var MaxAsyncActionTimeout = 32 * time.Minute

func setTagsForGithubWebhookHandler(span tracer.Span, rd models.RepoRevisionData) {
	span.SetTag("base_branch", rd.BaseBranch)
	span.SetTag("base_sha", rd.BaseSHA)
	span.SetTag("pull_request", rd.PullRequest)
	span.SetTag("repo", rd.Repo)
	span.SetTag("source_branch", rd.SourceBranch)
	span.SetTag("source_ref", rd.SourceRef)
	span.SetTag("source_sha", rd.SourceSHA)
	span.SetTag("user", rd.User)
}

func (api *v0api) processWebhook(ctx context.Context, action string, rrd models.RepoRevisionData) error {
	// As of 03/13/2019, Datadog seems to only allow monitors to be setup based
	// off the root level span of a trace.
	// While we could connect this with span found in r.Context(), this would
	// prevent us from making usable monitors in Datadog, since we respond with
	// 200 ok even though the async action may fail.
	span := tracer.StartSpan("webhook_processor")

	// We need to set this sampling priority tag in order to allow distributed tracing to work.
	// This only needs to be done for the root level span as the value is propagated down.
	// https://docs.datadoghq.com/tracing/getting_further/trace_sampling_and_storage/#priority-sampling-for-distributed-tracing
	span.SetTag(ext.SamplingPriority, ext.PriorityUserKeep)

	// new context for async actions since ctx will cancel when the webhook request connection is closed
	ctx2 := context.Background()
	// embed the eventlogger & github client from original context
	ctx2 = ghapp.CloneGitHubClientContext(ctx2, ctx)
	ctx2 = eventlogger.NewEventLoggerContext(ctx2, eventlogger.GetLogger(ctx))
	// embed the cancel func for later cancellation and overwrite the initial context bc we don't need it any longer
	ctx = ncontext.NewCancelFuncContext(context.WithCancel(ctx2))

	// enforce an unknown status stub before proceeding with action
	eventlogger.GetLogger(ctx).SetNewStatus(models.UnknownEventStatusType, "<undefined>", rrd)
	log := eventlogger.GetLogger(ctx).Printf

	// Events may be received for repos that have the github app installed but do not themselves contain an acyl.yml
	// (eg, repos that are dependencies of other repos that do contain acyl.yml)
	// therefore if acyl.yml is not found, ignore the event and return nil error so we don't set an error commit status on that repo
	log("checking for triggering repo acyl.yml in %v@%v", rrd.Repo, rrd.SourceSHA)
	if _, err := api.rc.GetFileContents(ctx, rrd.Repo, "acyl.yml", rrd.SourceSHA); err != nil {
		if strings.Contains(err.Error(), "404 Not Found") { // this is also returned if permissions are incorrect
			log("acyl.yml is missing for repo, ignoring event")
			return nil
		}
		log("error checking existence of acyl.yml: %v", err)
		return errors.Wrap(err, "error checking existence of acyl.yml")
	}
	log("acyl.yml found, continuing to process event")

	setTagsForGithubWebhookHandler(span, rrd)
	ctx = tracer.ContextWithSpan(ctx, span)

	switch action {
	case "reopened":
		fallthrough
	case "opened":
		log("starting async processing for %v", action)
		api.wg.Add(1)
		go func() {
			var err error
			defer func() { span.Finish(tracer.WithError(err)) }()
			defer api.wg.Done()
			ctx, cf := context.WithTimeout(ctx, MaxAsyncActionTimeout)
			defer cf() // guarantee that any goroutines created with the ctx are cancelled
			name, err := api.es.Create(ctx, rrd)
			if err != nil {
				log("finished processing create with error: %v", err)
				return
			}
			log("success processing create event (env: %q); done", name)
		}()
	case "synchronize":
		log("starting async processing for %v", action)
		api.wg.Add(1)
		go func() {
			var err error
			defer func() { span.Finish(tracer.WithError(err)) }()
			defer api.wg.Done()
			ctx, cf := context.WithTimeout(ctx, MaxAsyncActionTimeout)
			defer cf() // guarantee that any goroutines created with the ctx are cancelled
			name, err := api.es.Update(ctx, rrd)
			if err != nil {
				log("finished processing update with error: %v", err)
				return
			}
			log("success processing update event (env: %q); done", name)
		}()
	case "closed":
		log("starting async processing for %v", action)
		api.wg.Add(1)
		go func() {
			var err error
			defer func() { span.Finish(tracer.WithError(err)) }()
			defer api.wg.Done()
			ctx, cf := context.WithTimeout(ctx, MaxAsyncActionTimeout)
			defer cf() // guarantee that any goroutines created with the ctx are cancelled
			err = api.es.Destroy(ctx, rrd, models.DestroyApiRequest)
			if err != nil {
				log("finished processing destroy with error: %v", err)
				return
			}
			log("success processing destroy event; done")
		}()
	default:
		log("unknown action type: %v", action)
		err := fmt.Errorf("unknown action type: %v (event_log_id: %v)", action, eventlogger.GetLogger(ctx).ID.String())
		span.Finish(tracer.WithError(err))
		return err
	}

	return nil
}

// legacyGithubWebhookHandler serves the legacy (manually set up) GitHook webhook endpoint
func (api *v0api) legacyGithubWebhookHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	span := tracer.StartSpan("legacy_github_webhook_handler")
	var err error
	defer func() {
		span.Finish(tracer.WithError(err))
		if err != nil {
			api.logger.Printf("webhook handler error: %v", err)
		}
	}()

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		api.badRequestError(w, err)
		return
	}
	sig := r.Header.Get("X-Hub-Signature")
	if sig == "" {
		err = errors.New("X-Hub-Signature-Missing")
		api.forbiddenError(w, err.Error())
		return
	}
	did, err := uuid.Parse(r.Header.Get("X-GitHub-Delivery"))
	if err != nil {
		// Ignore invalid or missing Delivery ID
		did = uuid.Nil
	}
	out, err := api.ge.New(b, did, sig)
	if err != nil {
		_, bsok := err.(ghevent.BadSignature)
		if bsok {
			api.forbiddenError(w, "invalid hub signature")
		} else {
			api.badRequestError(w, err)
		}
		return
	}

	log := out.Logger.Printf
	ctx := eventlogger.NewEventLoggerContext(context.Background(), out.Logger)

	accepted := func() {
		w.WriteHeader(http.StatusAccepted)
		w.Header().Add("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"event_log_id": "%v"}`, out.Logger.ID.String())))
	}

	if out.Action == ghevent.NotRelevant {
		log("event not relevant: %v", out.Action)
		accepted()
		return
	}
	if out.RRD == nil {
		log("repo data is nil")
		api.internalError(w, fmt.Errorf("RepoData is nil (event_log_id: %v)", out.Logger.ID.String()))
		return
	}
	if out.RRD.SourceBranch == "" && out.Action != ghevent.NotRelevant {
		api.internalError(w, fmt.Errorf("RepoData.SourceBranch has no value (event_log_id: %v)", out.Logger.ID.String()))
		return
	}

	var action string
	switch out.Action {
	case ghevent.CreateNew:
		action = "opened"
	case ghevent.Update:
		action = "synchronize"
	case ghevent.Destroy:
		action = "closed"
	default:
		action = "unknown"
	}

	err = api.processWebhook(ctx, action, *out.RRD)
	if err != nil {
		api.internalError(w, err)
		return
	}
	accepted()
}

// DEPRECATED: no longer supported, please use /env/_search, or /v0/env/_search
func (api *v0api) envListHandler(w http.ResponseWriter, r *http.Request) {
	var fullDetails bool
	envs, err := api.dl.GetQAEnvironments(r.Context())
	if err != nil {
		api.internalError(w, fmt.Errorf("error getting environments: %v", err))
		return
	}
	if val, ok := r.URL.Query()["full_details"]; ok {
		for _, v := range val {
			if v == "true" {
				fullDetails = true
			}
		}
	}
	var j []byte
	if fullDetails {
		output := []v0QAEnvironment{}
		for _, e := range envs {
			output = append(output, *v0QAEnvironmentFromQAEnvironment(&e))
		}
		j, err = json.Marshal(output)
		if err != nil {
			api.internalError(w, fmt.Errorf("error marshaling environments: %v", err))
			return
		}
	} else {
		nl := []string{}
		for _, e := range envs {
			nl = append(nl, e.Name)
		}
		j, err = json.Marshal(nl)
		if err != nil {
			api.internalError(w, fmt.Errorf("error marshaling environments: %v", err))
			return
		}
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write(j)
}

func (api *v0api) envDetailHandler(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	qa, err := api.dl.GetQAEnvironmentConsistently(r.Context(), name)
	if err != nil {
		api.internalError(w, fmt.Errorf("error getting environment: %v", err))
		return
	}
	if qa == nil {
		api.notfoundError(w)
		return
	}

	output := v0QAEnvironmentFromQAEnvironment(qa)
	j, err := json.Marshal(output)
	if err != nil {
		api.internalError(w, fmt.Errorf("error marshaling environment: %v", err))
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write(j)
}

func (api *v0api) envDestroyHandler(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	qa, err := api.dl.GetQAEnvironmentConsistently(r.Context(), name)
	if err != nil {
		api.internalError(w, err)
		return
	}
	if qa == nil {
		api.notfoundError(w)
		return
	}
	go func() {
		err := api.es.DestroyExplicitly(context.Background(), qa, models.DestroyApiRequest)
		if err != nil {
			api.logger.Printf("error destroying QA: %v: %v", name, err)
		}
	}()
	w.WriteHeader(http.StatusNoContent)
}

// DEPRECATED: original Lambda-based DQA implementation, no longer supported
func (api *v0api) envSuccessHandler(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	err := api.es.Success(r.Context(), name)
	if err != nil {
		api.internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DEPRECATED: original Lambda-based DQA implementation, no longer supported
func (api *v0api) envFailureHandler(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	err := api.es.Failure(r.Context(), name, "")
	if err != nil {
		api.internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DEPRECATED: original Lambda-based DQA implementation, no longer supported
func (api *v0api) envEventHandler(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	event := models.QAEnvironmentEvent{}
	err := d.Decode(&event)
	if err != nil {
		api.badRequestError(w, err)
		return
	}
	err = api.dl.AddEvent(r.Context(), name, event.Message)
	if err != nil {
		api.internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *v0api) envSearchHandler(w http.ResponseWriter, r *http.Request) {
	qvars := r.URL.Query()
	if _, ok := qvars["pr"]; ok {
		if _, ok := qvars["repo"]; !ok {
			api.badRequestError(w, fmt.Errorf("search by PR requires repo name"))
			return
		}
	}
	if status, ok := qvars["status"]; ok {
		if status[0] == "destroyed" && len(qvars) == 1 {
			api.badRequestError(w, fmt.Errorf("'destroyed' status searches require at least one other search parameter"))
			return
		}
	}
	if len(qvars) == 0 {
		api.badRequestError(w, fmt.Errorf("at least one search parameter is required"))
		return
	}

	ops := models.EnvSearchParameters{}

	for k, vs := range qvars {
		if len(vs) != 1 {
			api.badRequestError(w, fmt.Errorf("unexpected value for %v: %v", k, vs))
			return
		}
		v := vs[0]
		switch k {
		case "repo":
			ops.Repo = v
		case "pr":
			pr, err := strconv.Atoi(v)
			if err != nil || pr < 1 {
				api.badRequestError(w, fmt.Errorf("bad PR number"))
				return
			}
			ops.Pr = uint(pr)
		case "source_sha":
			ops.SourceSHA = v
		case "source_branch":
			ops.SourceBranch = v
		case "user":
			ops.User = v
		case "status":
			s, err := models.EnvironmentStatusFromString(v)
			if err != nil {
				api.badRequestError(w, fmt.Errorf("unknown status"))
				return
			}
			ops.Status = s
		}
	}
	qas, err := api.dl.Search(r.Context(), ops)
	if err != nil {
		api.internalError(w, fmt.Errorf("error searching in DB: %v", err))
	}
	w.Header().Add("Content-Type", "application/json")
	if len(qas) == 0 {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
		return
	}
	output := []v0QAEnvironment{}
	for _, e := range qas {
		output = append(output, *v0QAEnvironmentFromQAEnvironment(&e))
	}
	j, err := json.Marshal(output)
	if err != nil {
		api.internalError(w, fmt.Errorf("error marshaling environments: %v", err))
		return
	}
	w.Write(j)
}
