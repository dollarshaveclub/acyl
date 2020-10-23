package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dollarshaveclub/acyl/pkg/config"
	"github.com/dollarshaveclub/acyl/pkg/eventlogger"
	"github.com/dollarshaveclub/acyl/pkg/ghevent"
	"github.com/dollarshaveclub/acyl/pkg/models"
	ncontext "github.com/dollarshaveclub/acyl/pkg/nitro/context"
	"github.com/dollarshaveclub/acyl/pkg/nitro/metahelm"
	"github.com/dollarshaveclub/acyl/pkg/persistence"
	"github.com/dollarshaveclub/acyl/pkg/spawner"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	muxtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/ext"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

// API output schema
type v2QAEnvironment struct {
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
	SourceRef                string                      `json:"source_ref"`
	RawStatus                string                      `json:"status"`
	RefMap                   models.RefMap               `json:"ref_map"`
	CommitSHAMap             models.RefMap               `json:"commit_sha_map"`
	AminoServiceToPort       map[string]int64            `json:"amino_service_to_port"`
	AminoKubernetesNamespace string                      `json:"amino_kubernetes_namespace"`
	AminoEnvironmentID       int                         `json:"amino_environment_id"`
}

func v2QAEnvironmentFromQAEnvironment(qae *models.QAEnvironment) *v2QAEnvironment {
	return &v2QAEnvironment{
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
		SourceRef:                qae.SourceRef,
		RawStatus:                qae.RawStatus,
		RefMap:                   qae.RefMap,
		CommitSHAMap:             qae.CommitSHAMap,
		AminoServiceToPort:       qae.AminoServiceToPort,
		AminoKubernetesNamespace: qae.AminoKubernetesNamespace,
		AminoEnvironmentID:       qae.AminoEnvironmentID,
	}
}

type v2EventLog struct {
	ID             uuid.UUID   `json:"id"`
	Created        time.Time   `json:"created"`
	Updated        pq.NullTime `json:"updated"`
	EnvName        string      `json:"env_name"`
	Repo           string      `json:"repo"`
	PullRequest    uint        `json:"pull_request"`
	WebhookPayload []byte      `json:"webhook_payload"`
	Log            []string    `json:"log"`
}

func v2EventLogFromEventLog(el *models.EventLog) *v2EventLog {
	return &v2EventLog{
		ID:             el.ID,
		Created:        el.Created,
		Updated:        el.Updated,
		EnvName:        el.EnvName,
		Repo:           el.Repo,
		PullRequest:    el.PullRequest,
		WebhookPayload: el.WebhookPayload,
		Log:            el.Log,
	}
}

func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func statusSummaryType(t models.EventStatusType) string {
	switch t {
	case models.UnknownEventStatusType:
		return "unknown"
	case models.CreateEvent:
		return "create"
	case models.UpdateEvent:
		return "update"
	case models.DestroyEvent:
		return "destroy"
	default:
		return "default"
	}
}

func statusSummaryStatus(s models.EventStatus) string {
	switch s {
	case models.UnknownEventStatus:
		return "unknown"
	case models.PendingStatus:
		return "pending"
	case models.DoneStatus:
		return "done"
	case models.FailedStatus:
		return "failed"
	case models.CancelledStatus:
		return "cancelled"
	default:
		return "default"
	}
}

func statusNodeChartStatus(n models.NodeChartStatus) string {
	switch n {
	case models.UnknownChartStatus:
		return "unknown"
	case models.WaitingChartStatus:
		return "waiting"
	case models.InstallingChartStatus:
		return "installing"
	case models.UpgradingChartStatus:
		return "upgrading"
	case models.DoneChartStatus:
		return "done"
	case models.FailedChartStatus:
		return "failed"
	default:
		return "default"
	}
}

type V2RenderedEventStatus struct {
	Description   string `json:"description"`
	LinkTargetURL string `json:"link_target_url"`
}

type V2EventStatusSummaryConfig struct {
	Type           string                `json:"type"`
	Status         string                `json:"status"`
	RenderedStatus V2RenderedEventStatus `json:"rendered_status"`
	EnvName        string                `json:"env_name"`
	K8sNamespace   string                `json:"k8s_ns"`
	TriggeringRepo string                `json:"triggering_repo"`
	PullRequest    uint                  `json:"pull_request"`
	GitHubUser     string                `json:"github_user"`
	Branch         string                `json:"branch"`
	Revision       string                `json:"revision"`
	ProcessingTime string                `json:"processing_time"`
	Started        *time.Time            `json:"started"`
	Completed      *time.Time            `json:"completed"`
	RefMap         map[string]string     `json:"ref_map"`
}

type V2EventStatusTreeNodeImage struct {
	Name      string     `json:"name"`
	Error     bool       `json:"error"`
	Completed *time.Time `json:"completed"`
	Started   *time.Time `json:"started"`
}

type V2EventStatusTreeNodeChart struct {
	Status    string     `json:"status"`
	Started   *time.Time `json:"started"`
	Completed *time.Time `json:"completed"`
}

func statusImageOrNil(image models.EventStatusTreeNodeImage) *V2EventStatusTreeNodeImage {
	if image.Name == "" {
		return nil
	}
	return &V2EventStatusTreeNodeImage{
		Name:      image.Name,
		Error:     image.Error,
		Completed: timeOrNil(image.Completed),
		Started:   timeOrNil(image.Started),
	}
}

type V2EventStatusTreeNode struct {
	Parent string                      `json:"parent"`
	Image  *V2EventStatusTreeNodeImage `json:"image"`
	Chart  V2EventStatusTreeNodeChart  `json:"chart"`
}

type V2EventStatusSummary struct {
	Config V2EventStatusSummaryConfig       `json:"config"`
	Tree   map[string]V2EventStatusTreeNode `json:"tree"`
}

func v2EventStatusTreeFromTree(tree map[string]models.EventStatusTreeNode) map[string]V2EventStatusTreeNode {
	out := make(map[string]V2EventStatusTreeNode, len(tree))
	for k, v := range tree {
		out[k] = V2EventStatusTreeNode{
			Parent: v.Parent,
			Image:  statusImageOrNil(v.Image),
			Chart: V2EventStatusTreeNodeChart{
				Status:    statusNodeChartStatus(v.Chart.Status),
				Completed: timeOrNil(v.Chart.Completed),
				Started:   timeOrNil(v.Chart.Started),
			},
		}
	}
	return out
}

func V2RenderedStatusFromRenderedStatus(rs models.RenderedEventStatus) V2RenderedEventStatus {
	return V2RenderedEventStatus{
		Description:   rs.Description,
		LinkTargetURL: rs.LinkTargetURL,
	}
}

func V2EventStatusSummaryFromEventStatusSummary(sum *models.EventStatusSummary) *V2EventStatusSummary {
	return &V2EventStatusSummary{
		Config: V2EventStatusSummaryConfig{
			Type:           statusSummaryType(sum.Config.Type),
			Status:         statusSummaryStatus(sum.Config.Status),
			RenderedStatus: V2RenderedStatusFromRenderedStatus(sum.Config.RenderedStatus),
			EnvName:        sum.Config.EnvName,
			K8sNamespace:   sum.Config.K8sNamespace,
			TriggeringRepo: sum.Config.TriggeringRepo,
			PullRequest:    sum.Config.PullRequest,
			GitHubUser:     sum.Config.GitHubUser,
			Branch:         sum.Config.Branch,
			Revision:       sum.Config.Revision,
			ProcessingTime: sum.Config.ProcessingTime.String(),
			Started:        timeOrNil(sum.Config.Started),
			Completed:      timeOrNil(sum.Config.Completed),
			RefMap:         sum.Config.RefMap,
		},
		Tree: v2EventStatusTreeFromTree(sum.Tree),
	}
}

type v2api struct {
	apiBase
	dl    persistence.DataLayer
	ge    *ghevent.GitHubEventWebhook
	es    spawner.EnvironmentSpawner
	sc    config.ServerConfig
	oauth OAuthConfig
	kr    metahelm.KubernetesReporter
}

func newV2API(dl persistence.DataLayer, ge *ghevent.GitHubEventWebhook, es spawner.EnvironmentSpawner, sc config.ServerConfig, oauth OAuthConfig, logger *log.Logger, kr metahelm.KubernetesReporter) (*v2api, error) {
	return &v2api{
		apiBase: apiBase{
			logger: logger,
		},
		dl:    dl,
		ge:    ge,
		es:    es,
		sc:    sc,
		oauth: oauth,
		kr:    kr,
	}, nil
}

func (api *v2api) register(r *muxtrace.Router) error {
	if r == nil {
		return fmt.Errorf("router is nil")
	}
	// v2 routes

	// API token
	r.HandleFunc("/v2/envs/_search", middlewareChain(authMiddleware.tokenAuth(api.envSearchHandler, models.ReadOnlyPermission))).Methods("GET")
	r.HandleFunc("/v2/envs/{name}", middlewareChain(authMiddleware.tokenAuth(api.envDetailHandler, models.ReadOnlyPermission))).Methods("GET")
	r.HandleFunc("/v2/eventlog/{id}", middlewareChain(authMiddleware.tokenAuth(api.eventLogHandler, models.ReadOnlyPermission))).Methods("GET")

	// Session auth
	r.HandleFunc("/v2/event/{id}/status", middlewareChain(api.eventStatusHandler, sessionAuthMiddleware.sessionAuth)).Methods("GET")
	r.HandleFunc("/v2/event/{id}/logs", middlewareChain(api.logsHandler, sessionAuthMiddleware.sessionAuth)).Methods("GET")
	r.HandleFunc("/v2/userenvs", middlewareChain(api.userEnvsHandler, sessionAuthMiddleware.sessionAuth)).Methods("GET")
	r.HandleFunc("/v2/userenvs/{name}", middlewareChain(api.userEnvDetailHandler, sessionAuthMiddleware.sessionAuth)).Methods("GET")
	r.HandleFunc("/v2/userenvs/{name}/actions/rebuild", middlewareChain(api.userEnvActionsRebuildHandler, sessionAuthMiddleware.sessionAuth)).Methods("POST")
	r.HandleFunc("/v2/userenvs/{name}/namespace/pods", middlewareChain(api.userEnvNamePodsHandler, sessionAuthMiddleware.sessionAuth)).Methods("GET")
	r.HandleFunc("/v2/userenvs/{name}/namespace/pod/{pod}/containers", middlewareChain(api.userEnvPodContainersHandler, sessionAuthMiddleware.sessionAuth)).Methods("GET")
	r.HandleFunc("/v2/userenvs/{name}/namespace/pod/{pod}/logs", middlewareChain(api.userEnvPodLogsHandler, sessionAuthMiddleware.sessionAuth)).Methods("GET")

	// unauthenticated
	r.HandleFunc("/v2/health-check", middlewareChain(api.healthCheck)).Methods("GET")
	return nil
}

func (api *v2api) marshalQAEnvironments(qas []models.QAEnvironment, w http.ResponseWriter) {
	w.Header().Add("Content-Type", "application/json")
	output := []v2QAEnvironment{}
	for _, e := range qas {
		output = append(output, *v2QAEnvironmentFromQAEnvironment(&e))
	}
	j, err := json.Marshal(output)
	if err != nil {
		api.internalError(w, fmt.Errorf("error marshaling environments: %v", err))
		return
	}
	w.Write(j)
}

func (api *v2api) envDetailHandler(w http.ResponseWriter, r *http.Request) {
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

	output := v2QAEnvironmentFromQAEnvironment(qa)
	j, err := json.Marshal(output)
	if err != nil {
		api.internalError(w, fmt.Errorf("error marshaling environment: %v", err))
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write(j)
}

func (api *v2api) envSearchHandler(w http.ResponseWriter, r *http.Request) {
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
	if _, ok := qvars["tracking_ref"]; ok {
		if _, ok := qvars["repo"]; !ok {
			api.badRequestError(w, fmt.Errorf("search by tracking_ref requires repo name"))
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
		case "tracking_ref":
			ops.TrackingRef = v
		}
	}
	qas, err := api.dl.Search(r.Context(), ops)
	if err != nil {
		api.internalError(w, fmt.Errorf("error searching in DB: %v", err))
	}
	api.marshalQAEnvironments(qas, w)
}

func (api *v2api) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte(`{ "message" : "Todo es bueno!" }`))
}

func (api *v2api) eventLogHandler(w http.ResponseWriter, r *http.Request) {
	idstr := mux.Vars(r)["id"]
	id, err := uuid.Parse(idstr)
	if err != nil {
		api.badRequestError(w, errors.Wrap(err, "error parsing id"))
		return
	}
	el, err := api.dl.GetEventLogByID(id)
	if err != nil {
		api.internalError(w, errors.Wrap(err, "error fetching event logs"))
		return
	}
	if el == nil {
		api.notfoundError(w)
		return
	}
	j, err := json.Marshal(v2EventLogFromEventLog(el))
	if err != nil {
		api.internalError(w, errors.Wrap(err, "error marshaling event log"))
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write(j)
}

func (api *v2api) eventStatusHandler(w http.ResponseWriter, r *http.Request) {
	idstr := mux.Vars(r)["id"]
	id, err := uuid.Parse(idstr)
	if err != nil {
		api.badRequestError(w, errors.Wrap(err, "error parsing id"))
		return
	}
	es, err := api.dl.GetEventStatus(id)
	if err != nil {
		api.internalError(w, errors.Wrap(err, "error fetching event status"))
		return
	}
	if es == nil {
		api.notfoundError(w)
		return
	}
	j, err := json.Marshal(V2EventStatusSummaryFromEventStatusSummary(es))
	if err != nil {
		api.internalError(w, errors.Wrap(err, "error marshaling event status"))
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write(j)
}

// logsHandler is an unauthenticated event log API endpoint for the UI that only returns event log lines
// and not the full EventLog object
// Instead of a global API token (like /v2/eventlog/{id}) it requires an event-scoped
// log key (UUID) passed in the "Acyl-Log-Key" request header
func (api *v2api) logsHandler(w http.ResponseWriter, r *http.Request) {
	lk := r.Header.Get("Acyl-Log-Key")
	if lk == "" {
		api.logger.Printf("error serving event logs: missing log key")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	lkuuid, err := uuid.Parse(lk)
	if err != nil {
		api.logger.Printf("error serving event logs: bad log key: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	idstr := mux.Vars(r)["id"]
	id, err := uuid.Parse(idstr)
	if err != nil {
		api.logger.Printf("error serving event logs: bad event id: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	elog, err := api.dl.GetEventLogByID(id)
	if err != nil {
		api.logger.Printf("error serving event logs: error getting event log: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if elog == nil {
		api.logger.Printf("error serving event logs: missing event log")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if elog.LogKey != lkuuid {
		api.logger.Printf("error serving event logs: mismatched log key")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	j, err := json.Marshal(&elog.Log)
	if err != nil {
		api.logger.Printf("error serving event logs: error marshaling log: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write(j)
}

type V2UserEnv struct {
	Repo        string    `json:"repo"`
	PullRequest uint      `json:"pull_request"`
	EnvName     string    `json:"env_name"`
	LastEvent   time.Time `json:"last_event"`
	Status      string    `json:"status"`
}

func v2UserEnvFromQAEnvironment(qa models.QAEnvironment) V2UserEnv {
	out := V2UserEnv{
		Repo:        qa.Repo,
		PullRequest: qa.PullRequest,
		EnvName:     qa.Name,
		LastEvent:   qa.Created.Truncate(time.Second),
	}
	switch qa.Status {
	case models.Destroyed:
		out.Status = "destroyed"
	case models.Success:
		out.Status = "success"
	case models.Failure:
		out.Status = "failed"
	case models.Spawned:
		fallthrough
	case models.Updating:
		out.Status = "pending"
	default:
		out.Status = "unknown"
	}
	return out
}

var (
	defaultUserEnvsHistory = 7 * 24 * time.Hour
)

// userEnvsHandler returns the environments for the session user that have been created/updated within the history duration
func (api *v2api) userEnvsHandler(w http.ResponseWriter, r *http.Request) {
	uis, err := getSessionFromContext(r.Context())
	if err != nil {
		api.rlogger(r).Logf("session missing from context")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	history := defaultUserEnvsHistory
	if h := r.URL.Query().Get("history"); h != "" {
		hd, err := time.ParseDuration(h)
		if err != nil {
			api.rlogger(r).Logf("invalid history duration: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		history = hd
	}
	statuses := []models.EnvironmentStatus{
		models.Success,
		models.Spawned,
		models.Updating,
		models.Failure,
	}
	if incd := r.URL.Query().Get("include_destroyed"); incd == "true" {
		statuses = append(statuses, models.Destroyed)
	}
	sparams := models.EnvSearchParameters{
		User:         uis.GitHubUser,
		Statuses:     statuses,
		CreatedSince: history,
	}
	// user-scoped by default unless allenvs=true
	if r.URL.Query().Get("allenvs") == "true" {
		sparams.User = ""
		repos, err := userPermissionsClient(api.oauth).GetUserVisibleRepos(r.Context(), uis)
		if err != nil {
			api.rlogger(r).Logf("error getting user visible repos: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sparams.Repos = repos
	}
	envs, err := api.dl.Search(r.Context(), sparams)
	if err != nil {
		api.rlogger(r).Logf("error getting envs: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	out := make([]V2UserEnv, len(envs))
	for i, env := range envs {
		out[i] = v2UserEnvFromQAEnvironment(env)
	}
	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		api.rlogger(r).Logf("error marshaling envs: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

type V2EventSummary struct {
	EventID  string                           `json:"event_id"`
	Started  time.Time                        `json:"started"`
	Duration *models.ConfigProcessingDuration `json:"duration"`
	Type     string                           `json:"type"`
	Status   string                           `json:"status"`
}

func durationOrNil(t1, t2 time.Time) *models.ConfigProcessingDuration {
	if t1.IsZero() || t2.IsZero() || !t1.After(t2) {
		return nil
	}
	return &models.ConfigProcessingDuration{Duration: t1.Sub(t2)}
}

func V2EventSummariesFromEventLogs(elogs []models.EventLog) []V2EventSummary {
	out := make([]V2EventSummary, len(elogs))
	for i := range elogs {
		out[i] = V2EventSummary{
			EventID:  elogs[i].ID.String(),
			Started:  elogs[i].Created,
			Duration: durationOrNil(elogs[i].Status.Config.Completed, elogs[i].Created),
			Type:     statusSummaryType(elogs[i].Status.Config.Type),
			Status:   statusSummaryStatus(elogs[i].Status.Config.Status),
		}
	}
	return out
}

type V2EnvDetail struct {
	V2UserEnv
	GitHubUser   string           `json:"github_user"`
	PRHeadBranch string           `json:"pr_head_branch"`
	K8sNamespace string           `json:"k8s_namespace"`
	Events       []V2EventSummary `json:"events"`
}

func V2EnvDetailFromQAEnvAndK8sEnv(qae models.QAEnvironment, k8senv models.KubernetesEnvironment) V2EnvDetail {
	return V2EnvDetail{
		V2UserEnv:    v2UserEnvFromQAEnvironment(qae),
		GitHubUser:   qae.User,
		PRHeadBranch: qae.SourceBranch,
		K8sNamespace: k8senv.Namespace,
	}
}

// userEnvDetailHandler gets environment detail for the UI
func (api *v2api) userEnvDetailHandler(w http.ResponseWriter, r *http.Request) {
	uis, err := getSessionFromContext(r.Context())
	if err != nil {
		api.rlogger(r).Logf("session missing from context")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	envname := mux.Vars(r)["name"]
	if envname == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	qae, err := api.dl.GetQAEnvironment(r.Context(), envname)
	if err != nil {
		api.rlogger(r).Logf("error getting qa env from db: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if qae == nil {
		api.rlogger(r).Logf("qa env not found")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	repos, err := userPermissionsClient(api.oauth).GetUserVisibleRepos(r.Context(), uis)
	if err != nil {
		api.rlogger(r).Logf("error getting user visible repos: %v: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !repoInRepos(repos, qae.Repo) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	k8senv, err := api.dl.GetK8sEnv(r.Context(), envname)
	if err != nil {
		api.rlogger(r).Logf("error getting k8s env from db: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if k8senv == nil {
		// if there's no k8senv yet, we'll just use an empty one (this will result in an empty namespace in the UI)
		k8senv = &models.KubernetesEnvironment{}
	}
	elogs, err := api.dl.GetEventLogsWithStatusByEnvName(envname)
	if err != nil {
		api.rlogger(r).Logf("error getting eventlogs from db: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(elogs) == 0 {
		// it shouldn't be possible to have an environment with zero events
		api.rlogger(r).Logf("no eventlogs found for env: %v", envname)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ed := V2EnvDetailFromQAEnvAndK8sEnv(*qae, *k8senv)
	ed.Events = V2EventSummariesFromEventLogs(elogs)
	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(&ed); err != nil {
		api.rlogger(r).Logf("error marshaling user env detail: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// userEnvActionsRebuildHandler rebuilds the environment from the UI with a standard synchronize or (full) rebuild
func (api *v2api) userEnvActionsRebuildHandler(w http.ResponseWriter, r *http.Request) {
	uis, err := getSessionFromContext(r.Context())
	if err != nil {
		api.rlogger(r).Logf("session missing from context")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	envname := mux.Vars(r)["name"]
	if envname == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	qae, err := api.dl.GetQAEnvironment(r.Context(), envname)
	if err != nil {
		api.rlogger(r).Logf("error getting qa env from db: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if qae == nil {
		api.rlogger(r).Logf("qa env not found")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	repos, err := userPermissionsClient(api.oauth).GetUserWritableRepos(r.Context(), uis)
	if err != nil {
		api.rlogger(r).Logf("error getting user writable repos: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, ok := repos[qae.Repo]; !ok {
		api.rlogger(r).Logf("user writable repo not found")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	k8senv, err := api.dl.GetK8sEnv(r.Context(), envname)
	if err != nil {
		api.rlogger(r).Logf("error getting k8s env from db: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if k8senv == nil {
		api.rlogger(r).Logf("k8s env not found")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	rrd := qae.RepoRevisionDataFromQA()

	// setup logger
	id, err := uuid.NewRandom()
	if err != nil {
		api.rlogger(r).Logf("error getting random UUID: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	elogger := &eventlogger.Logger{
		ID:         id,
		DeliveryID: uuid.Nil,
		DL:         api.dl,
		Sink:       os.Stdout,
	}
	if err := elogger.Init([]byte{}, qae.Repo, qae.PullRequest); err != nil {
		api.rlogger(r).Logf("error initializing event logger: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := elogger.SetEnvName(qae.Name); err != nil {
		api.rlogger(r).Logf("error setting event logger name: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// setup context
	ctx := eventlogger.NewEventLoggerContext(context.Background(), elogger)
	ctx = ncontext.NewCancelFuncContext(context.WithCancel(ctx))
	span := tracer.StartSpan("actions_rebuilder")
	span.SetTag(ext.SamplingPriority, ext.PriorityUserKeep)
	setTagsForGithubWebhookHandler(span, *rrd)
	ctx = tracer.ContextWithSpan(ctx, span)
	logger := eventlogger.GetLogger(ctx).Printf

	// check for full rebuild
	messaging := "synchronize"
	if r.URL.Query().Get("full") == "true" {
		messaging = "rebuild"
		err = api.dl.UpdateK8sEnvConfigSignature(ctx, qae.Name, [32]byte{})
		if err != nil {
			api.rlogger(r).Logf("error updating config signature: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	// update environment
	logger("starting async processing for %v rebuild update", messaging)
	api.wg.Add(1)
	go func() {
		var err error
		defer func() { span.Finish(tracer.WithError(err)) }()
		defer api.wg.Done()
		ctx, cf := context.WithTimeout(ctx, MaxAsyncActionTimeout)
		defer cf() // guarantee that any goroutines created with the ctx are cancelled
		name, err := api.es.Update(ctx, *rrd)
		if err != nil {
			logger("finished processing %v update with error: %v", messaging, err)
			return
		}
		logger("success processing %v update event (env: %q); done", messaging, name)
	}()
	w.WriteHeader(http.StatusCreated)
}

type V2EnvNamePods struct {
	Name     string `json:"name"`
	Ready    string `json:"ready"`
	Status   string `json:"status"`
	Restarts string `json:"restarts"`
	Age      string `json:"age"`
}

// userEnvNamePodsHandler returns curated kubernetes pod data by the environment name
func (api *v2api) userEnvNamePodsHandler(w http.ResponseWriter, r *http.Request) {
	v2enp := []V2EnvNamePods{}
	uis, err := getSessionFromContext(r.Context())
	if err != nil {
		api.rlogger(r).Logf("session missing from context")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	envname := mux.Vars(r)["name"]
	if envname == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	qae, err := api.dl.GetQAEnvironment(r.Context(), envname)
	if err != nil {
		api.rlogger(r).Logf("error getting qa env from db: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if qae == nil {
		api.rlogger(r).Logf("qa env not found")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	repos, err := userPermissionsClient(api.oauth).GetUserVisibleRepos(r.Context(), uis)
	if err != nil {
		api.rlogger(r).Logf("error getting user visible repos: %v: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !repoInRepos(repos, qae.Repo) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	k8senv, err := api.dl.GetK8sEnv(r.Context(), envname)
	if err != nil {
		api.rlogger(r).Logf("error getting k8s env from db: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Return empty kubernetes environment if not found
	if k8senv == nil {
		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&v2enp); err != nil {
			api.rlogger(r).Logf("error marshaling user env pod list: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	pl, err := api.kr.GetPodList(r.Context(), k8senv.Namespace)
	if err != nil {
		api.rlogger(r).Logf("error getting pod list for k8s env: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Return empty pod list if nil
	if pl == nil {
		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&v2enp); err != nil {
			api.rlogger(r).Logf("error marshaling user env pod list: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	for _, p := range pl {
		v2enp = append(v2enp, V2EnvNamePods{
			Name:     p.Name,
			Ready:    p.Ready,
			Status:   p.Status,
			Restarts: strconv.Itoa(int(p.Restarts)),
			Age:      p.Age.Round(time.Second).String(),
		})
	}
	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(&v2enp); err != nil {
		api.rlogger(r).Logf("error marshaling user env pod list: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

type V2EnvNamePodContainers struct {
	Name       string   `json:"name"`
	Containers []string `json:"containers"`
}

// userEnvPodContainersHandler returns list of container names for specified pod and environment name
func (api *v2api) userEnvPodContainersHandler(w http.ResponseWriter, r *http.Request) {
	v2enpc := V2EnvNamePodContainers{}
	w.Header().Set("Content-Type", "application/json")
	uis, err := getSessionFromContext(r.Context())
	if err != nil {
		api.rlogger(r).Logf("session missing from context")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	podname := mux.Vars(r)["pod"]
	if podname == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	envname := mux.Vars(r)["name"]
	if envname == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	qae, err := api.dl.GetQAEnvironment(r.Context(), envname)
	if err != nil {
		api.rlogger(r).Logf("error getting qa env from db: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if qae == nil {
		api.rlogger(r).Logf("qa env not found")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	repos, err := userPermissionsClient(api.oauth).GetUserVisibleRepos(r.Context(), uis)
	if err != nil {
		api.rlogger(r).Logf("error getting user visible repos: %v: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !repoInRepos(repos, qae.Repo) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	k8senv, err := api.dl.GetK8sEnv(r.Context(), envname)
	if err != nil {
		api.rlogger(r).Logf("error getting k8s env from db: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Return empty kubernetes environment if not found
	if k8senv == nil {
		if err := json.NewEncoder(w).Encode(&v2enpc); err != nil {
			api.rlogger(r).Logf("error marshaling user env pod list: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	podContainers, err := api.kr.GetPodContainers(r.Context(), k8senv.Namespace, podname)
	if err != nil {
		api.rlogger(r).Logf("error getting pod containers: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	v2enpc = V2EnvNamePodContainers{
		Name:       podname,
		Containers: podContainers.Containers,
	}
	if err := json.NewEncoder(w).Encode(&v2enpc); err != nil {
		api.rlogger(r).Logf("error marshaling user env pod list: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// userEnvPodLogsHandler returns logs for the specified env and pod name
func (api *v2api) userEnvPodLogsHandler(w http.ResponseWriter, r *http.Request) {
	uis, err := getSessionFromContext(r.Context())
	if err != nil {
		api.rlogger(r).Logf("session missing from context")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	podname := mux.Vars(r)["pod"]
	if podname == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	envname := mux.Vars(r)["name"]
	if envname == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	qae, err := api.dl.GetQAEnvironment(r.Context(), envname)
	if err != nil {
		api.rlogger(r).Logf("error getting qa env from db: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if qae == nil {
		api.rlogger(r).Logf("qa env not found")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	repos, err := userPermissionsClient(api.oauth).GetUserVisibleRepos(r.Context(), uis)
	if err != nil {
		api.rlogger(r).Logf("error getting user visible repos: %v: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !repoInRepos(repos, qae.Repo) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	k8senv, err := api.dl.GetK8sEnv(r.Context(), envname)
	if err != nil {
		api.rlogger(r).Logf("error getting k8s env from db: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if k8senv == nil {
		api.rlogger(r).Logf("error getting k8s env from db: %v", err)
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	lines := DefaultPodContainerLogLines
	if l := r.URL.Query().Get("lines"); l != "" {
		i, err := strconv.Atoi(l)
		if err != nil {
			api.rlogger(r).Logf("error converting line to integer: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// return error if request violates limits
		if i < 0 || i > metahelm.MaxPodContainerLogLines {
			api.rlogger(r).Logf("error requested lines exceed limit: %v", i)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		lines = i
	}
	container := r.URL.Query().Get("container")
	pl, err := api.kr.GetPodLogs(r.Context(), k8senv.Namespace, podname, container, uint(lines))
	if err != nil {
		api.rlogger(r).Logf("error getting container %v logs for pod %v: %v", container, podname, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer pl.Close()
	w.Header().Set("Content-Type", "text/plain")
	_, err = io.Copy(w, pl)
	if err != nil {
		api.rlogger(r).Logf("error copying pod logs output")
		w.WriteHeader(http.StatusInternalServerError)
	}
}
