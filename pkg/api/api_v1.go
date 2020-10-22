package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dollarshaveclub/acyl/pkg/config"
	"github.com/dollarshaveclub/acyl/pkg/ghevent"
	"github.com/dollarshaveclub/acyl/pkg/models"
	"github.com/dollarshaveclub/acyl/pkg/persistence"
	"github.com/dollarshaveclub/acyl/pkg/spawner"
	"github.com/gorilla/mux"
	muxtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
)

// API output schema
type v1QAEnvironment struct {
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
	CommitSHAMap             models.RefMap               `json:"commit_sha_map"`
	AminoServiceToPort       map[string]int64            `json:"amino_service_to_port"`
	AminoKubernetesNamespace string                      `json:"amino_kubernetes_namespace"`
	AminoEnvironmentID       int                         `json:"amino_environment_id"`
}

func v1QAEnvironmentFromQAEnvironment(qae *models.QAEnvironment) *v1QAEnvironment {
	return &v1QAEnvironment{
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
		CommitSHAMap:             qae.CommitSHAMap,
		AminoServiceToPort:       qae.AminoServiceToPort,
		AminoKubernetesNamespace: qae.AminoKubernetesNamespace,
		AminoEnvironmentID:       qae.AminoEnvironmentID,
	}
}

type v1api struct {
	apiBase
	dl persistence.DataLayer
	ge *ghevent.GitHubEventWebhook
	es spawner.EnvironmentSpawner
	sc config.ServerConfig
}

func newV1API(dl persistence.DataLayer, ge *ghevent.GitHubEventWebhook, es spawner.EnvironmentSpawner, sc config.ServerConfig, logger *log.Logger) (*v1api, error) {
	return &v1api{
		apiBase: apiBase{
			logger: logger,
		},
		dl: dl,
		ge: ge,
		es: es,
		sc: sc,
	}, nil
}

func (api *v1api) register(r *muxtrace.Router) error {
	if r == nil {
		return fmt.Errorf("router is nil")
	}
	// v1 routes
	r.HandleFunc("/v1/envs/_search", middlewareChain(authMiddleware.tokenAuth(api.envSearchHandler, models.ReadOnlyPermission))).Methods("GET")
	r.HandleFunc("/v1/envs/_recent", middlewareChain(authMiddleware.tokenAuth(api.envRecentHandler, models.ReadOnlyPermission))).Methods("GET")
	r.HandleFunc("/v1/envs/{name}", middlewareChain(authMiddleware.tokenAuth(api.envDetailHandler, models.ReadOnlyPermission))).Methods("GET")
	return nil
}

func (api *v1api) marshalQAEnvironments(qas []models.QAEnvironment, w http.ResponseWriter) {
	w.Header().Add("Content-Type", "application/json")
	output := []v1QAEnvironment{}
	for _, e := range qas {
		output = append(output, *v1QAEnvironmentFromQAEnvironment(&e))
	}
	j, err := json.Marshal(output)
	if err != nil {
		api.internalError(w, fmt.Errorf("error marshaling environments: %v", err))
		return
	}
	w.Write(j)
}

func (api *v1api) envDetailHandler(w http.ResponseWriter, r *http.Request) {
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

	output := v1QAEnvironmentFromQAEnvironment(qa)
	j, err := json.Marshal(output)
	if err != nil {
		api.internalError(w, fmt.Errorf("error marshaling environment: %v", err))
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write(j)
}

func (api *v1api) envSearchHandler(w http.ResponseWriter, r *http.Request) {
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
	api.marshalQAEnvironments(qas, w)
}

func (api *v1api) envRecentHandler(w http.ResponseWriter, r *http.Request) {
	qvars := r.URL.Query()
	daysstr, ok := qvars["days"]
	if !ok {
		daysstr = []string{"1"}
	}
	days, err := strconv.Atoi(daysstr[0])
	if err != nil || days < 0 {
		api.badRequestError(w, fmt.Errorf("invalid days value: %v", daysstr[0]))
		return
	}
	var includeDestroyed bool
	if val, ok := qvars["include_destroyed"]; ok {
		includeDestroyed = val[0] == "true" || val[0] == "yes" || val[0] == "1"
	}
	qas, err := api.dl.GetMostRecent(r.Context(), uint(days))
	if err != nil {
		api.internalError(w, fmt.Errorf("error performing query: %v", err))
		return
	}
	if !includeDestroyed {
		before := make([]models.QAEnvironment, len(qas))
		copy(before, qas)
		var count int
		for _, qa := range before {
			if qa.Status != models.Destroyed {
				qas[count] = qa
				count++
			}
		}
		qas = qas[0:count]
	}
	api.marshalQAEnvironments(qas, w)
}
