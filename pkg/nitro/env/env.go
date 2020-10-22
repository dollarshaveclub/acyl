package env

import (
	"context"
	stdliberrors "errors"
	"fmt"
	"html/template"
	"sort"
	"time"

	"github.com/dollarshaveclub/acyl/pkg/ghapp"

	"github.com/dollarshaveclub/acyl/pkg/eventlogger"
	"github.com/dollarshaveclub/acyl/pkg/ghclient"
	"github.com/dollarshaveclub/acyl/pkg/locker"
	"github.com/dollarshaveclub/acyl/pkg/models"
	"github.com/dollarshaveclub/acyl/pkg/namegen"
	ncontext "github.com/dollarshaveclub/acyl/pkg/nitro/context"
	nitroerrors "github.com/dollarshaveclub/acyl/pkg/nitro/errors"
	"github.com/dollarshaveclub/acyl/pkg/nitro/meta"
	"github.com/dollarshaveclub/acyl/pkg/nitro/metahelm"
	"github.com/dollarshaveclub/acyl/pkg/nitro/metrics"
	"github.com/dollarshaveclub/acyl/pkg/nitro/notifier"
	"github.com/dollarshaveclub/acyl/pkg/persistence"
	metahelmlib "github.com/dollarshaveclub/metahelm/pkg/metahelm"
	"github.com/google/uuid"
	"github.com/imdario/mergo"
	"github.com/pkg/errors"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	billy "gopkg.in/src-d/go-billy.v4"
	billyutil "gopkg.in/src-d/go-billy.v4/util"
)

// LogFunc is a function that logs a formatted string somewhere
type LogFunc func(string, ...interface{})

// metrics name prefix
var mpfx = "env."

// NotificationsFactoryFunc is a function that takes a notifications config from the triggering repo, processes it according to any global defaults, and returns a Router suitable to push notifications
type NotificationsFactoryFunc func(lf func(string, ...interface{}), notifications models.Notifications, user string) notifier.Router

// Manager is an object that creates/updates/deletes environments in k8s
type Manager struct {
	NF                   NotificationsFactoryFunc
	DefaultNotifications models.Notifications
	DL                   persistence.DataLayer
	RC                   ghclient.RepoClient
	MC                   metrics.Collector
	NG                   namegen.NameGenerator
	FS                   billy.Filesystem
	MG                   meta.Getter
	CI                   metahelm.Installer
	PLF                  locker.PreemptiveLockerFactory
	GlobalLimit          uint
	failureTemplate      *template.Template
	OperationTimeout     time.Duration
	UIBaseURL            string
}

var DefaultOperationTimeout = 30 * time.Minute

func (m *Manager) log(ctx context.Context, msg string, args ...interface{}) {
	eventlogger.GetLogger(ctx).Printf(msg, args...)
}

func (m *Manager) setloggername(ctx context.Context, name string) {
	l := eventlogger.GetLogger(ctx)
	l.SetEnvName(name)
	if l.ID != uuid.UUID([16]byte{}) {
		m.DL.AddEvent(ctx, name, "webhook event id: "+l.ID.String())
	}
}

// validContext returns ctx2 if ctx1 is cancelled, or ctx1 otherwise
func validContext(ctx1, ctx2 context.Context) context.Context {
	select {
	case <-ctx1.Done():
		return ctx2
	default:
		return ctx1
	}
}

func (m *Manager) pushNotification(ctx context.Context, env *newEnv, event notifier.NotificationEvent, errmsg string) {
	var err error
	var cmsg string
	if env == nil {
		m.log(ctx, "pushNotification: %v: newenv is nil", event.Key())
		return
	}
	if env.env == nil {
		m.log(ctx, "pushNotification: %v: newenv.env is nil", event.Key())
		return
	}
	// if ctx is cancelled, we don't want to use it to fetch the commit status
	cmsg, err = m.RC.GetCommitMessage(validContext(ctx, context.Background()), env.env.Repo, env.env.SourceSHA)
	if err != nil {
		m.log(ctx, "error getting commit message: %v", err)
		cmsg = "<error getting commit message: " + err.Error() + ">"
	}
	k8sns := m.getKubernetesNamespaceName(ctx, env.env.Name)
	if env.rc == nil {
		env.rc = &models.RepoConfig{}
	}
	if err := mergo.Merge(&env.rc.Notifications, m.DefaultNotifications); err != nil {
		msg := "error merging notifications defaults: " + err.Error()
		m.log(ctx, msg)
		m.DL.AddEvent(ctx, env.env.Name, msg)
	}
	n := notifier.Notification{
		Data: models.NotificationData{
			EnvName:       env.env.Name,
			Repo:          env.env.Repo,
			SourceBranch:  env.env.SourceBranch,
			SourceSHA:     env.env.SourceSHA,
			BaseBranch:    env.env.BaseBranch,
			BaseSHA:       env.env.BaseSHA,
			User:          env.env.User,
			PullRequest:   env.env.PullRequest,
			K8sNamespace:  k8sns,
			CommitMessage: cmsg,
			ErrorMessage:  errmsg,
			Event:         event.String(),
		},
		Event:    event,
		Template: env.rc.Notifications.Templates[event.Key()],
	}
	if m.NF == nil {
		m.log(ctx, "notifier factory is uninitialized")
		return
	}
	if err := m.NF(func(msg string, args ...interface{}) { m.log(ctx, msg, args...) }, env.rc.Notifications, env.env.User).FanOut(n); err != nil {
		msg := "error sending " + event.Key() + " notification: " + err.Error()
		m.log(ctx, msg)
		m.DL.AddEvent(ctx, env.env.Name, msg)
	}
}

func (m *Manager) getKubernetesNamespaceName(ctx context.Context, envName string) string {
	var k8sns string
	k8senv, err := m.DL.GetK8sEnv(ctx, envName)
	switch {
	case err != nil:
		k8sns = fmt.Sprintf("<error getting namespace: %v>", err)
	case k8senv == nil:
		k8sns = "<k8s environment not found>"
	default:
		k8sns = k8senv.Namespace
	}
	return k8sns
}

func (m *Manager) setGithubCommitStatus(ctx context.Context, rd *models.RepoRevisionData, env *newEnv, ncs models.CommitStatus, errmsg string) (_ *ghclient.CommitStatus, err error) {
	defer func() {
		if err != nil {
			m.log(ctx, "error setting github commit status: %v", err)
		}
	}()
	cst, ok := env.rc.Notifications.GitHub.CommitStatuses.Templates[ncs.Key()]
	if !ok {
		cst = models.DefaultCommitStatusTemplates[ncs.Key()]
	}
	csData := models.NotificationData{
		EnvName:      env.env.Name,
		Repo:         env.env.Repo,
		SourceBranch: env.env.SourceBranch,
		SourceSHA:    env.env.SourceSHA,
		BaseBranch:   env.env.BaseBranch,
		BaseSHA:      env.env.BaseSHA,
		User:         env.env.User,
		PullRequest:  env.env.PullRequest,
		K8sNamespace: m.getKubernetesNamespaceName(ctx, env.env.Name),
		ErrorMessage: errmsg,
	}
	renderedCSTemplate, err := cst.Render(csData)
	if err != nil {
		return nil, fmt.Errorf("error rendering template: %w", err)
	}
	eid := eventlogger.GetLogger(ctx).ID
	if err := m.DL.SetEventStatusRenderedStatus(eid, models.RenderedEventStatus{
		Description:   renderedCSTemplate.Description,
		LinkTargetURL: renderedCSTemplate.TargetURL,
	}); err != nil {
		return nil, fmt.Errorf("error setting event status rendered status: %w", err)

	}
	turl := renderedCSTemplate.TargetURL
	if m.UIBaseURL != "" {
		turl = fmt.Sprintf("%v/ui/event/status?id=%v", m.UIBaseURL, eid.String())
	}
	cs := &ghclient.CommitStatus{
		Context:     "Acyl",
		Status:      ncs.Key(),
		Description: renderedCSTemplate.Description,
		TargetURL:   turl,
	}
	ctx2 := eventlogger.NewEventLoggerContext(context.Background(), eventlogger.GetLogger(ctx))
	ctx2 = ghapp.CloneGitHubClientContext(ctx2, ctx)
	err = m.RC.SetStatus(ctx2, rd.Repo, rd.SourceSHA, cs)
	if err != nil {
		return nil, fmt.Errorf("error setting commit status: %w", err)
	}
	return cs, nil
}

// lockingOperation sets up the lock and if successful executes f, releasing the lock afterward
func (m *Manager) lockingOperation(ctx context.Context, repo string, pr uint, f func(ctx context.Context) error) (err error) {
	ctx, cf := context.WithCancel(ctx)
	defer cf()
	end := m.MC.Timing(mpfx+"lock_wait", "triggering_repo:"+repo)
	lock := m.PLF(repo, pr, "event") // TODO: consider adding more detailed event information
	preempt, err := lock.Lock(ctx)
	if err != nil {
		end("success:false")
		return fmt.Errorf("error getting lock: %w", err)

	}
	end("success:true")
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		lock.Release(releaseCtx)
		cancel()
	}()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case np := <-preempt: // Lock got preempted, cancel action
			m.MC.Increment(mpfx+"lock_preempt", "triggering_repo:"+repo)
			m.log(ctx, "operation preempted: %v: %v, %v", repo, pr, np)
		case <-stop:
		}
		cf()
	}()
	endop := m.MC.Timing(mpfx+"operation", "triggering_repo:"+repo)
	// Since the input function can block indefinitely, it's critical that we protect this goroutine from getting blocked.
	// We know the context will get canceled after the timeout duration, so let's ensure we move on at that point.
	ch := make(chan error)
	go func() {
		ch <- f(ctx)
	}()
	cancelled := false
	select {
	case opErr := <-ch:
		select {
		case <-ctx.Done():
			cancelled = true
		default:
			err = opErr
		}
	case <-ctx.Done():
		cancelled = true
	}
	switch {
	case cancelled:
		eventlogger.GetLogger(ctx).SetCompletedStatus(models.CancelledStatus)
		err = fmt.Errorf("%w: %v", nitroerrors.ErrContextCancelled, ctx.Err())
	case err != nil:
		var ce metahelmlib.ChartError
		if stdliberrors.As(err, &ce) {
			m.log(ctx, "error returned was a ChartError")
		}
		eventlogger.GetLogger(ctx).SetFailedStatus(ce)
		m.log(ctx, "operation error (user: %v, sys: %v): %v: %v: %v", nitroerrors.IsUserError(err), nitroerrors.IsSystemError(err), repo, pr, err)
	}
	endop(fmt.Sprintf("success:%v", err == nil), fmt.Sprintf("user_error:%v", nitroerrors.IsUserError(err)), fmt.Sprintf("system_error:%v", nitroerrors.IsSystemError(err)))
	return err
}

// Create creates a new k8s environment, persists the information to the DB and returns the environment name or error
func (m *Manager) Create(ctx context.Context, rd models.RepoRevisionData) (string, error) {
	var err error
	var name string
	err = m.lockingOperation(ctx, rd.Repo, rd.PullRequest, func(ctx context.Context) error {
		name, err = m.create(ctx, &rd)
		return err
	})
	return name, err
}

// enforceGlobalLimit checks existing environments against the configured global limit.
// If necessary, kill oldest environments to bring the environment count into compliance with the limit.
func (m *Manager) enforceGlobalLimit(ctx context.Context) error {
	if m.GlobalLimit == 0 {
		return nil
	}
	limit := int(m.GlobalLimit)
	qae, err := m.DL.GetRunningQAEnvironments(ctx)
	if err != nil {
		return fmt.Errorf("error getting running environments: %v", err)
	}
	extant := len(qae)
	if extant > limit {
		kill := extant - limit
		// GetRunningQAEnvironments() returns a sorted list in ascending order of creation timestamp
		kenvs := qae[0:kill]
		m.log(ctx, "enforcing global limit: extant: %v, limit: %v, destroying: %v", extant, limit, kill)
		for _, e := range kenvs {
			env := e
			m.log(ctx, "destroying: %v (created %v)", env.Name, env.Created)
			// we lock around each destroyed environment to preempt any ongoing operations
			// create a new context as lockingOperation() always cancels the context when finished
			ctx2, cf := context.WithCancel(ctx)
			if err := m.Delete(ctx2, e.RepoRevisionDataFromQA(), models.EnvironmentLimitExceeded); err != nil {
				m.log(ctx, "error destroying environment for exceeding limit: %v", err)
			}
			cf()
			select {
			case <-ctx.Done():
				return errors.New("context was cancelled")
			default:
			}
		}
		return nil
	}
	m.log(ctx, "global limit not exceeded: running: %v, limit: %v", extant, limit)
	return nil
}

// newEnv contains all the information required for construction of a new environment
type newEnv struct {
	env *models.QAEnvironment
	rc  *models.RepoConfig
}

func (m *Manager) getRepoConfig(ctx context.Context, rd *models.RepoRevisionData) (rc *models.RepoConfig, err error) {
	if rd == nil {
		return nil, nitroerrors.SystemError(errors.New("rd is nil"))
	}
	m.log(ctx, "fetching and processing environment config")
	end := m.MC.Timing(mpfx+"process_config", "triggering_repo:"+rd.Repo)
	defer func() {
		end(fmt.Sprintf("success:%v", err == nil))
	}()
	rc, err = m.MG.Get(ctx, *rd)
	if err != nil {
		return nil, fmt.Errorf("error getting metadata: %w", nitroerrors.UserError(err))
	}
	if rc == nil {
		return nil, nitroerrors.SystemError(errors.New("rc is nil"))
	}
	m.MC.Gauge(mpfx+"dependencies", float64(len(rc.Dependencies.All())), "triggering_repo:"+rd.Repo)
	return rc, nil
}

// generateNewEnv calculates the metadata for a new environment and either creates a new environment DB record or modifies an existing one
func (m *Manager) generateNewEnv(ctx context.Context, rd *models.RepoRevisionData) (env *models.QAEnvironment, err error) {
	span, ctx := tracer.StartSpanFromContext(ctx, "generate_new_env")
	defer func() {
		if err != nil {
			err = nitroerrors.SystemError(err)
		}
		span.Finish(tracer.WithError(err))
	}()
	envs, err := m.DL.GetQAEnvironmentsByRepoAndPR(ctx, rd.Repo, rd.PullRequest)
	if err != nil {
		return nil, fmt.Errorf("error checking for existing environment record: %w", err)
	}
	if len(envs) > 0 {
		// environment record exists, reuse the latest one
		sort.Slice(envs, func(i, j int) bool { return envs[i].Created.Before(envs[j].Created) })
		env = &envs[len(envs)-1]
		m.log(ctx, "reusing environment db record: %v", env.Name)
		// update relevant fields
		if err := m.DL.SetQAEnvironmentStatus(tracer.ContextWithSpan(context.Background(), span), env.Name, models.Spawned); err != nil {
			return nil, fmt.Errorf("error setting environment status: %w", err)

		}
		m.DL.AddEvent(ctx, env.Name, fmt.Sprintf("reusing environment record for webhook event %v", eventlogger.GetLogger(ctx).ID.String()))
		if err := m.DL.SetQAEnvironmentRepoData(ctx, env.Name, rd); err != nil {
			return nil, fmt.Errorf("error setting environment repo data: %w", err)

		}
		if err := m.DL.SetQAEnvironmentCreated(ctx, env.Name, time.Now().UTC()); err != nil {
			return nil, fmt.Errorf("error setting environment created timestamp: %w", err)

		}
		env, err = m.DL.GetQAEnvironment(ctx, env.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting updated, reused environment record: %w", err)
		}
	} else {
		// no record exists, create a new one
		name, err := m.NG.New()
		if err != nil {
			return nil, fmt.Errorf("error generating name: %w", err)
		}
		m.log(ctx, "generating new environment record: %v", name)
		env = &models.QAEnvironment{
			Name:         name,
			Created:      time.Now().UTC(),
			Status:       models.Spawned,
			User:         rd.User,
			Repo:         rd.Repo,
			PullRequest:  rd.PullRequest,
			SourceSHA:    rd.SourceSHA,
			BaseSHA:      rd.BaseSHA,
			SourceBranch: rd.SourceBranch,
			BaseBranch:   rd.BaseBranch,
			SourceRef:    rd.SourceRef,
		}
		if err = m.DL.CreateQAEnvironment(ctx, env); err != nil {
			return nil, fmt.Errorf("error writing environment to db: %w", err)

		}
	}
	return env, nil
}

// processEnvConfig fetches, parses and validates the top-level acyl.yml and all dependencies, calculates refs and writes them to the env db record. It always returns a valid *newEnv regardless of error.
func (m *Manager) processEnvConfig(ctx context.Context, env *models.QAEnvironment, rd *models.RepoRevisionData) (ne *newEnv, err error) {
	span, ctx := tracer.StartSpanFromContext(ctx, "process_env_config")
	defer func() {
		if err != nil && !nitroerrors.IsUserError(err) {
			err = nitroerrors.SystemError(err)
		}
		span.Finish(tracer.WithError(err))
	}()
	ne = &newEnv{env: env}
	rc, err := m.getRepoConfig(ctx, rd)
	if err != nil {
		return ne, fmt.Errorf("error validating environment config: %w", err)
	}
	ne.rc = rc
	rm, err := rc.RefMap()
	if err != nil {
		return ne, fmt.Errorf("error generating ref map: %w", err)
	}
	csm, err := rc.CommitSHAMap()
	if err != nil {
		return ne, fmt.Errorf("error generating commit SHA map: %w", err)
	}
	if err := m.DL.SetQAEnvironmentRefMap(ctx, env.Name, rm); err != nil {
		return ne, fmt.Errorf("error setting environment ref map: %w", err)

	}
	if err := m.DL.SetQAEnvironmentCommitSHAMap(ctx, env.Name, csm); err != nil {
		return ne, fmt.Errorf("error setting environment commit sha map: %w", err)

	}
	if err := m.DL.SetQAEnvironmentRepoData(ctx, env.Name, rd); err != nil {
		return ne, fmt.Errorf("error setting environment repo data: %w", err)

	}
	env, err = m.DL.GetQAEnvironment(ctx, env.Name)
	if err != nil {
		return ne, fmt.Errorf("error getting updated environment record: %w", err)
	}
	ne.env = env
	return ne, nil
}

func (m *Manager) fetchCharts(ctx context.Context, name string, rc *models.RepoConfig) (_ string, _ meta.ChartLocations, err error) {
	span, ctx := tracer.StartSpanFromContext(ctx, "fetch_charts")
	defer func() {
		span.Finish(tracer.WithError(err))
	}()
	td, err := tempDir(m.FS, "", name)
	if err != nil {
		return "", nil, fmt.Errorf("error generating temp dir: %w", err)
	}
	end := m.MC.Timing(mpfx+"fetch_helm_charts", "triggering_repo:"+rc.Application.Repo)
	cloc, err := m.MG.FetchCharts(ctx, rc, td)
	if err != nil {
		end("success:false")
		if !nitroerrors.IsSystemError(err) {
			err = nitroerrors.UserError(err)
		}
		return "", nil, fmt.Errorf("error fetching charts: %w", err)

	}
	end("success:true")
	return td, cloc, nil
}

func (m *Manager) enforceTimeout(ctx context.Context, cf context.CancelFunc, newenv *newEnv) {
	to := DefaultOperationTimeout
	if m.OperationTimeout != 0 {
		to = m.OperationTimeout
	}
	select {
	case <-time.After(to):
		m.pushNotification(ctx, newenv, notifier.Failure, fmt.Sprintf("timeout reached (%v), aborting", to))
		m.log(ctx, "timed out (%v), cancelling context and aborting", to)
		cf()
		// cancel root context and all child contexts
		ncontext.GetCancelFunc(ctx)()
	case <-ctx.Done():
	}
}

// create creates a new environment and returns the environment name, or error
func (m *Manager) create(ctx context.Context, rd *models.RepoRevisionData) (envname string, err error) {
	end := m.MC.Timing(mpfx+"create", "triggering_repo:"+rd.Repo)
	span, ctx := tracer.StartSpanFromContext(ctx, "create")
	defer func() {
		end(fmt.Sprintf("success:%v", err == nil))
		span.Finish(tracer.WithError(err))
	}()
	env, err := m.generateNewEnv(ctx, rd)
	if err != nil {
		return "", fmt.Errorf("error generating environment data: %w", err)
	}
	eventlogger.GetLogger(ctx).SetNewStatus(models.CreateEvent, env.Name, *rd)
	m.setloggername(ctx, env.Name)
	newenv := &newEnv{env: env}
	ctx, cf := context.WithCancel(ctx)
	defer cf()
	go m.enforceTimeout(ctx, cf, newenv)
	defer func() {
		if err != nil {
			if err := m.DL.SetQAEnvironmentStatus(tracer.ContextWithSpan(context.Background(), span), env.Name, models.Failure); err != nil {
				m.log(ctx, "error setting environment status to failed: %v", err)
			}
			errmsg := "error creating: " + err.Error()
			m.pushNotification(ctx, newenv, notifier.Failure, errmsg)
			m.setGithubCommitStatus(ctx, rd, newenv, models.CommitStatusFailure, errmsg)
			eventlogger.GetLogger(ctx).SetCompletedStatus(models.FailedStatus)
			m.MC.Increment(mpfx+"create_errors", "triggering_repo:"+rd.Repo)
			return
		}
		// metahelm.Manager sets the success status on QAEnvironment
		m.pushNotification(ctx, newenv, notifier.Success, "")
		m.setGithubCommitStatus(ctx, rd, newenv, models.CommitStatusSuccess, "")
		eventlogger.GetLogger(ctx).SetCompletedStatus(models.DoneStatus)
	}()
	start := time.Now().UTC()
	newenv, err = m.processEnvConfig(ctx, env, rd)
	if err != nil {
		return "", fmt.Errorf("error processing environment config: %w", err)
	}
	elapsed := time.Since(start)
	eventlogger.GetLogger(ctx).SetInitialStatus(newenv.rc, elapsed)
	select {
	case <-ctx.Done():
		return "", nitroerrors.UserError(fmt.Errorf("context was cancelled in create"))
	default:
		break
	}
	m.pushNotification(ctx, newenv, notifier.CreateEnvironment, "")
	m.setGithubCommitStatus(ctx, rd, newenv, models.CommitStatusPending, "")
	td, cloc, err := m.fetchCharts(ctx, env.Name, newenv.rc)
	if err != nil {
		return "", fmt.Errorf("error fetching charts: %w", err)
	}
	defer billyutil.RemoveAll(m.FS, td)
	mcloc := metahelm.ChartLocations{}
	for k, v := range cloc {
		mcloc[k] = metahelm.ChartLocation{
			ChartPath:   v.ChartPath,
			VarFilePath: v.VarFilePath,
		}
	}

	if err = m.enforceGlobalLimit(ctx); err != nil {
		return "", fmt.Errorf("error enforcing global limit: %w", err)

	}

	chartSpan, ctx := tracer.StartSpanFromContext(ctx, "build_and_install_charts")
	if err = m.CI.BuildAndInstallCharts(ctx, &metahelm.EnvInfo{Env: newenv.env, RC: newenv.rc}, mcloc); err != nil {
		chartSpan.Finish(tracer.WithError(err))
		return "", fmt.Errorf("error installing charts: %w", nitroerrors.UserError(err))

	}
	chartSpan.Finish()
	return newenv.env.Name, nil
}

// Delete destroys an environment in k8s and marks it as such in the DB
func (m *Manager) Delete(ctx context.Context, rd *models.RepoRevisionData, reason models.QADestroyReason) error {
	var err error
	err = m.lockingOperation(ctx, rd.Repo, rd.PullRequest, func(ctx context.Context) error {
		return m.delete(ctx, rd, reason)
	})
	return err
}

var extantEnvsErr = errors.New("did not find exactly one extant environment")

// getenv returns the extant environment for rd or error
func (m *Manager) getenv(ctx context.Context, rd *models.RepoRevisionData) (*models.QAEnvironment, error) {
	envs, err := m.DL.GetExtantQAEnvironments(ctx, rd.Repo, rd.PullRequest)
	if err != nil {
		return nil, fmt.Errorf("error getting extant environments: %w", err)
	}
	if len(envs) != 1 {
		m.log(ctx, "expected exactly one extant environment but there are %v", len(envs))
		return nil, extantEnvsErr
	}
	return &envs[0], nil
}

func (m *Manager) delete(ctx context.Context, rd *models.RepoRevisionData, reason models.QADestroyReason) (err error) {
	end := m.MC.Timing(mpfx+"delete", "triggering_repo:"+rd.Repo)
	span, ctx := tracer.StartSpanFromContext(ctx, "delete")
	defer func() {
		end(fmt.Sprintf("success:%v", err == nil))
		span.Finish(tracer.WithError(err))
	}()
	env, err := m.getenv(ctx, rd)
	if err != nil {
		eventlogger.GetLogger(ctx).SetNewStatus(models.DestroyEvent, "<unknown>", *rd)
		defer eventlogger.GetLogger(ctx).SetCompletedStatus(models.DoneStatus)
		if err == extantEnvsErr {
			// if there's no extant envs, set all associated with the repo & PR to status destroyed
			m.log(ctx, "no extant envs for destroy request")
			envs, err := m.DL.GetQAEnvironmentsByRepoAndPR(ctx, rd.Repo, rd.PullRequest)
			if err != nil {
				return fmt.Errorf("error getting environments associated with the repo (%v) and PR (%v): %w", rd.Repo, rd.PullRequest, nitroerrors.SystemError(err))
			}
			if len(envs) > 0 {
				for _, e := range envs {
					m.log(ctx, "setting %v to status destroyed", e.Name)
					if err := m.DL.SetQAEnvironmentStatus(tracer.ContextWithSpan(context.Background(), span), e.Name, models.Destroyed); err != nil {
						m.log(ctx, "error setting status to destroyed for environment: %v: %v", e.Name, err)
					}
				}
			}
			return nil
		}
		return fmt.Errorf("error getting extant environment: %w", nitroerrors.SystemError(err))

	}
	eventlogger.GetLogger(ctx).SetNewStatus(models.DestroyEvent, env.Name, *rd)
	m.setloggername(ctx, env.Name)
	started := time.Now().UTC()
	ne, err := m.processEnvConfig(ctx, env, rd)
	if err != nil {
		// if there's an error getting or processing the config, continue on with default notifications
		// processEnvConfig() always returns a valid newenv
		m.log(ctx, "error processing environment config: %v", err)
	}
	elapsed := time.Since(started)
	eventlogger.GetLogger(ctx).SetInitialStatus(ne.rc, elapsed)
	defer func() {
		if err != nil {
			m.pushNotification(ctx, ne, notifier.Failure, "error destroying: "+err.Error())
			eventlogger.GetLogger(ctx).SetCompletedStatus(models.FailedStatus)
			return
		}
		eventlogger.GetLogger(ctx).SetCompletedStatus(models.DoneStatus)
	}()
	select {
	case <-ctx.Done():
		return nitroerrors.UserError(fmt.Errorf("context was cancelled in delete"))
	default:
		break
	}
	m.pushNotification(ctx, ne, notifier.DestroyEnvironment, "")
	k8senv, err := m.DL.GetK8sEnv(ctx, env.Name)
	if err != nil {
		return fmt.Errorf("error getting k8s environment: %w", nitroerrors.SystemError(err))
	}
	if k8senv == nil {
		return errors.New("missing k8s environment")
	}

	eventlogger.GetLogger(ctx).SetK8sNamespace(k8senv.Namespace)

	// Delete k8s resources asynchronously with retries
	go m.deleteNamespace(ctx, k8senv, rd.Repo)

	// use independent context for setting the status
	err = m.DL.SetQAEnvironmentStatus(tracer.ContextWithSpan(context.Background(), span), env.Name, models.Destroyed)
	if err != nil {
		return fmt.Errorf("error setting environment status: %w", nitroerrors.SystemError(err))
	}
	return nil
}

// deleteNamespace deletes a namespace and cleans up the database
func (m *Manager) deleteNamespace(ctx context.Context, k8senv *models.KubernetesEnvironment, repo string) {

	// new context with independent timeout, but preserve the eventlogger from the original context
	ctx, cf := context.WithTimeout(eventlogger.NewEventLoggerContext(context.Background(), eventlogger.GetLogger(ctx)), 10*time.Minute)
	defer cf()

	m.log(ctx, "beginning k8s delete for env: %v", k8senv.EnvName)

	dnend := m.MC.Timing(mpfx+"delete_namespace_duration", "triggering_repo:"+repo)

	// delete helm releases from DB only
	if _, err := m.DL.DeleteHelmReleasesForEnv(ctx, k8senv.EnvName); err != nil {
		m.log(ctx, "error deleting helm releases from DB: %v", err)
	}
	// delete NS with retry
	for i := 0; i < 3; i++ {
		if err := m.CI.DeleteNamespace(ctx, k8senv); err != nil {
			m.log(ctx, "error deleting namespace (try: %v): %v", i, err)
			continue
		}
		break
	}
	dnend()
	m.log(ctx, "completed k8s delete for env: %v", k8senv.EnvName)
}

// Update changes an existing environment
func (m *Manager) Update(ctx context.Context, rd models.RepoRevisionData) (string, error) {
	var err error
	var name string
	err = m.lockingOperation(ctx, rd.Repo, rd.PullRequest, func(ctx context.Context) error {
		name, err = m.update(ctx, &rd)
		return err
	})
	return name, err
}

func (m *Manager) update(ctx context.Context, rd *models.RepoRevisionData) (envname string, err error) {
	end := m.MC.Timing(mpfx+"update", "triggering_repo:"+rd.Repo)
	span, ctx := tracer.StartSpanFromContext(ctx, "update")
	defer func() {
		end(fmt.Sprintf("success:%v", err == nil))
		span.Finish(tracer.WithError(err))
	}()
	// check config signatures, if match then we can do chart upgrades
	// if mismatch, then tear down existing env and rebuild from scratch
	env, err := m.getenv(ctx, rd)
	if err != nil {
		if err == extantEnvsErr {
			// if there's no extant envs, go through the create flow (which will reuse the previous name, if a record exists)
			m.log(ctx, "could not find an extant environment so creating new env from scratch")
			m.MC.Increment(mpfx+"update_create", "triggering_repo:"+rd.Repo)
			return m.create(ctx, rd)
		}
		eventlogger.GetLogger(ctx).SetCompletedStatus(models.FailedStatus)
		return "", fmt.Errorf("error getting extant environment: %w", nitroerrors.SystemError(err))

	}
	eventlogger.GetLogger(ctx).SetNewStatus(models.UpdateEvent, env.Name, *rd)
	m.setloggername(ctx, env.Name)
	ne := &newEnv{env: env}
	ctx, cf := context.WithCancel(ctx)
	defer cf()
	go m.enforceTimeout(ctx, cf, ne)
	defer func() {
		if err != nil {
			if err := m.DL.SetQAEnvironmentStatus(tracer.ContextWithSpan(context.Background(), span), env.Name, models.Failure); err != nil {
				m.log(ctx, "error setting environment status to failed: %v", err)
			}
			m.pushNotification(ctx, ne, notifier.Failure, err.Error())
			m.setGithubCommitStatus(ctx, rd, ne, models.CommitStatusFailure, err.Error())
			eventlogger.GetLogger(ctx).SetCompletedStatus(models.FailedStatus)
			return
		}
		// metahelm.Manager sets the success status on QAEnvironment
		m.pushNotification(ctx, ne, notifier.Success, "")
		m.setGithubCommitStatus(ctx, rd, ne, models.CommitStatusSuccess, "")
		eventlogger.GetLogger(ctx).SetCompletedStatus(models.DoneStatus)
	}()
	started := time.Now().UTC()
	ne, err = m.processEnvConfig(ctx, env, rd)
	if err != nil {
		return "", fmt.Errorf("error processing environment config for update: %w", err)
	}
	elapsed := time.Since(started)
	eventlogger.GetLogger(ctx).SetInitialStatus(ne.rc, elapsed)
	k8senv, err := m.DL.GetK8sEnv(ctx, env.Name)
	if err != nil {
		return "", fmt.Errorf("error getting k8s environment: %w", nitroerrors.SystemError(err))
	}
	if k8senv == nil {
		return "", nitroerrors.SystemError(errors.New("missing k8s environment"))
	}
	select {
	case <-ctx.Done():
		return "", nitroerrors.UserError(fmt.Errorf("context was cancelled in update"))
	default:
		break
	}
	m.pushNotification(ctx, ne, notifier.UpdateEnvironment, "")
	m.setGithubCommitStatus(ctx, rd, ne, models.CommitStatusPending, "")
	td, cloc, err := m.fetchCharts(ctx, env.Name, ne.rc)
	if err != nil {
		return "", fmt.Errorf("error fetching charts: %w", err)
	}
	defer billyutil.RemoveAll(m.FS, td)
	mcloc := metahelm.ChartLocations{}
	for k, v := range cloc {
		mcloc[k] = metahelm.ChartLocation{
			ChartPath:   v.ChartPath,
			VarFilePath: v.VarFilePath,
		}
	}
	envinfo := &metahelm.EnvInfo{Env: env, RC: ne.rc}
	var sig [32]byte
	copy(sig[:], k8senv.ConfigSignature)
	if ne.rc.ConfigSignature() == sig && env.Status == models.Success {
		m.log(ctx, "config signature matches previous successful environment: performing helm release upgrades")
		m.MC.Increment(mpfx+"update_in_place", "triggering_repo:"+rd.Repo)
		releases, err := m.DL.GetHelmReleasesForEnv(ctx, env.Name)
		if err != nil {
			return "", fmt.Errorf("error getting helm releases for env: %w", nitroerrors.SystemError(err))
		}
		rsls := map[string]string{}
		for _, r := range releases {
			rsls[r.Name] = r.Release // chart title (dependency name) to release name
		}
		envinfo.Releases = rsls
		if err := m.CI.BuildAndUpgradeCharts(ctx, envinfo, k8senv, mcloc); err != nil {
			return envinfo.Env.Name, fmt.Errorf("error upgrading charts: %w", nitroerrors.UserError(err))

		}
		return envinfo.Env.Name, nil
	}
	m.log(ctx, "config signature mismatch or previous environment failed: tearing down namespace and building new env from scratch")
	m.MC.Increment(mpfx+"update_tear_down", "triggering_repo:"+rd.Repo)

	go m.deleteNamespace(ctx, k8senv, rd.Repo)

	chartSpan, ctx := tracer.StartSpanFromContext(ctx, "build_and_install_charts")
	if err = m.CI.BuildAndInstallCharts(ctx, &metahelm.EnvInfo{Env: ne.env, RC: ne.rc}, mcloc); err != nil {
		chartSpan.Finish(tracer.WithError(err))
		return "", fmt.Errorf("error installing charts: %w", nitroerrors.UserError(err))

	}
	chartSpan.Finish()

	return envinfo.Env.Name, nil
}
