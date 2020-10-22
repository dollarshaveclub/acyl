package persistence

import (
	"context"
	"net"
	"time"

	"github.com/dollarshaveclub/acyl/pkg/models"
	"github.com/dollarshaveclub/metahelm/pkg/metahelm"
	"github.com/google/uuid"
)

// LogFunc is a function that logs a formatted string somewhere
type LogFunc func(string, ...interface{})

// DataLayer describes an object that interacts with the persistant data store
type DataLayer interface {
	CreateQAEnvironment(context.Context, *QAEnvironment) error
	GetQAEnvironment(context.Context, string) (*QAEnvironment, error)
	GetQAEnvironmentConsistently(context.Context, string) (*QAEnvironment, error)
	GetQAEnvironments(context.Context) ([]QAEnvironment, error)
	DeleteQAEnvironment(context.Context, string) error
	GetQAEnvironmentsByStatus(ctx context.Context, status string) ([]QAEnvironment, error)
	GetRunningQAEnvironments(context.Context) ([]QAEnvironment, error)
	GetQAEnvironmentsByRepoAndPR(context.Context, string, uint) ([]QAEnvironment, error)
	GetQAEnvironmentsByRepo(ctx context.Context, repo string) ([]QAEnvironment, error)
	GetQAEnvironmentBySourceSHA(ctx context.Context, sourceSHA string) (*QAEnvironment, error)
	GetQAEnvironmentsBySourceBranch(ctx context.Context, sourceBranch string) ([]QAEnvironment, error)
	GetQAEnvironmentsByUser(ctx context.Context, user string) ([]QAEnvironment, error)
	SetQAEnvironmentStatus(context.Context, string, EnvironmentStatus) error
	SetQAEnvironmentRepoData(context.Context, string, *RepoRevisionData) error
	SetQAEnvironmentRefMap(context.Context, string, RefMap) error
	SetQAEnvironmentCommitSHAMap(context.Context, string, RefMap) error
	SetQAEnvironmentCreated(context.Context, string, time.Time) error
	GetExtantQAEnvironments(context.Context, string, uint) ([]QAEnvironment, error)
	SetAminoEnvironmentID(ctx context.Context, name string, did int) error
	SetAminoServiceToPort(ctx context.Context, name string, serviceToPort map[string]int64) error
	SetAminoKubernetesNamespace(ctx context.Context, name, namespace string) error
	AddEvent(context.Context, string, string) error
	Search(ctx context.Context, opts models.EnvSearchParameters) ([]QAEnvironment, error)
	GetMostRecent(ctx context.Context, n uint) ([]QAEnvironment, error)
	Close() error
	HelmDataLayer
	K8sEnvDataLayer
	EventLoggerDataLayer
	UISessionsDataLayer
	APIKeyDataLayer
}

// HelmDataLayer describes an object that stores data about Helm
type HelmDataLayer interface {
	GetHelmReleasesForEnv(ctx context.Context, name string) ([]models.HelmRelease, error)
	UpdateHelmReleaseRevision(ctx context.Context, envname, release, revision string) error
	CreateHelmReleasesForEnv(ctx context.Context, releases []models.HelmRelease) error
	DeleteHelmReleasesForEnv(ctx context.Context, name string) (uint, error)
}

// K8sEnvDataLayer describes an object that stores data about the K8s environment details
type K8sEnvDataLayer interface {
	GetK8sEnv(ctx context.Context, name string) (*models.KubernetesEnvironment, error)
	GetK8sEnvsByNamespace(ctx context.Context, ns string) ([]models.KubernetesEnvironment, error)
	CreateK8sEnv(ctx context.Context, env *models.KubernetesEnvironment) error
	DeleteK8sEnv(ctx context.Context, name string) error
	UpdateK8sEnvTillerAddr(ctx context.Context, envname, taddr string) error
	UpdateK8sEnvConfigSignature(ctx context.Context, name string, confSig [32]byte) error
}

// EventLoggerDataLayer desribes an object that stores event log data
type EventLoggerDataLayer interface {
	GetEventLogByID(id uuid.UUID) (*models.EventLog, error)
	GetEventLogByDeliveryID(deliveryID uuid.UUID) (*models.EventLog, error)
	GetEventLogsByEnvName(name string) ([]models.EventLog, error)
	GetEventLogsByRepoAndPR(repo string, pr uint) ([]models.EventLog, error)
	CreateEventLog(elog *models.EventLog) error
	SetEventLogEnvName(id uuid.UUID, name string) error
	AppendToEventLog(id uuid.UUID, msg string) error
	DeleteEventLog(id uuid.UUID) error
	DeleteEventLogsByEnvName(name string) (uint, error)
	DeleteEventLogsByRepoAndPR(repo string, pr uint) (uint, error)
	SetEventStatus(id uuid.UUID, status models.EventStatusSummary) error
	SetEventStatusConfig(id uuid.UUID, processingTime time.Duration, refmap map[string]string) error
	SetEventStatusConfigK8sNS(id uuid.UUID, ns string) error
	SetEventStatusTree(id uuid.UUID, tree map[string]models.EventStatusTreeNode) error
	SetEventStatusCompleted(id uuid.UUID, configStatus models.EventStatus) error
	SetEventStatusImageStarted(id uuid.UUID, name string) error
	SetEventStatusImageCompleted(id uuid.UUID, name string, err bool) error
	SetEventStatusChartStarted(id uuid.UUID, name string, status models.NodeChartStatus) error
	SetEventStatusChartCompleted(id uuid.UUID, name string, status models.NodeChartStatus) error
	GetEventStatus(id uuid.UUID) (*models.EventStatusSummary, error)
	SetEventStatusRenderedStatus(id uuid.UUID, rstatus models.RenderedEventStatus) error
	GetEventLogsWithStatusByEnvName(name string) ([]models.EventLog, error)
	SetEventStatusFailed(id uuid.UUID, ce metahelm.ChartError) error
}

type UISessionsDataLayer interface {
	CreateUISession(targetRoute string, state []byte, clientIP net.IP, userAgent string, expires time.Time) (int, error)
	UpdateUISession(id int, githubUser string, encryptedtoken []byte, authenticated bool) error
	DeleteUISession(id int) error
	GetUISession(id int) (*models.UISession, error)
	DeleteExpiredUISessions() (uint, error)
}

type APIKeyDataLayer interface {
	CreateAPIKey(ctx context.Context, permissionLevel models.PermissionLevel, name, description, githubUser string) (uuid.UUID, error)
	GetAPIKeyById(ctx context.Context, id uuid.UUID) (*models.APIKey, error)
	GetAPIKeysByGithubUser(ctx context.Context, githubUser string) ([]*models.APIKey, error)
	UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error
	DeleteAPIKey(ctx context.Context, id uuid.UUID) error
}