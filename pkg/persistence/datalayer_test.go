package persistence

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dollarshaveclub/acyl/pkg/models"
	"github.com/dollarshaveclub/metahelm/pkg/metahelm"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func TestDataLayerCreateQAEnvironment(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qae := QAEnvironment{
		Name:         "something-clever",
		Repo:         "dollarshaveclub/asdf",
		PullRequest:  1,
		User:         "alicejones",
		SourceBranch: "feature-4-lulz",
		SourceSHA:    "asdk9339kdkde9e9e",
		QAType:       "asdf",
	}
	err := dl.CreateQAEnvironment(context.Background(), &qae)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
}

func TestDataLayerGetQAEnvironment(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qae, err := dl.GetQAEnvironment(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if qae == nil {
		t.Fatalf("should have found env")
	}
	if qae.Name != "foo-bar" {
		t.Fatalf("wrong env: %v", qae.Name)
	}
}

func TestDataLayerGetQAEnvironmentConsistently(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qae, err := dl.GetQAEnvironmentConsistently(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if qae == nil {
		t.Fatalf("should have found env")
	}
	if qae.Name != "foo-bar" {
		t.Fatalf("wrong env: %v", qae.Name)
	}
}

func TestDataLayerGetQAEnvironments(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qs, err := dl.GetQAEnvironments(context.Background())
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(qs) != 7 {
		t.Fatalf("wrong count: %v", len(qs))
	}
}

func TestDataLayerDeleteQAEnvironment(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	err := dl.DeleteQAEnvironment(context.Background(), "foo-bar-2")
	if err == nil {
		t.Fatalf("delete should have failed because environment is not destroyed")
	}
	if err := dl.CreateK8sEnv(context.Background(), &models.KubernetesEnvironment{EnvName: "foo-bar-2", Namespace: "foo-bar"}); err != nil {
		t.Fatalf("create k8senv should have succeeded: %v", err)
	}
	if err := dl.CreateHelmReleasesForEnv(context.Background(), []models.HelmRelease{models.HelmRelease{EnvName: "foo-bar-2", Release: "foo"}}); err != nil {
		t.Fatalf("k8senv create should have succeeded: %v", err)
	}
	if err := dl.SetQAEnvironmentStatus(context.Background(), "foo-bar-2", models.Destroyed); err != nil {
		t.Fatalf("set status should have succeeded: %v", err)
	}
	err = dl.DeleteQAEnvironment(context.Background(), "foo-bar-2")
	if err != nil {
		t.Fatalf("delete should have succeeded: %v", err)
	}
	qae, err := dl.GetQAEnvironmentConsistently(context.Background(), "foo-bar-2")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	k8senv, err := dl.GetK8sEnv(context.Background(), "foo-bar-2")
	if err != nil {
		t.Fatalf("get k8senv should have succeeded: %v", err)
	}
	if k8senv != nil {
		t.Fatalf("k8senv should have been deleted")
	}
	hr, err := dl.GetHelmReleasesForEnv(context.Background(), "foo-bar-2")
	if err != nil {
		t.Fatalf("get helm releases should have succeeded: %v", err)
	}
	if len(hr) != 0 {
		t.Fatalf("helm releases should have been deleted")
	}
	if qae != nil {
		t.Fatalf("should have not found env")
	}
}

func TestDataLayerGetQAEnvironmentsByStatus(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qs, err := dl.GetQAEnvironmentsByStatus(context.Background(), "success")
	if err != nil {
		t.Fatalf("success get should have succeeded: %v", err)
	}
	if len(qs) != 5 {
		t.Fatalf("wrong success count: %v", len(qs))
	}
	qs, err = dl.GetQAEnvironmentsByStatus(context.Background(), "destroyed")
	if err != nil {
		t.Fatalf("destroy get should have succeeded: %v", err)
	}
	if len(qs) != 1 {
		t.Fatalf("wrong destroyed count: %v", len(qs))
	}
}

func TestDataLayerGetRunningQAEnvironments(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qs, err := dl.GetRunningQAEnvironments(context.Background())
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(qs) != 5 {
		t.Fatalf("wrong running count: %v", len(qs))
	}
	if !(qs[0].Created.Before(qs[1].Created) && qs[1].Created.Before(qs[2].Created) && qs[2].Created.Before(qs[3].Created) && qs[3].Created.Before(qs[4].Created)) {
		t.Fatalf("list should be sorted in ascending order")
	}
}

func TestDataLayerGetQAEnvironmentsByRepoAndPR(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qs, err := dl.GetQAEnvironmentsByRepoAndPR(context.Background(), "dollarshaveclub/foo-baz", 99)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(qs) != 2 {
		t.Fatalf("wrong running count: %v", len(qs))
	}
	for _, q := range qs {
		if !strings.Contains(q.Name, "foo-baz") {
			t.Fatalf("wrong name: %v", q.Name)
		}
	}
}

func TestDataLayerGetQAEnvironmentsByRepo(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qs, err := dl.GetQAEnvironmentsByRepo(context.Background(), "dollarshaveclub/foo-bar")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(qs) != 2 {
		t.Fatalf("wrong running count: %v", len(qs))
	}
	var found int
	for _, qa := range qs {
		if qa.Name == "foo-bar" {
			found++
		}
		if qa.Name == "foo-bar-2" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("unexpected qa list: %v", qs)
	}
}

func TestDataLayerSetQAEnvironmentStatus(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	err := dl.SetQAEnvironmentStatus(context.Background(), "foo-bar", models.Spawned)
	if err != nil {
		t.Fatalf("set should have succeeded: %v", err)
	}
	qae, err := dl.GetQAEnvironmentConsistently(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if qae.Name != "foo-bar" {
		t.Fatalf("wrong name: %v", qae.Name)
	}
	if qae.Status != models.Spawned {
		t.Fatalf("wrong status: %v", qae.Status)
	}
}

func TestDataLayerSetQAEnvironmentRepoData(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	rd := RepoRevisionData{
		User:         "bobsmith",
		Repo:         "foo/asdf",
		PullRequest:  110,
		SourceSHA:    "asdf1234",
		BaseSHA:      "qwerty5678",
		SourceBranch: "foo",
		BaseBranch:   "master",
	}
	err := dl.SetQAEnvironmentRepoData(context.Background(), "foo-bar", &rd)
	if err != nil {
		t.Fatalf("set should have succeeded: %v", err)
	}
	qae, err := dl.GetQAEnvironmentConsistently(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if qae.Name != "foo-bar" {
		t.Fatalf("wrong name: %v", qae.Name)
	}
	if qae.Repo != "foo/asdf" {
		t.Fatalf("wrong repo: %v", qae.Repo)
	}
	if qae.PullRequest != 110 {
		t.Fatalf("wrong pull request: %v", qae.PullRequest)
	}
	if qae.SourceSHA != rd.SourceSHA {
		t.Fatalf("wrong source sha: %v", qae.SourceSHA)
	}
	if qae.BaseSHA != rd.BaseSHA {
		t.Fatalf("wrong base sha: %v", qae.BaseSHA)
	}
	if qae.SourceBranch != rd.SourceBranch {
		t.Fatalf("wrong source branch: %v", qae.SourceBranch)
	}
	if qae.BaseBranch != rd.BaseBranch {
		t.Fatalf("wrong base branch: %v", qae.BaseBranch)
	}
	if qae.User != rd.User {
		t.Fatalf("wrong user: %v", qae.User)
	}
}

func TestDataLayerSetQAEnvironmentRefMap(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	err := dl.SetQAEnvironmentRefMap(context.Background(), "foo-bar", map[string]string{"dollarshaveclub/foo-bar": "some-branch"})
	if err != nil {
		t.Fatalf("set should have succeeded: %v", err)
	}
	qae, err := dl.GetQAEnvironmentConsistently(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if qae.Name != "foo-bar" {
		t.Fatalf("wrong name: %v", qae.Name)
	}
	if len(qae.RefMap) != 1 {
		t.Fatalf("wrong refmap size: %v", len(qae.RefMap))
	}
	if v, ok := qae.RefMap["dollarshaveclub/foo-bar"]; ok {
		if v != "some-branch" {
			t.Fatalf("wrong branch: %v", v)
		}
	} else {
		t.Fatalf("refmap missing key")
	}
}

func TestDataLayerSetQAEnvironmentCommitSHAMap(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	sha := "37a1218def12549a56e4e48be95d9cdf9a20d45d"
	err := dl.SetQAEnvironmentCommitSHAMap(context.Background(), "foo-bar", map[string]string{"dollarshaveclub/foo-bar": sha})
	if err != nil {
		t.Fatalf("set should have succeeded: %v", err)
	}
	qae, err := dl.GetQAEnvironmentConsistently(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if qae.Name != "foo-bar" {
		t.Fatalf("wrong name: %v", qae.Name)
	}
	if len(qae.CommitSHAMap) != 1 {
		t.Fatalf("wrong CommitSHAMap size: %v", len(qae.RefMap))
	}
	if v, ok := qae.CommitSHAMap["dollarshaveclub/foo-bar"]; ok {
		if v != sha {
			t.Fatalf("wrong commit sha: %v", v)
		}
	} else {
		t.Fatalf("CommitSHAMap missing key")
	}
}

func TestDataLayerSetQAEnvironmentCreated(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	ts := time.Now().UTC()
	err := dl.SetQAEnvironmentCreated(context.Background(), "foo-bar", ts)
	if err != nil {
		t.Fatalf("set should have succeeded: %v", err)
	}
	qae, err := dl.GetQAEnvironmentConsistently(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if qae.Name != "foo-bar" {
		t.Fatalf("wrong name: %v", qae.Name)
	}
	ts = ts.Truncate(1 * time.Microsecond)
	if !qae.Created.Truncate(1 * time.Microsecond).Equal(ts) {
		t.Fatalf("wrong created timestamp: %v (wanted: %v)", qae.Created, ts)
	}
}

func TestDataLayerGetExtantQAEnvironments(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qs, err := dl.GetExtantQAEnvironments(context.Background(), "dollarshaveclub/foo-baz", 99)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(qs) != 1 {
		t.Fatalf("wrong extant count: %v", len(qs))
	}
	if qs[0].Name != "foo-baz" {
		t.Fatalf("wrong name: %v", qs[0].Name)
	}
}

func TestDataLayerSetAminoEnvironmentID(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	err := dl.SetAminoEnvironmentID(context.Background(), "foo-bar", 1000)
	if err != nil {
		t.Fatalf("set should have succeeded: %v", err)
	}
	qae, err := dl.GetQAEnvironmentConsistently(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if qae.Name != "foo-bar" {
		t.Fatalf("wrong name: %v", qae.Name)
	}
	if qae.AminoEnvironmentID != 1000 {
		t.Fatalf("wrong amino env id: %v", qae.AminoEnvironmentID)
	}
}

func TestDataLayerSetAminoServiceToPort(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	err := dl.SetAminoServiceToPort(context.Background(), "foo-bar", map[string]int64{"oracle": 6666})
	if err != nil {
		t.Fatalf("set should have succeeded: %v", err)
	}
	qae, err := dl.GetQAEnvironmentConsistently(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if qae.Name != "foo-bar" {
		t.Fatalf("wrong name: %v", qae.Name)
	}
	if v, ok := qae.AminoServiceToPort["oracle"]; ok {
		if v != 6666 {
			t.Fatalf("wrong port: %v", v)
		}
	} else {
		t.Fatalf("AminoServiceToPort missing key")
	}
}

func TestDataLayerSetAminoKubernetesNamespace(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	err := dl.SetAminoKubernetesNamespace(context.Background(), "foo-bar", "k8s-foo-bar")
	if err != nil {
		t.Fatalf("set should have succeeded: %v", err)
	}
	qae, err := dl.GetQAEnvironmentConsistently(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if qae.Name != "foo-bar" {
		t.Fatalf("wrong name: %v", qae.Name)
	}
	if qae.AminoKubernetesNamespace != "k8s-foo-bar" {
		t.Fatalf("wrong amino k8s namespace: %v", qae.AminoKubernetesNamespace)
	}
}

func TestDataLayerAddEvent(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qae, err := dl.GetQAEnvironment(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("first get should have succeeded: %v", err)
	}
	if qae.Name != "foo-bar" {
		t.Fatalf("wrong env: %v", qae.Name)
	}
	i := len(qae.Events)
	err = dl.AddEvent(context.Background(), "foo-bar", "this is a msg")
	if err != nil {
		t.Fatalf("add should have succeeded: %v", err)
	}
	qae, err = dl.GetQAEnvironmentConsistently(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("second get should have succeeded: %v", err)
	}
	if len(qae.Events) != i+1 {
		t.Fatalf("bad event count: %v", len(qae.Events))
	}
	if qae.Events[i].Message != "this is a msg" {
		t.Fatalf("bad msg: %v", qae.Events[1].Message)
	}
}

func TestDataLayerGetQAEnvironmentBySourceSHA(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qae, err := dl.GetQAEnvironmentBySourceSHA(context.Background(), "93jdhsksjusnc839")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if qae.Name != "foo-baz" {
		t.Fatalf("wrong env: %v", qae.Name)
	}
}

func TestDataLayerGetQAEnvironmentBySourceBranch(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qas, err := dl.GetQAEnvironmentsBySourceBranch(context.Background(), "feature-crash-the-site")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(qas) != 1 {
		t.Fatalf("bad qa count: %v (wanted 1)", len(qas))
	}
	if qas[0].Name != "foo-baz" {
		t.Fatalf("wrong env: %v", qas[0].Name)
	}
}

func TestDataLayerGetQAEnvironmentByUser(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qas, err := dl.GetQAEnvironmentsByUser(context.Background(), "alicejones")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(qas) != 1 {
		t.Fatalf("bad qa count: %v (wanted 1)", len(qas))
	}
	if qas[0].Name != "foo-bar-2" {
		t.Fatalf("wrong env: %v", qas[0].Name)
	}
}
func TestDataLayerSearch(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	tests := []struct {
		name       string
		opts       models.EnvSearchParameters
		verifyfunc func([]models.QAEnvironment, error) error
	}{
		{
			name: "by repo",
			opts: models.EnvSearchParameters{
				Repo: "dollarshaveclub/foo-bar",
			},
			verifyfunc: func(envs []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("repo: should have succeeded: %v", err)
				}
				if len(envs) != 2 {
					return fmt.Errorf("repo: unexpected length: %v", len(envs))
				}
				return nil
			},
		},
		{
			name: "by repo and pr",
			opts: models.EnvSearchParameters{
				Repo: "dollarshaveclub/foo-bar",
				Pr:   99,
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("repo/pr: should have succeeded: %v", err)
				}
				if len(qas) != 1 {
					return fmt.Errorf("repo/pr: unexpected length: %v", len(qas))
				}
				if qas[0].Name != "foo-bar" {
					return fmt.Errorf("repo/pr: bad qa: %v", qas[0].Name)
				}
				return nil
			},
		},
		{
			name: "by source sha",
			opts: models.EnvSearchParameters{
				SourceSHA: "372829sskskskdkdke499393",
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("source sha: should have succeeded: %v", err)
				}
				if len(qas) != 1 {
					return fmt.Errorf("source sha: unexpected length: %v", len(qas))
				}
				if qas[0].Name != "biz-baz" {
					return fmt.Errorf("source sha: bad qa: %v", qas[0].Name)
				}
				return nil
			},
		},
		{
			name: "by source branch",
			opts: models.EnvSearchParameters{
				SourceBranch: "feature-crash-the-site",
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("source branch: should have succeeded: %v", err)
				}
				if len(qas) != 1 {
					return fmt.Errorf("source branch:unexpected length: %v", len(qas))
				}
				if qas[0].Name != "foo-baz" {
					return fmt.Errorf("source branch:bad qa: %v", qas[0].Name)
				}
				return nil
			},
		},
		{
			name: "by user",
			opts: models.EnvSearchParameters{
				User: "bobsmith",
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("user: should have succeeded: %v", err)
				}
				if len(qas) != 1 {
					return fmt.Errorf("user: unexpected length: %v", len(qas))
				}
				if qas[0].Name != "foo-bar" {
					return fmt.Errorf("user: bad qa: %v", qas[0].Name)
				}
				return nil
			},
		},
		{
			name: "by status",
			opts: models.EnvSearchParameters{
				Status: models.Success,
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("status: should have succeeded: %v", err)
				}
				if len(qas) != 5 {
					return fmt.Errorf("status: unexpected length: %v", len(qas))
				}
				return nil
			},
		},
		{
			name: "by repo, source branch, user and status",
			opts: models.EnvSearchParameters{
				Repo:         "dollarshaveclub/foo-bar",
				SourceBranch: "feature-sell-moar-stuff",
				User:         "alicejones",
				Status:       models.Success,
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("multi 1: should have succeeded: %v", err)
				}
				if len(qas) != 1 {
					return fmt.Errorf("multi 1: unexpected length: %v", len(qas))
				}
				if qas[0].Name != "foo-bar-2" {
					return fmt.Errorf("multi 1: bad qa: %v", qas[0].Name)
				}
				return nil
			},
		},
		{
			name: "by repo and status = success",
			opts: models.EnvSearchParameters{
				Repo:   "dollarshaveclub/biz-baz",
				Status: models.Success,
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("repo + status success: should have succeeded: %v", err)
				}
				if len(qas) != 2 {
					return fmt.Errorf("repo + status success: unexpected length: %v", len(qas))
				}
				return nil
			},
		},
		{
			name: "by repo and status = destroyed",
			opts: models.EnvSearchParameters{
				Repo:   "dollarshaveclub/biz-baz",
				Status: models.Destroyed,
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("repo + status destroyed: should have succeeded: %v", err)
				}
				if len(qas) != 1 {
					return fmt.Errorf("repo + status destroyed: unexpected length: %v", len(qas))
				}
				if qas[0].Name != "biz-baz" {
					return fmt.Errorf("repo + status destroyed: unexpected name: %v", qas[0].Name)
				}
				return nil
			},
		},
		{
			name: "by repo, source branch, user and status",
			opts: models.EnvSearchParameters{
				Repo:         "dollarshaveclub/foo-bar",
				SourceBranch: "feature-sell-moar-stuff",
				User:         "notalicejones",
				Status:       models.Success,
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("multi 2: should have succeeded: %v", err)
				}
				if len(qas) != 0 {
					return fmt.Errorf("multi 2: expected no results: %v", qas)
				}
				return nil
			},
		},
		{
			name: "by multiple statuses",
			opts: models.EnvSearchParameters{
				Statuses: []EnvironmentStatus{models.Destroyed, models.Failure},
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("statuses: should have succeeded: %v", err)
				}
				if len(qas) != 2 {
					return fmt.Errorf("statuses: expected 2, got: %v", len(qas))
				}
				return nil
			},
		},
		{
			name: "by created since",
			opts: models.EnvSearchParameters{
				CreatedSince: 2 * 24 * time.Hour,
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("created since: should have succeeded: %v", err)
				}
				if len(qas) != 2 {
					return fmt.Errorf("created since: expected 2, got: %v", len(qas))
				}
				return nil
			},
		},
		{
			name: "by created since, user and multiple statuses",
			opts: models.EnvSearchParameters{
				CreatedSince: 2 * 24 * time.Hour,
				User:         "bobsmith",
				Statuses:     []EnvironmentStatus{models.Success, models.Spawned, models.Updating, models.Failure},
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("multi userenvs: should have succeeded: %v", err)
				}
				if len(qas) != 1 {
					return fmt.Errorf("multi userenvs: expected 1, got: %v", len(qas))
				}
				return nil
			},
		},
		{
			name: "by multiple repos",
			opts: models.EnvSearchParameters{
				Repos: []string{"dollarshaveclub/foo-bar", "dollarshaveclub/biz-baz"},
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err != nil {
					return fmt.Errorf("multi repos: should have succeeded: %v", err)
				}
				if len(qas) != 5 {
					return fmt.Errorf("multi repos: expected 5, got: %v", len(qas))
				}
				return nil
			},
		},
		{
			name: "error for repo and repos",
			opts: models.EnvSearchParameters{
				Repo:  "dollarshaveclub/something",
				Repos: []string{"dollarshaveclub/foo-bar", "dollarshaveclub/biz-baz"},
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for both repo and repos")
				}
				return nil
			},
		},
		{
			name: "error for status and statuses",
			opts: models.EnvSearchParameters{
				Status:   models.Success,
				Statuses: []EnvironmentStatus{models.Spawned, models.Updating, models.Failure},
			},
			verifyfunc: func(qas []models.QAEnvironment, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for both status and statuses")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.verifyfunc(dl.Search(context.Background(), tt.opts)); err != nil {
				t.Errorf("subtest %v failed: %v", tt.name, err)
			}
		})
	}
}

func TestDataLayerGetMostRecentEmpty(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qas, err := dl.GetMostRecent(context.Background(), 0)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(qas) != 0 {
		t.Fatalf("should have empty results: %v", qas)
	}
}

func TestDataLayerGetMostRecentFiveDays(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qas, err := dl.GetMostRecent(context.Background(), 5)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(qas) != 5 {
		t.Fatalf("should have returned all envs: %v", qas)
	}
}

func TestDataLayerGetMostRecentTwoDays(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qas, err := dl.GetMostRecent(context.Background(), 2)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(qas) != 2 {
		t.Fatalf("should have returned two envs: %v", qas)
	}
}

func TestDataLayerGetMostRecentOneDay(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qas, err := dl.GetMostRecent(context.Background(), 1)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(qas) != 1 {
		t.Fatalf("should have returned one env: %v", qas)
	}
}

func TestDataLayerGetMostRecentOrdering(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	qas, err := dl.GetMostRecent(context.Background(), 5)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(qas) != 5 {
		t.Fatalf("should have returned all envs: %v", qas)
	}
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		got := qas[i].Created.String()
		expectedPrefix := now.AddDate(0, 0, -i).Format("2006-01-02")
		if !strings.HasPrefix(got, expectedPrefix) {
			t.Fatalf("bad ordering: got %s, expected prefix %s: %v\n", got, expectedPrefix, qas)
		}
	}
}

func TestDataLayerGetHelmReleasesForEnv(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	releases, err := dl.GetHelmReleasesForEnv(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(releases) == 0 {
		t.Fatalf("empty results")
	}
	for i, r := range releases {
		if r.EnvName != "foo-bar" {
			t.Fatalf("bad env name: %v", r.EnvName)
		}
		if r.Created.Equal(time.Time{}) {
			t.Fatalf("zero value for created (offset: %v): %v", i, r.Created)
		}
	}
}

func TestDataLayerUpdateHelmReleaseRevision(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	if err := dl.UpdateHelmReleaseRevision(context.Background(), "foo-bar", "some-random-name", "9999"); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	rel, err := dl.GetHelmReleasesForEnv(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	for _, r := range rel {
		if r.Release == "some-random-name" {
			if r.RevisionSHA != "9999" {
				t.Fatalf("bad revision: %v", r.RevisionSHA)
			}
		}
	}
}

func TestDataLayerCreateHelmReleasesForEnv(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	releases := []models.HelmRelease{
		models.HelmRelease{EnvName: "foo-bar-2", Release: "some-random-name", Name: "dollarshaveclub-foo-bar-2"},
		models.HelmRelease{EnvName: "foo-bar-2", Release: "some-random-name2", Name: "dollarshaveclub-foo-bar-3"},
		models.HelmRelease{EnvName: "foo-bar-2", Release: "some-random-name3", Name: "dollarshaveclub-foo-bar-4"},
	}
	if err := dl.CreateHelmReleasesForEnv(context.Background(), releases); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	releases, err := dl.GetHelmReleasesForEnv(context.Background(), "foo-bar-2")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if len(releases) != 3 {
		t.Fatalf("bad result length: %v", len(releases))
	}
	if releases[0].EnvName != "foo-bar-2" {
		t.Fatalf("bad env name: %v", releases[0].EnvName)
	}
	releases = []models.HelmRelease{models.HelmRelease{EnvName: "asdf", Release: "some-random-name", Name: "dollarshaveclub-foo-bar-2"}}
	if err := dl.CreateHelmReleasesForEnv(context.Background(), releases); err == nil {
		t.Fatalf("should have failed with env not found")
	}
}

func TestDataLayerDeleteHelmReleasesForEnv(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	n, err := dl.DeleteHelmReleasesForEnv(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if n != 2 {
		t.Fatalf("bad count: %v", n)
	}
	releases, err := dl.GetHelmReleasesForEnv(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if len(releases) != 0 {
		t.Fatalf("bad result length: %v", len(releases))
	}
	n, err = dl.DeleteHelmReleasesForEnv(context.Background(), "does-not-exist")
	if err != nil || n != 0 {
		t.Fatalf("should have succeeded: %v", err)
	}
}

func TestDataLayerGetK8sEnv(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	env, err := dl.GetK8sEnv(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if env.EnvName != "foo-bar" {
		t.Fatalf("bad env name: %v", env.EnvName)
	}
	if env.TillerAddr != "10.10.10.10:1234" {
		t.Fatalf("bad tiller addr: %v", env.TillerAddr)
	}
	if env.Created.Equal(time.Time{}) {
		t.Fatalf("zero value for created: %v", env.Created)
	}
	env, err = dl.GetK8sEnv(context.Background(), "does-not-exist")
	if err != nil {
		t.Fatalf("should have succeeded with empty results: %v", err)
	}
	if env != nil {
		t.Fatalf("should have returned a nil env: %v", env)
	}
}

func TestDataLayerGetK8sEnvByNamespace(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	envs, err := dl.GetK8sEnvsByNamespace(context.Background(), "foo")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if len(envs) != 1 {
		t.Fatalf("should have found k8senv")
	}
	env := envs[0]
	if env.EnvName != "foo-bar" {
		t.Fatalf("bad env name: %v", env.EnvName)
	}
	if env.TillerAddr != "10.10.10.10:1234" {
		t.Fatalf("bad tiller addr: %v", env.TillerAddr)
	}
	if env.Created.Equal(time.Time{}) {
		t.Fatalf("zero value for created: %v", env.Created)
	}
	envs, err = dl.GetK8sEnvsByNamespace(context.Background(), "does-not-exist")
	if err != nil {
		t.Fatalf("should have succeeded with empty results: %v", err)
	}
	if len(envs) != 0 {
		t.Fatalf("should have returned a zero envs: %v", env)
	}
}

func TestDataLayerCreateK8sEnv(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	if err := dl.CreateK8sEnv(context.Background(), &models.KubernetesEnvironment{EnvName: "foo-bar-2"}); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if err := dl.CreateK8sEnv(context.Background(), &models.KubernetesEnvironment{EnvName: "does-not-exist"}); err == nil {
		t.Fatalf("should have failed with unknown env")
	}
}

func TestDataLayerDeleteK8sEnv(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	if err := dl.DeleteK8sEnv(context.Background(), "foo-bar"); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if err := dl.DeleteK8sEnv(context.Background(), "does-not-exist"); err != nil {
		t.Fatalf("delete of non-extant env should have succeeded: %v", err)
	}
}

func TestDataLayerUpdateK8sEnvTillerAddr(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	if err := dl.UpdateK8sEnvTillerAddr(context.Background(), "foo-bar", "192.168.1.1:1234"); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	env, err := dl.GetK8sEnv(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("get env should have succeeded: %v", err)
	}
	if env.TillerAddr != "192.168.1.1:1234" {
		t.Fatalf("bad tiller addr: %v", env.TillerAddr)
	}
}

func TestDataLayerUpdateK8sEnvConfSignature(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	var confSig [32]byte
	copy(confSig[:], []byte("f0o0o0b0a0r0n0e0w0s0i0g0n0a0t0u0"))
	if err := dl.UpdateK8sEnvConfigSignature(context.Background(), "foo-bar", confSig); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	env, err := dl.GetK8sEnv(context.Background(), "foo-bar")
	if err != nil {
		t.Fatalf("get env should have succeeded: %v", err)
	}
	if compResult := bytes.Compare(env.ConfigSignature, confSig[:]); compResult != 0 {
		t.Fatalf("bad config signature: %v", env.ConfigSignature)
	}
}

func TestDataLayerGetEventLogByID(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id, _ := uuid.Parse("db20d1e7-1e0d-45c6-bfe1-4ea24b7f4159")
	el, err := dl.GetEventLogByID(id)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if el == nil {
		t.Fatalf("empty result")
	}
	if i := len(el.Log); i != 2 {
		t.Fatalf("expected log length of 2: %v", i)
	}
	if el.EnvName != "foo-bar" {
		t.Fatalf("unexpected env name: %v", el.EnvName)
	}
	if el.Created.Equal(time.Time{}) {
		t.Fatalf("zero value for created: %v", el.Created)
	}
	if el.LogKey == uuid.Nil {
		t.Fatalf("unset log key: %v", el.LogKey)
	}
	// null delivery id
	id, _ = uuid.Parse("9beb4f55-bc47-4411-b17d-78e2c0bccb26")
	el, err = dl.GetEventLogByID(id)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if el.GitHubDeliveryID != uuid.Nil {
		t.Fatalf("expected empty delivery id: %v", el.GitHubDeliveryID)
	}
}

func TestDataLayerGetEventLogByDeliveryID(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("db20d1e7-1e0d-45c6-bfe1-4ea24b7f4159"))
	did := uuid.Must(uuid.Parse("ec7014ee-b691-47fd-a011-8ae1a37ce406"))
	el, err := dl.GetEventLogByDeliveryID(did)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if el == nil {
		t.Fatalf("empty result")
	}
	if el.GitHubDeliveryID != did {
		t.Fatalf("bad delivery id: %v", el.GitHubDeliveryID)
	}
	if el.ID != id {
		t.Fatalf("bad id: %v", el.ID)
	}
	if el.EnvName != "foo-bar" {
		t.Fatalf("unexpected env name: %v", el.EnvName)
	}
}

func TestDataLayerGetEventLogsByEnvName(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	logs, err := dl.GetEventLogsByEnvName("foo-bar")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if i := len(logs); i != 2 {
		t.Fatalf("expected length of 2: %v", i)
	}
}

func TestDataLayerGetEventLogsWithStatusByEnvName(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	logs, err := dl.GetEventLogsWithStatusByEnvName("foo-bar-2")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if i := len(logs); i != 1 {
		t.Fatalf("expected length of 1: %v", i)
	}
	if logs[0].Status.Config.Status == 0 {
		t.Fatalf("zero value for config status")
	}
	if len(logs[0].Status.Tree) == 0 {
		t.Fatalf("zero length for status tree")
	}
}

func TestDataLayerGetEventLogsByRepoAndPR(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	logs, err := dl.GetEventLogsByRepoAndPR("acme/something", 23)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if i := len(logs); i != 1 {
		t.Fatalf("expected length of 1: %v", i)
	}
}

func TestDataLayerCreateEventLog(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	el := models.EventLog{
		ID:      uuid.Must(uuid.NewRandom()),
		EnvName: "asdf",
		Log: []string{
			"foo",
		},
	}
	if err := dl.CreateEventLog(&el); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	el2, err := dl.GetEventLogByID(el.ID)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if el2.EnvName != el.EnvName {
		t.Fatalf("bad env name: %v", el2.EnvName)
	}
	if el2.Log[0] != el.Log[0] {
		t.Fatalf("bad log: %v", el2.Log)
	}
	if el2.LogKey == uuid.Nil {
		t.Fatalf("unset log key: %v", el2.LogKey)
	}
}

func TestDataLayerAppendToEventLog(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("db20d1e7-1e0d-45c6-bfe1-4ea24b7f4159"))
	if err := dl.AppendToEventLog(id, "foo"); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	el, err := dl.GetEventLogByID(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if i := len(el.Log); i != 3 {
		t.Fatalf("bad length: %v", i)
	}
	if el.Log[2] != "foo" {
		t.Fatalf("bad log msg: %v", el.Log[2])
	}
}

func TestDataLayerSetEventLogEnvName(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("db20d1e7-1e0d-45c6-bfe1-4ea24b7f4159"))
	if err := dl.SetEventLogEnvName(id, "1234"); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	el, err := dl.GetEventLogByID(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if el.EnvName != "1234" {
		t.Fatalf("bad env name: %v", el.EnvName)
	}
}

func TestDataLayerDeleteEventLog(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("db20d1e7-1e0d-45c6-bfe1-4ea24b7f4159"))
	if err := dl.DeleteEventLog(id); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	el, err := dl.GetEventLogByID(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if el != nil {
		t.Fatalf("expected empty results: %v", el)
	}
}

func TestDataLayerDeleteEventLogsByEnvName(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	n, err := dl.DeleteEventLogsByEnvName("foo-bar")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected delete count of 2: %v", n)
	}
	logs, err := dl.GetEventLogsByEnvName("foo-bar")
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if i := len(logs); i != 0 {
		t.Fatalf("expected empty results: len: %v: %v", i, logs)
	}
}

func TestDataLayerDeleteEventLogsByRepoAndPR(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	n, err := dl.DeleteEventLogsByRepoAndPR("acme/something", 23)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected delete count of 1: %v", n)
	}
	logs, err := dl.GetEventLogsByRepoAndPR("acme/something", 23)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if i := len(logs); i != 0 {
		t.Fatalf("expected empty results: len: %v: %v", i, logs)
	}
}

func TestDataLayerSetEventStatus(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	logs, err := dl.GetEventLogsByEnvName("foo-bar")
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if i := len(logs); i != 2 {
		t.Fatalf("expected length of 2: %v", i)
	}
	elog := logs[0]
	s := models.EventStatusSummary{
		Config: models.EventStatusSummaryConfig{
			Status: models.PendingStatus,
		},
		Tree: map[string]models.EventStatusTreeNode{
			"foo/bar": models.EventStatusTreeNode{},
		},
	}
	if err := dl.SetEventStatus(elog.ID, s); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	s2, err := dl.GetEventStatus(elog.ID)
	if err != nil {
		t.Fatalf("get 2 should have succeeded: %v", err)
	}
	if s2.Config.Status != models.PendingStatus {
		t.Fatalf("unexpected status: %v (%v)", s2.Config.Status, s2.Config.Status.String())
	}
}

func TestDataLayerSetEventStatusConfig(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("c1e1e229-86d8-4d99-a3d5-62b2f6390bbe"))
	if err := dl.SetEventStatusConfig(id, 10*time.Millisecond, map[string]string{"foo/bar": "asdf"}); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	s, err := dl.GetEventStatus(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if refmap := s.Config.RefMap; len(refmap) != 1 {
		t.Fatalf("unexpected refmap: %+v", refmap)
	}
	if s.Config.ProcessingTime.Duration == 0 {
		t.Fatalf("processing_time should have been set")
	}
}

func TestDataLayerSetEventStatusConfigK8sNS(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("c1e1e229-86d8-4d99-a3d5-62b2f6390bbe"))
	if err := dl.SetEventStatusConfigK8sNS(id, "nitro-93938-some-name"); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	s, err := dl.GetEventStatus(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if s.Config.K8sNamespace != "nitro-93938-some-name" {
		t.Fatalf("unexpected k8s ns: %v", s.Config.K8sNamespace)
	}
}

func TestDataLayerSetEventStatusTree(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("c1e1e229-86d8-4d99-a3d5-62b2f6390bbe"))
	if err := dl.SetEventStatusTree(id, map[string]models.EventStatusTreeNode{
		"foo/bar": models.EventStatusTreeNode{Parent: "foo"},
	}); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	s, err := dl.GetEventStatus(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if tree := s.Tree; len(tree) != 1 {
		t.Fatalf("unexpected tree: %+v", tree)
	}
	if node, ok := s.Tree["foo/bar"]; !ok || node.Parent != "foo" {
		t.Fatalf("unexpected or missing node: %v: %+v", ok, node)
	}
}

func TestDataLayerSetEventStatusCompleted(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("c1e1e229-86d8-4d99-a3d5-62b2f6390bbe"))
	if err := dl.SetEventStatusCompleted(id, models.DoneStatus); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	s, err := dl.GetEventStatus(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if status := s.Config.Status; status != models.DoneStatus {
		t.Fatalf("unexpected status: %v", status)
	}
	if s.Config.Completed.IsZero() {
		t.Fatalf("completed should have been set")
	}
}

func TestDataLayerSetEventStatusFailed(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	ce := metahelm.ChartError{
		FailedDeployments: map[string][]metahelm.FailedPod{
			"foo": {
				{
					Name:   "foo",
					Reason: "readiness probe failed",
				},
			},
		},
	}
	id := uuid.Must(uuid.Parse("c1e1e229-86d8-4d99-a3d5-62b2f6390bbe"))
	if err := dl.SetEventStatusFailed(id, ce); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	s, err := dl.GetEventStatus(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if status := s.Config.Status; status != models.FailedStatus {
		t.Fatalf("unexpected status: %v", status)
	}
	if s.Config.Completed.IsZero() {
		t.Fatalf("completed should have been set")
	}
	if diff := cmp.Diff(s.Config.FailedResources, ce); diff != "" {
		t.Fatalf("SetEventStatusFailed() (-expected +got):\n%s\n", diff)
	}
}

func TestDataLayerSetEventStatusImageStarted(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("c1e1e229-86d8-4d99-a3d5-62b2f6390bbe"))
	if err := dl.SetEventStatusImageStarted(id, "foo/bar"); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	s, err := dl.GetEventStatus(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if s.Tree["foo/bar"].Image.Started.IsZero() {
		t.Fatalf("started should have been set")
	}
}

func TestDataLayerSetEventStatusImageCompleted(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("c1e1e229-86d8-4d99-a3d5-62b2f6390bbe"))
	if err := dl.SetEventStatusImageCompleted(id, "foo/bar", true); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	s, err := dl.GetEventStatus(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if s.Tree["foo/bar"].Image.Completed.IsZero() {
		t.Fatalf("completed should have been set")
	}
	if !s.Tree["foo/bar"].Image.Error {
		t.Fatalf("error should have been set")
	}
}

func TestDataLayerSetEventStatusChartStarted(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("c1e1e229-86d8-4d99-a3d5-62b2f6390bbe"))
	if err := dl.SetEventStatusChartStarted(id, "foo/bar", models.InstallingChartStatus); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	s, err := dl.GetEventStatus(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if s.Tree["foo/bar"].Chart.Started.IsZero() {
		t.Fatalf("started should have been set")
	}
	if status := s.Tree["foo/bar"].Chart.Status; status != models.InstallingChartStatus {
		t.Fatalf("unexpected chart status: %v", status)
	}
}

func TestDataLayerSetEventStatusChartCompleted(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("c1e1e229-86d8-4d99-a3d5-62b2f6390bbe"))
	if err := dl.SetEventStatusChartCompleted(id, "foo/bar", models.DoneChartStatus); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	s, err := dl.GetEventStatus(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if s.Tree["foo/bar"].Chart.Completed.IsZero() {
		t.Fatalf("completed should have been set")
	}
	if status := s.Tree["foo/bar"].Chart.Status; status != models.DoneChartStatus {
		t.Fatalf("unexpected chart status: %v", status)
	}
}

func TestDataLayerGetEventStatus(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("c1e1e229-86d8-4d99-a3d5-62b2f6390bbe"))
	if err := dl.SetEventStatusChartCompleted(id, "foo/bar", models.DoneChartStatus); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	_, err := dl.GetEventStatus(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
}

func TestDataLayerSetEventStatusRenderedStatus(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id := uuid.Must(uuid.Parse("c1e1e229-86d8-4d99-a3d5-62b2f6390bbe"))
	rstat := models.RenderedEventStatus{
		Description:   "something",
		LinkTargetURL: "https://foobar.com",
	}
	if err := dl.SetEventStatusRenderedStatus(id, rstat); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	s, err := dl.GetEventStatus(id)
	if err != nil {
		t.Fatalf("get should have succeeded: %v", err)
	}
	if rsd := s.Config.RenderedStatus.Description; rsd != rstat.Description {
		t.Fatalf("unexpected description: %v", rsd)
	}
	if rsl := s.Config.RenderedStatus.LinkTargetURL; rsl != rstat.LinkTargetURL {
		t.Fatalf("unexpected link: %v", rsl)
	}
}

func TestDataLayerCreateUISession(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id, err := dl.CreateUISession("/asdf", []byte("bar"), net.ParseIP("192.168.0.1"), "useragent", time.Now().UTC().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	uis, err := dl.GetUISession(id)
	if err != nil {
		t.Fatalf("error getting ui session: %v", err)
	}
	if uis.TargetRoute != "/asdf" {
		t.Fatalf("bad target route: %v", string(uis.TargetRoute))
	}
	if string(uis.State) != "bar" {
		t.Fatalf("bad state: %v", string(uis.State))
	}
	// expired
	if _, err := dl.CreateUISession("a", []byte("bar"), net.ParseIP("192.168.0.1"), "useragent", time.Now().UTC().Add(-10*time.Minute)); err == nil {
		t.Fatalf("should have failed because expired")
	}
	// missing params
	if _, err := dl.CreateUISession("", nil, net.ParseIP("192.168.0.1"), "useragent", time.Now().UTC().Add(10*time.Minute)); err == nil {
		t.Fatalf("should have failed with missing params")
	}
}

func TestDataLayerUpdateUISession(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id, err := dl.CreateUISession("/asdf", []byte("bar"), net.ParseIP("192.168.0.1"), "useragent", time.Now().UTC().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("create should have succeeded: %v", err)
	}
	if err := dl.UpdateUISession(id, "someuser", []byte(`asdf`), true); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	uis, err := dl.GetUISession(id)
	if err != nil {
		t.Fatalf("error getting ui session: %v", err)
	}
	if uis.GitHubUser != "someuser" {
		t.Fatalf("bad user: %v", uis.GitHubUser)
	}
	if !uis.Authenticated {
		t.Fatalf("should have been authenticated")
	}
	if string(uis.EncryptedUserToken) != "asdf" {
		t.Fatalf("bad encrypted token: %v", string(uis.EncryptedUserToken))
	}
}

func TestDataLayerDeleteUISession(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id, err := dl.CreateUISession("/asdf", []byte("bar"), net.ParseIP("192.168.0.1"), "useragent", time.Now().UTC().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("create should have succeeded: %v", err)
	}
	_, err = dl.GetUISession(id)
	if err != nil {
		t.Fatalf("error getting ui session: %v", err)
	}
	if err := dl.DeleteUISession(id); err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if uis, err := dl.GetUISession(id); err != nil || uis != nil {
		t.Fatalf("get should have succeeded and returned nil: %v: %+v", err, *uis)
	}
}

func TestDataLayerGetUISession(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id, err := dl.CreateUISession("/asdf", []byte("bar"), net.ParseIP("192.168.0.1"), "useragent", time.Now().UTC().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("create should have succeeded: %v", err)
	}
	uis, err := dl.GetUISession(id)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if uis.TargetRoute != "/asdf" {
		t.Fatalf("bad data: %v", uis.TargetRoute)
	}
	if string(uis.State) != "bar" {
		t.Fatalf("bad state: %v", string(uis.State))
	}
}

func TestDataLayerDeleteExpiredUISessions(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	id1, err := dl.CreateUISession("/asdf", []byte("bar"), net.ParseIP("192.168.0.1"), "useragent", time.Now().UTC().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("create 1 should have succeeded: %v", err)
	}
	id2, err := dl.CreateUISession("/asdf", []byte("bar"), net.ParseIP("192.168.0.1"), "useragent", time.Now().UTC().Add(1*time.Millisecond))
	if err != nil {
		t.Fatalf("create 2 should have succeeded: %v", err)
	}
	id3, err := dl.CreateUISession("/asdf", []byte("bar"), net.ParseIP("192.168.0.1"), "useragent", time.Now().UTC().Add(2*time.Millisecond))
	if err != nil {
		t.Fatalf("create 3 should have succeeded: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	n, err := dl.DeleteExpiredUISessions()
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	if n != 2 {
		t.Fatalf("unexpected deleted count: %v (wanted 2)", n)
	}
	if uis, err := dl.GetUISession(id1); err != nil || uis == nil {
		t.Fatalf("error getting ui session or missing session: %v: %v", err, uis)
	}
	if uis, err := dl.GetUISession(id2); err != nil || uis != nil {
		t.Fatalf("error getting ui session or session not deleted: %v: %+v", err, *uis)
	}
	if uis, err := dl.GetUISession(id3); err != nil || uis != nil {
		t.Fatalf("error getting ui session or session not deleted: %v: %+v", err, *uis)
	}
}

func TestDataLayerCreateAPIKey(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	ids := []uuid.UUID{}
	requests := []models.APIKey{
		{
			PermissionLevel: models.WritePermission,
			Name:            "foo write",
			Description:     "foo write description",
			GitHubUser:      "johnsmith",
		},
		{
			PermissionLevel: models.AdminPermission,
			Name:            "bar admin",
			Description:     "bar admin description",
			GitHubUser:      "jackhandy",
		},
		{
			PermissionLevel: models.ReadOnlyPermission,
			Name:            "foo read only",
			Description:     "foo read only description",
			GitHubUser:      "janejones",
		},
	}
	for _, r := range requests {
		id, err := dl.CreateAPIKey(context.Background(), r.PermissionLevel, r.Name, r.Description, r.GitHubUser)
		if err != nil {
			t.Fatalf("create api key should have succeeded: %v", err)
		}
		if id == uuid.Nil {
			t.Fatal("create api key should have returned the api key id")
		}
		ids = append(ids, id)

	}
	_, err := dl.GetAPIKeyById(context.Background(), ids[1])
	if err != nil {
		t.Fatalf("error getting created api key: %v", err)
	}
}

func TestGetAPIKeyById(t *testing.T) {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	requests := []models.APIKey{
		{
			ID:              uuid.MustParse("9df12e4e-08d6-11eb-adc1-0242ac120002"),
			PermissionLevel: models.AdminPermission,
			Name:            "my-repo-abc",
			Description:     "admin for my-repo-abc",
			GitHubUser:      "janejones",
		},
		{
			ID:              uuid.MustParse("a5f3f316-098e-11eb-adc1-0242ac120002"),
			PermissionLevel: models.WritePermission,
			Name:            "my-repo-abc",
			Description:     "write for my-repo-abc",
			GitHubUser:      "jackhandy",
		},
		{
			ID:              uuid.MustParse("6985dc36-08d6-11eb-adc1-0242ac120002"),
			PermissionLevel: models.ReadOnlyPermission,
			Name:            "my-repo-def",
			Description:     "read only for my-repo-def",
			GitHubUser:      "johnsmith",
		},
	}
	for _, r := range requests {
		apiKey, err := dl.GetAPIKeyById(context.Background(), r.ID)
		if err != nil {
			t.Fatalf("error getting api key: %v", err)
		}
		if apiKey == nil {
			t.Fatalf("expected api key returned")
		}
		if apiKey.PermissionLevel != r.PermissionLevel {
			t.Fatalf("unexpected Permissions Level: %v (wanted: %v)", apiKey.PermissionLevel, r.PermissionLevel)
		}
		if apiKey.Name != r.Name {
			t.Fatalf("unexpected name: %v (wanted: %v)", apiKey.Name, r.Name)
		}
		if apiKey.Description != r.Description {
			t.Fatalf("unexpected description: %v (wanted: %v)", apiKey.Description, r.Description)
		}
		if apiKey.GitHubUser != r.GitHubUser {
			t.Fatalf("unexpected github user: %v (wanted: %v)", apiKey.GitHubUser, r.GitHubUser)
		}
	}
}

func TestGetAPIKeysByGithubUser(t *testing.T)  {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	apiKeys, err := dl.GetAPIKeysByGithubUser(context.Background(), "janejones")
	if err != nil {
		t.Fatalf("error getting api keys for user: %v", err)
	}
	if apiKeys == nil {
		t.Fatalf("expected api keys returned")
	}
	if len(apiKeys) != 2 {
		t.Fatalf("unexpected total api keys for user: %v (wanted 2)", len(apiKeys))
	}
}

func TestUpdateAPIKeyLastUsed(t *testing.T)  {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	req := models.APIKey{
		PermissionLevel: models.ReadOnlyPermission,
		Name:            "foo read only",
		Description:     "foo read only description",
		GitHubUser:      "jimbob",
	}
	id, err := dl.CreateAPIKey(context.Background(), req.PermissionLevel, req.Name, req.Description, req.GitHubUser)
	if err != nil {
		t.Fatalf("create api key should have succeeded: %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("create api key should have returned the api key id")
	}
	apikey, err := dl.GetAPIKeyById(context.Background(), id)
	if err != nil {
		t.Fatalf("error getting api key: %v", err)
	}
	lu := apikey.LastUsed.Time
	time.Sleep(500 * time.Millisecond)
	err = dl.UpdateAPIKeyLastUsed(context.Background(), id)
	if err != nil {
		t.Fatalf("error updating api key: %v", err)
	}
	updated, err := dl.GetAPIKeyById(context.Background(), id)
	if err != nil {
		t.Fatalf("error getting api key: %v", err)
	}
	if  lu == updated.LastUsed.Time {
		t.Fatalf("expected last used to update; original: %v, updated: %v", lu, updated.LastUsed.Time)
	}
}

func TestDeleteAPIKey(t *testing.T)  {
	dl, tdl := NewTestDataLayer(t)
	if err := tdl.Setup(testDataPath); err != nil {
		t.Fatalf("error setting up test database: %v", err)
	}
	defer tdl.TearDown()
	ids := []uuid.UUID{}
	requests := []models.APIKey{
		{
			PermissionLevel: models.WritePermission,
			Name:            "foo write",
			Description:     "foo write description",
			GitHubUser:      "johnsmith",
		},
		{
			PermissionLevel: models.AdminPermission,
			Name:            "bar admin",
			Description:     "bar admin description",
			GitHubUser:      "jackhandy",
		},
		{
			PermissionLevel: models.ReadOnlyPermission,
			Name:            "foo read only",
			Description:     "foo read only description",
			GitHubUser:      "janejones",
		},
	}
	for _, r := range requests {
		id, err := dl.CreateAPIKey(context.Background(),r.PermissionLevel, r.Name, r.Description, r.GitHubUser)
		if err != nil {
			t.Fatalf("create api key should have succeeded: %v", err)
		}
		if id == uuid.Nil {
			t.Fatal("create api key should have returned the api key id")
		}
		ids = append(ids, id)

	}
	err := dl.DeleteAPIKey(context.Background(), ids[1])
	if err != nil {
		t.Fatalf("error getting created api key: %v", err)
	}
	apikey, _ := dl.GetAPIKeyById(context.Background(), ids[1])
	if apikey != nil {
		t.Fatalf("error api key was not deleted: %v", apikey)
	}
}
