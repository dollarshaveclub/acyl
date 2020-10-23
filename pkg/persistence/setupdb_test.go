package persistence

/*
Copypasta from testhelper/testdatalayer to avoid import cycle
*/

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/lib/pq/hstore"

	"github.com/DavidHuie/gomigrate"
	"github.com/dollarshaveclub/acyl/pkg/config"
	"github.com/dollarshaveclub/acyl/pkg/models"
	"github.com/pkg/errors"
)

type TestDataLayer struct {
	pgdb   *sqlx.DB
	logger *log.Logger
	t      *testing.T
	fdl    *FakeDataLayer // fake Datalayer
}

var testpostgresURI = "postgres://acyl:acyl@localhost:5432/acyl?sslmode=disable"

func NewTestDataLayer(t *testing.T) (DataLayer, *TestDataLayer) {
	return newTestPGDataLayer(t)
}

func newTestPGDataLayer(t *testing.T) (DataLayer, *TestDataLayer) {
	if dltype == "fake" {
		fdl := NewFakeDataLayer()
		return fdl, &TestDataLayer{
			logger: testlogger,
			t:      t,
			fdl:    fdl,
		}
	}
	pcfg := &config.PGConfig{PostgresURI: testpostgresURI}
	dl, err := NewPGLayer(pcfg, testlogger)
	if err != nil {
		t.Fatalf("error getting PG datalayer: %v", err)
	}
	return dl, &TestDataLayer{
		logger: testlogger,
		t:      t,
		pgdb:   dl.db,
	}
}

func (tdl *TestDataLayer) createTables() error {
	if dltype == "fake" {
		return nil
	}
	return tdl.createPGTables()
}

func (tdl *TestDataLayer) createPGTables() error {
	if envURI := os.Getenv("ACYL_POSTGRES_URI"); envURI != "" {
		testpostgresURI = envURI
	}
	db, err := sqlx.Open("postgres", testpostgresURI)
	if err != nil {
		return errors.Wrap(err, "error creating postgres connection")
	}
	defer db.Close()
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	migrator, err := gomigrate.NewMigratorWithLogger(db.DB, gomigrate.Postgres{}, "./migrations", logger)
	if err != nil {
		return errors.Wrap(err, "error creating migrator")
	}
	if err := migrator.Migrate(); err != nil {
		return errors.Wrap(err, "error applying migration")
	}
	return nil
}

func (tdl *TestDataLayer) setTimestamps(qas []models.QAEnvironment) {
	now := time.Now().UTC()
	settimes := func(qa *models.QAEnvironment, basetime time.Time) {
		qa.Created = basetime
		qa.Events[0].Timestamp = basetime
		qa.Events[1].Timestamp = basetime.Add(1 * time.Minute)
	}
	for i := range qas {
		settimes(&qas[i], now.AddDate(0, 0, -i))
	}
}

func (tdl *TestDataLayer) insertFake(qae *models.QAEnvironment) error {
	tdl.fdl.data.Lock()
	tdl.fdl.data.d[qae.Name] = qae
	tdl.fdl.data.Unlock()
	return nil
}

func (tdl *TestDataLayer) insertPG(qae *models.QAEnvironment) error {
	q := `INSERT INTO qa_environments
	(name, created, raw_events, hostname, qa_type, username, repo, pull_request, source_sha, base_sha, source_branch, base_branch, source_ref, status, ref_map, commit_sha_map, amino_service_to_port, amino_kubernetes_namespace, amino_environment_id, event_ids)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20);`

	crm2hstore := func(m models.RefMap) hstore.Hstore {
		out := hstore.Hstore{Map: make(map[string]sql.NullString)}
		for k, v := range m {
			out.Map[k] = sql.NullString{String: v, Valid: true}
		}
		return out
	}

	casp2hstore := func(m map[string]int64) hstore.Hstore {
		out := hstore.Hstore{Map: make(map[string]sql.NullString)}
		for k, v := range m {
			out.Map[k] = sql.NullString{String: strconv.Itoa(int(v)), Valid: true}
		}
		return out
	}

	args := []interface{}{qae.Name, qae.Created, pq.StringArray(qae.RawEvents), qae.Hostname, qae.QAType, qae.User, qae.Repo, qae.PullRequest, qae.SourceSHA, qae.BaseSHA, qae.SourceBranch, qae.BaseBranch, qae.SourceRef, qae.Status, crm2hstore(qae.RefMap), crm2hstore(qae.CommitSHAMap), casp2hstore(qae.AminoServiceToPort), qae.AminoKubernetesNamespace, qae.AminoEnvironmentID, pq.Array(qae.EventIDs)}
	if _, err := tdl.pgdb.Exec(q, args...); err != nil {
		return errors.Wrapf(err, "error inserting QAEnvironment into database: %v", qae.Name)
	}
	return nil
}

func (tdl *TestDataLayer) insertHelm(r models.HelmRelease) error {
	r.Created = time.Now().UTC()
	if dltype == "fake" {
		tdl.fdl.data.Lock()
		if len(tdl.fdl.data.helm[r.EnvName]) == 0 {
			tdl.fdl.data.helm[r.EnvName] = []models.HelmRelease{}
		}
		tdl.fdl.data.helm[r.EnvName] = append(tdl.fdl.data.helm[r.EnvName], r)
		tdl.fdl.data.Unlock()
		return nil
	}
	q := `INSERT INTO helm_releases (` + r.InsertColumns() + `) VALUES (` + r.InsertParams() + `);`
	if _, err := tdl.pgdb.Exec(q, r.InsertValues()...); err != nil {
		return errors.Wrap(err, "error inserting helm release")
	}
	return nil
}

func (tdl *TestDataLayer) insertK8sEnvs(e models.KubernetesEnvironment) error {
	e.Created = time.Now().UTC()
	e.Updated = pq.NullTime{Time: time.Now().UTC(), Valid: true}
	if dltype == "fake" {
		tdl.fdl.data.Lock()
		tdl.fdl.data.k8s[e.EnvName] = &e
		tdl.fdl.data.Unlock()
		return nil
	}
	q := `INSERT INTO kubernetes_environments (` + e.InsertColumns() + `) VALUES (` + e.InsertParams() + `);`
	if _, err := tdl.pgdb.Exec(q, e.InsertValues()...); err != nil {
		return errors.Wrap(err, "error inserting k8s env")
	}
	return nil
}

func (tdl *TestDataLayer) insertEventLog(el models.EventLog) error {
	el.Created = time.Now().UTC()
	el.Updated = pq.NullTime{Time: time.Now().UTC(), Valid: true}
	if dltype == "fake" {
		tdl.fdl.data.Lock()
		tdl.fdl.data.elogs[el.ID] = &el
		tdl.fdl.data.Unlock()
		return nil
	}
	q := `INSERT INTO event_logs (` + el.InsertColumns() + `) VALUES (` + el.InsertParams() + `);`
	if _, err := tdl.pgdb.Exec(q, el.InsertValues()...); err != nil {
		return errors.Wrap(err, "error inserting event log")
	}
	q = `UPDATE event_logs SET status = $1 WHERE id = $2;`
	if _, err := tdl.pgdb.Exec(q, el.Status, el.ID); err != nil {
		return errors.Wrap(err, "error setting event log status")
	}
	return nil
}

func (tdl *TestDataLayer) insertAPIKeys(key models.APIKey) error {
	if dltype == "fake" {
		tdl.fdl.data.Lock()
		tdl.fdl.data.apikeys[key.ID] = &key
		tdl.fdl.data.Unlock()
		return nil
	}
	q := `INSERT INTO api_keys (` + key.InsertColumns() + `) VALUES (` + key.InsertParams() + `);`
	if _, err := tdl.pgdb.Exec(q, key.InsertValues()...); err != nil {
		return errors.Wrap(err, "error inserting api keys")
	}
	return nil
}

func (tdl *TestDataLayer) insert(qa *models.QAEnvironment) error {
	if dltype == "fake" {
		return tdl.insertFake(qa)
	}
	return tdl.insertPG(qa)
}

func readTestHelmData(path string) ([]models.HelmRelease, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening test db file: %v", err)
	}
	defer f.Close()
	data := []models.HelmRelease{}
	d := json.NewDecoder(f)
	err = d.Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling test data: %v", err)
	}
	return data, nil
}

func readTestK8sEnvData(path string) ([]models.KubernetesEnvironment, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening test db file: %v", err)
	}
	defer f.Close()
	data := []models.KubernetesEnvironment{}
	d := json.NewDecoder(f)
	err = d.Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling test data: %v", err)
	}
	return data, nil
}

func readTestEventLogData(path string) ([]models.EventLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening test event log file: %v", err)
	}
	defer f.Close()
	data := []models.EventLog{}
	d := json.NewDecoder(f)
	err = d.Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling test event log data: %v", err)
	}
	return data, nil
}

func readTestAPIKeysData(path string) ([]models.APIKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening test api key file: %v", err)
	}
	defer f.Close()
	data := []models.APIKey{}
	d := json.NewDecoder(f)
	err = d.Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling test api key data: %v", err)
	}
	return data, nil
}

func (tdl *TestDataLayer) CreateTables() error {
	return tdl.createTables()
}

func (tdl *TestDataLayer) Setup(path string) error {
	tdl.t.Helper()
	err := tdl.createTables()
	if err != nil {
		return fmt.Errorf("error creating test tables/indices: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("error opening test db file: %v", err)
	}
	defer f.Close()
	data := []models.QAEnvironment{}
	d := json.NewDecoder(f)
	err = d.Decode(&data)
	if err != nil {
		return fmt.Errorf("error unmarshaling test data: %v", err)
	}
	tdl.setTimestamps(data)
	for _, qa := range data {
		qa := qa
		qa.CreatedDate = qa.Created.Format("2006-01-02") // YYYY-MM-DD
		if err := qa.SetRaw(); err != nil {
			return fmt.Errorf("error setting raw fields: %v", err)
		}
		if err := tdl.insert(&qa); err != nil {
			return errors.Wrap(err, "error inserting qa")
		}
	}
	helm, err := readTestHelmData("testdata/helm.json")
	if err != nil {
		return errors.Wrap(err, "error reading helm data")
	}
	for _, r := range helm {
		if err := tdl.insertHelm(r); err != nil {
			return errors.Wrap(err, "error inserting helm release")
		}
	}
	k8senvs, err := readTestK8sEnvData("testdata/k8s_envs.json")
	if err != nil {
		return errors.Wrap(err, "error reading k8s env data")
	}
	for _, e := range k8senvs {
		if err := tdl.insertK8sEnvs(e); err != nil {
			return errors.Wrap(err, "error inserting k8s env")
		}
	}
	elogs, err := readTestEventLogData("testdata/event_logs.json")
	if err != nil {
		return errors.Wrap(err, "error reading event log data")
	}
	for _, el := range elogs {
		if err := tdl.insertEventLog(el); err != nil {
			return errors.Wrap(err, "error inserting event log")
		}
	}
	apikeys, err := readTestAPIKeysData("testdata/api_keys.json")
	if err != nil {
		return errors.Wrap(err, "error reading api key data")
	}
	for _, key := range apikeys {
		if err := tdl.insertAPIKeys(key); err != nil {
			return errors.Wrap(err, "error inserting api key")
		}
	}
	return nil
}

func (tdl *TestDataLayer) tearDownPG() error {
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	migrator, err := gomigrate.NewMigratorWithLogger(tdl.pgdb.DB, gomigrate.Postgres{}, "./migrations", logger)
	if err != nil {
		return errors.Wrap(err, "error creating migrator")
	}
	if err := migrator.RollbackAll(); err != nil {
		return errors.Wrap(err, "error rolling back migrations")
	}
	return tdl.pgdb.Close()
}

func (tdl *TestDataLayer) TearDown() error {
	tdl.t.Helper()
	if dltype == "fake" {
		tdl.fdl = NewFakeDataLayer()
		return nil
	}
	return tdl.tearDownPG()
}
