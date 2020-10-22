package persistence

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pkg/errors"

	"github.com/dollarshaveclub/acyl/pkg/models"
)

// CreateAPIKey creates a new api key for a user from the ID model
func (pg *PGLayer) CreateAPIKey(ctx context.Context, permissionLevel models.PermissionLevel, name, description, githubUser string) (uuid.UUID, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return uuid.Nil, errors.Wrap(err, "error creating new random uuid")
	}
	in := &models.APIKey{
		ID:              id,
		Created:         time.Now().UTC(),
		LastUsed:        pq.NullTime{Time: time.Now().UTC(), Valid: true},
		PermissionLevel: permissionLevel,
		Name:            name,
		Description:     description,
		GitHubUser:      githubUser,
	}
	q := `INSERT INTO api_keys (` + in.InsertColumns() + `) VALUES (` + in.InsertParams() + `);`
	if _, err := pg.db.ExecContext(ctx, q, in.InsertValues()...); err != nil {
		return uuid.Nil, errors.Wrap(err, "error inserting api key")
	}
	return id, nil
}

// GetAPIKeyById returns the api key object by api key id, nil if not found
func (pg *PGLayer) GetAPIKeyById(ctx context.Context, id uuid.UUID) (*models.APIKey, error) {
	out := &models.APIKey{}
	q := `SELECT ` + out.Columns() + ` FROM api_keys WHERE id = $1;`
	if err := pg.db.QueryRow(q, id).Scan(out.ScanValues()...); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, errors.Wrap(err, "error getting api key")
	}
	return out, nil
}

// GetAPIKeysByGithubUser returns the api key for the name and github user or nil if not found
func (pg *PGLayer) GetAPIKeysByGithubUser(ctx context.Context, githubUser string) ([]*models.APIKey, error) {
	var out []*models.APIKey
	q := `SELECT ` + models.APIKey{}.Columns() + ` FROM api_keys WHERE github_user = $1;`
	rows, err := pg.db.QueryContext(ctx,q, githubUser)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "error querying")
	}
	defer rows.Close()
	for rows.Next() {
		key := models.APIKey{}
		if err := rows.Scan(key.ScanValues()...); err != nil {
			return nil, errors.Wrap(err, "error scanning row")
		}
		out = append(out, &key)
	}
	return out, nil
}

// UpdateAPIKeyLastUsed updates the last used field for the api key id
func (pg *PGLayer) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	q := `UPDATE api_keys SET last_used = $1 WHERE id = $2;`
	_, err := pg.db.ExecContext(ctx, q, pq.NullTime{Time: time.Now().UTC(), Valid: true}, id)
	if err != nil {
		return errors.Wrap(err, "error updating api key")
	}
	return nil
}

// DeleteAPIKey unconditionally deletes the api key for the api key id
func (pg *PGLayer) DeleteAPIKey(ctx context.Context, id uuid.UUID) error {
	q := `DELETE FROM api_keys WHERE id = $1;`
	_, err := pg.db.ExecContext(ctx, q, id)
	if err != nil {
		return errors.Wrap(err, "error deleting api key")
	}
	return nil
}
