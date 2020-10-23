package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type APIKey struct {
	ID              uuid.UUID       `json:"id"`
	Created         time.Time       `json:"created"`
	LastUsed        pq.NullTime     `json:"last_used"`
	PermissionLevel PermissionLevel `json:"permission_level"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	GitHubUser      string          `json:"github_user"`
}

func (apik APIKey) Columns() string {
	return strings.Join([]string{"id", "created", "last_used", "permission_level", "name", "description", "github_user"}, ",")
}

func (apik APIKey) InsertColumns() string {
	return strings.Join([]string{"id", "created", "last_used", "permission_level", "name", "description", "github_user"}, ",")
}

func (apik *APIKey) ScanValues() []interface{} {
	return []interface{}{&apik.ID, &apik.Created, &apik.LastUsed, &apik.PermissionLevel, &apik.Name, &apik.Description, &apik.GitHubUser}
}

func (apik *APIKey) InsertValues() []interface{} {
	return []interface{}{&apik.ID, &apik.Created, &apik.LastUsed, &apik.PermissionLevel, &apik.Name, &apik.Description, &apik.GitHubUser}
}

func (apik APIKey) InsertParams() string {
	params := []string{}
	for i := range strings.Split(apik.InsertColumns(), ",") {
		params = append(params, fmt.Sprintf("$%v", i+1))
	}
	return strings.Join(params, ", ")
}

//go:generate stringer -type=PermissionLevel

type PermissionLevel int

const (
	UnknownPermission PermissionLevel = iota
	ReadOnlyPermission
	WritePermission
	AdminPermission
)
