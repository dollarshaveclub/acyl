package cmd

import (
	"log"
	"os"

	"github.com/DavidHuie/gomigrate"
	"github.com/dollarshaveclub/acyl/pkg/config"
	"github.com/dollarshaveclub/acyl/pkg/secrets"
	"github.com/spf13/cobra"

	"database/sql"

	_ "github.com/lib/pq"
)

var pgMigrateCmd = &cobra.Command{
	Use:   "pg-migrate",
	Short: "run Postgres migrations",
	Run:   pgMigrate,
}

var migrationsPGConfig config.PGConfig
var pgURIFromVault bool

func init() {
	pgMigrateCmd.PersistentFlags().StringVar(
		&migrationsPGConfig.PostgresURI, "postgres-uri",
		"postgresql://acyl:acyl@localhost:5432?sslmode=disable",
		"the address to the Postgres database",
	)
	pgMigrateCmd.PersistentFlags().StringVar(
		&migrationsPGConfig.PostgresMigrationsPath, "postgres-migrations-dir",
		"migrations",
		"the path to the Postgres migrations directory",
	)
	pgMigrateCmd.PersistentFlags().BoolVar(&pgURIFromVault, "db-uri-from-vault", false, "retrieve the Postgres URI from Vault")
	RootCmd.AddCommand(pgMigrateCmd)
}

func pgMigrate(cmd *cobra.Command, args []string) {
	logger := log.New(os.Stdout, "", log.LstdFlags)

	if pgURIFromVault {
		err := secrets.PopulatePG(secretsBackend, &secretsConfig, &vaultConfig, &pgConfig)
		if err != nil {
			logger.Fatalf("error populating Postgres Migrations Config: %v", err)
		}
	}

	db, err := sql.Open("postgres", migrationsPGConfig.PostgresURI)
	if err != nil {
		logger.Fatalf("error creating postgres connection: %s", err)
	}

	migrator, err := gomigrate.NewMigrator(db, gomigrate.Postgres{},
		migrationsPGConfig.PostgresMigrationsPath)
	if err != nil {
		logger.Fatalf("error creating migrator: %s", err)
	}

	if err := migrator.Migrate(); err != nil {
		logger.Fatalf("error applying migration: %s", err)
	}
}
