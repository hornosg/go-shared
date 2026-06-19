// Package migrate wraps golang-migrate to provide a single, idempotent
// migration entry-point for every Go service in the mercado-cercano fleet.
//
// See ADR-001 (libs/go-shared/docs/adr/ADR-001-migraciones-versionadas-golang-migrate.md)
// for the full rationale, naming conventions, and rollout plan.
package migrate

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// RunMigrations applies all pending migrations embedded in fsys against db,
// using the PostgreSQL advisory lock provided natively by golang-migrate's
// postgres driver (no extra setup required). It is safe to call from multiple
// service replicas concurrently: only one will run the migrations while the
// others wait and then observe ErrNoChange.
//
// Parameters:
//   - db     — an already-open, verified *sql.DB pool (reused as-is; no new
//     connection is opened).
//   - fsys   — an embed.FS that contains a "migrations" subdirectory with
//     files named NNNNNN_description.up.sql / NNNNNN_description.down.sql.
//   - dbName — name of the database; used only for logging and diagnostics.
//
// Behaviour:
//   - If all migrations are already applied (ErrNoChange), the function returns
//     nil — it is fully idempotent.
//   - If any migration fails, the error is returned wrapped with context so the
//     caller can abort the startup sequence (fail-fast pattern).
func RunMigrations(db *sql.DB, fsys embed.FS, dbName string) error {
	// Build the iofs source driver from the embedded filesystem.
	// golang-migrate expects the migration files to live inside a "migrations"
	// subdirectory of the provided FS, which matches the fleet convention
	// (//go:embed migrations/*.sql in the service's main package).
	src, err := iofs.New(fsys, "migrations")
	if err != nil {
		return fmt.Errorf("migrate: build iofs source for %q: %w", dbName, err)
	}

	// Build the postgres database driver reusing the existing connection pool.
	// postgres.WithInstance does NOT open a new connection: it wraps the *sql.DB
	// already held by the service. The advisory lock (pg_advisory_lock) is
	// managed automatically by the driver — no configuration needed.
	driver, err := postgres.WithInstance(db, &postgres.Config{
		DatabaseName: dbName,
	})
	if err != nil {
		return fmt.Errorf("migrate: build postgres driver for %q: %w", dbName, err)
	}

	// Assemble the migrator from the source and database drivers.
	m, err := migrate.NewWithInstance("iofs", src, dbName, driver)
	if err != nil {
		return fmt.Errorf("migrate: initialise migrator for %q: %w", dbName, err)
	}

	// Apply all pending migrations.
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			// No pending migrations: nothing to do. This is the steady-state on
			// every restart after the initial rollout.
			slog.Info("migrate: no pending migrations", "db", dbName)
			return nil
		}
		return fmt.Errorf("migrate: apply migrations for %q: %w", dbName, err)
	}

	slog.Info("migrate: migrations applied successfully", "db", dbName)
	return nil
}
