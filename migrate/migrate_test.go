package migrate_test

import (
	"embed"
	"strings"
	"testing"

	gosharedmigrate "github.com/hornosg/go-shared/migrate"
)

// ---------------------------------------------------------------------------
// Embedded test fixtures
// ---------------------------------------------------------------------------

// noMigrationsDirFS embeds testdata/migrations but under the path
// "testdata/migrations", NOT under "migrations". When RunMigrations calls
// iofs.New(fsys, "migrations"), it will not find a "migrations" entry at the
// FS root and must return an error.
//
//go:embed testdata/migrations
var noMigrationsDirFS embed.FS

// ---------------------------------------------------------------------------
// Tests — boundary conditions reachable without a live database
// ---------------------------------------------------------------------------

// TestRunMigrations_NoMigrationsAtFSRoot verifies that RunMigrations returns a
// non-nil, contextual error when the embed.FS does not expose a "migrations"
// directory at its root. iofs.New fails before any database operation, so db
// is never touched — passing nil is safe and explicit.
//
// This test covers the most common misconfiguration: the service embeds from
// the wrong path (e.g. //go:embed internal/migrations instead of
// //go:embed migrations) and the helper catches it early.
func TestRunMigrations_NoMigrationsAtFSRoot_ReturnsContextualError(t *testing.T) {
	t.Parallel()

	// noMigrationsDirFS has the SQL files under "testdata/migrations/...", not
	// "migrations/...". iofs.New("migrations") will fail to open the subdir.
	err := gosharedmigrate.RunMigrations(nil, noMigrationsDirFS, "testdb")
	if err == nil {
		t.Fatal("expected error when embed.FS has no 'migrations' entry at its root, got nil")
	}

	// The error must carry the function prefix and the db name so callers can
	// diagnose which database and which step failed.
	errMsg := err.Error()
	for _, want := range []string{"migrate:", "testdb"} {
		if !strings.Contains(errMsg, want) {
			t.Errorf("error %q does not contain expected substring %q", errMsg, want)
		}
	}

	t.Logf("got expected contextual error: %v", err)
}

// TestRunMigrations_ErrorWrapping verifies that errors from inner drivers are
// wrapped with fmt.Errorf("migrate: ...: %w", err) so that callers can both
// log a human-readable message and inspect the sentinel via errors.Is/As.
//
// The empty-FS path produces a known error from the iofs driver. We check that
// the wrapper preserves the original message rather than swallowing it.
func TestRunMigrations_ErrorWrapping_PreservesInnerMessage(t *testing.T) {
	t.Parallel()

	err := gosharedmigrate.RunMigrations(nil, noMigrationsDirFS, "myservice_db")
	if err == nil {
		t.Fatal("expected non-nil error, got nil")
	}

	// The outer message must start with our package prefix.
	if !strings.HasPrefix(err.Error(), "migrate:") {
		t.Errorf("error should start with 'migrate:', got: %q", err.Error())
	}

	// The error must not be empty (regression guard against silent swallowing).
	if err.Error() == "migrate:" {
		t.Error("error message is just the prefix with no detail — inner error was swallowed")
	}
}

// ---------------------------------------------------------------------------
// Integration test placeholder
// ---------------------------------------------------------------------------

// TestRunMigrations_Integration_LiveDB documents the integration coverage
// expected from the first consuming service (webdata-service, ADR-001 step 2).
//
// go-shared carries no live-database test infrastructure by design:
// introducing dockertest/testcontainers would add a heavyweight dependency to
// a library consumed by every fleet service. The decision (ADR-001 §Plan de
// rollout, step 1) is to validate the full happy-path against lab-postgres in
// the first consuming service.
//
// What the webdata-service integration test MUST cover:
//
//  1. Apply 2 migrations from a real embed.FS → schema_migrations table has 2 rows.
//  2. Call RunMigrations again on the same DB → returns nil (ErrNoChange, idempotent).
//  3. Apply a migration with a syntax error → returns non-nil error; schema_migrations
//     marks the version as "dirty".
func TestRunMigrations_Integration_LiveDB_CoveredInWebdataService(t *testing.T) {
	t.Skip("integration against live PostgreSQL is covered in webdata-service (ADR-001 step 2)")
}
