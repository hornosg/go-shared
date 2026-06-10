package port

import (
	"context"
	"database/sql"
)

// Executor abstracts a database transaction or connection.
// Both *sql.DB and *sql.Tx satisfy this interface, enabling the same
// repository code to run with or without an explicit transaction.
type Executor interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}
