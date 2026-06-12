// Package postgres centralizes the Postgres connection "dance" that every
// service in the mercado-cercano ecosystem repeats by hand: build a DSN from
// config, sql.Open the lib/pq driver, tune the pool and Ping. It ships sane
// pool defaults (most services ran with NO connection limit) and an optional
// saturation monitor that logs, with the owning service and a timestamp, when
// the pool limit is actually being hit.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/lib/pq" // registers the "postgres" driver
)

// Pool defaults applied when a Config leaves the field at its zero value.
const (
	DefaultMaxOpenConns    = 25
	DefaultMaxIdleConns    = 5
	DefaultConnMaxLifetime = 5 * time.Minute
)

// Config describes a Postgres connection. The pool fields are optional; zero
// values fall back to the Default* constants.
type Config struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string // defaults to "disable" if empty

	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// DSN builds the lib/pq keyword DSN. lib/pq parses this and the URL form
// identically, so this is the canonical shape for the ecosystem.
func (c Config) DSN() string {
	sslmode := c.SSLMode
	if sslmode == "" {
		sslmode = "disable"
	}
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, sslmode)
}

func (c Config) withDefaults() Config {
	if c.MaxOpenConns == 0 {
		c.MaxOpenConns = DefaultMaxOpenConns
	}
	if c.MaxIdleConns == 0 {
		c.MaxIdleConns = DefaultMaxIdleConns
	}
	if c.ConnMaxLifetime == 0 {
		c.ConnMaxLifetime = DefaultConnMaxLifetime
	}
	return c
}

// Connect opens a Postgres pool with sane defaults applied and verifies it
// with Ping. On Ping failure the pool is closed and the error returned.
func Connect(c Config) (*sql.DB, error) {
	c = c.withDefaults()
	db, err := sql.Open("postgres", c.DSN())
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	db.SetMaxOpenConns(c.MaxOpenConns)
	db.SetMaxIdleConns(c.MaxIdleConns)
	db.SetConnMaxLifetime(c.ConnMaxLifetime)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return db, nil
}

// MonitorOptions configures StartPoolMonitor.
type MonitorOptions struct {
	Service  string        // who owns the pool, e.g. "iam-service" — appears in every log line
	DBName   string        // which database, e.g. "iam_db"
	Interval time.Duration // sampling interval; defaults to 30s
	Logger   *slog.Logger  // defaults to slog.Default()
}

// StartPoolMonitor launches a goroutine that samples db.Stats() every Interval
// and logs a WARN line whenever the pool is saturated — i.e. goroutines had to
// WAIT for a connection because MaxOpenConns was reached, or the pool is fully
// in use at sample time. Each line carries the service and db (the "who") and
// slog's timestamp (the "when"), so it is greppable in Loki/Grafana. The
// goroutine stops when ctx is cancelled.
func StartPoolMonitor(ctx context.Context, db *sql.DB, opts MonitorOptions) {
	if opts.Interval <= 0 {
		opts.Interval = 30 * time.Second
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	go func() {
		ticker := time.NewTicker(opts.Interval)
		defer ticker.Stop()
		prev := db.Stats()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cur := db.Stats()
				if hit, newWaits := saturated(prev, cur); hit {
					logger.Warn("db pool limit reached: goroutines waited for a connection",
						"service", opts.Service,
						"db", opts.DBName,
						"max_open_conns", cur.MaxOpenConnections,
						"in_use", cur.InUse,
						"idle", cur.Idle,
						"new_waits", newWaits,
						"wait_count_total", cur.WaitCount,
						"wait_duration_total", cur.WaitDuration.String(),
					)
				}
				prev = cur
			}
		}
	}()
}

// saturated reports whether the pool hit its limit between prev and cur:
// either new waits accumulated (goroutines blocked on MaxOpenConns) or the
// pool is fully in use right now. Returns the number of new waits. Pure, so it
// is unit-testable without a live database.
func saturated(prev, cur sql.DBStats) (bool, int64) {
	newWaits := cur.WaitCount - prev.WaitCount
	atLimit := cur.MaxOpenConnections > 0 && cur.InUse >= cur.MaxOpenConnections
	return newWaits > 0 || atLimit, newWaits
}
