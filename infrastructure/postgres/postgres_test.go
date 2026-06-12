package postgres

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestDSN(t *testing.T) {
	c := Config{Host: "lab-postgres", Port: "5432", User: "postgres", Password: "pw", DBName: "iam_db", SSLMode: "disable"}
	want := "host=lab-postgres port=5432 user=postgres password=pw dbname=iam_db sslmode=disable"
	if got := c.DSN(); got != want {
		t.Fatalf("DSN = %q, want %q", got, want)
	}
}

func TestDSN_DefaultsSSLMode(t *testing.T) {
	c := Config{Host: "h", Port: "5432", User: "u", Password: "p", DBName: "d"} // SSLMode empty
	if got := c.DSN(); !strings.Contains(got, "sslmode=disable") {
		t.Fatalf("DSN should default sslmode=disable, got %q", got)
	}
}

func TestWithDefaults(t *testing.T) {
	c := Config{}.withDefaults()
	if c.MaxOpenConns != DefaultMaxOpenConns || c.MaxIdleConns != DefaultMaxIdleConns || c.ConnMaxLifetime != DefaultConnMaxLifetime {
		t.Fatalf("defaults not applied: %+v", c)
	}
	// explicit values are preserved
	custom := Config{MaxOpenConns: 100, MaxIdleConns: 10, ConnMaxLifetime: time.Hour}.withDefaults()
	if custom.MaxOpenConns != 100 || custom.MaxIdleConns != 10 || custom.ConnMaxLifetime != time.Hour {
		t.Fatalf("explicit pool values overwritten: %+v", custom)
	}
}

func TestSaturated(t *testing.T) {
	base := sql.DBStats{MaxOpenConnections: 25, InUse: 3, WaitCount: 0}

	// no new waits, not at limit -> not saturated
	if hit, n := saturated(base, sql.DBStats{MaxOpenConnections: 25, InUse: 4, WaitCount: 0}); hit || n != 0 {
		t.Fatalf("expected not saturated, got hit=%v n=%d", hit, n)
	}
	// new waits accumulated -> saturated
	if hit, n := saturated(base, sql.DBStats{MaxOpenConnections: 25, InUse: 25, WaitCount: 7}); !hit || n != 7 {
		t.Fatalf("expected saturated with 7 new waits, got hit=%v n=%d", hit, n)
	}
	// fully in use at sample time, no new waits yet -> saturated
	if hit, _ := saturated(base, sql.DBStats{MaxOpenConnections: 25, InUse: 25, WaitCount: 0}); !hit {
		t.Fatalf("expected saturated when InUse == MaxOpenConnections")
	}
}

func TestConnect_PingFailureReturnsError(t *testing.T) {
	// Port 1 -> connection refused, Ping fails fast and Connect must return an error.
	_, err := Connect(Config{Host: "127.0.0.1", Port: "1", User: "x", Password: "x", DBName: "x"})
	if err == nil {
		t.Fatal("expected error connecting to a refused port, got nil")
	}
	if !strings.Contains(err.Error(), "postgres:") {
		t.Fatalf("error should be wrapped with postgres: prefix, got %v", err)
	}
}
