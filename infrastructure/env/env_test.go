package env

import (
	"testing"
	"time"
)

func TestGet(t *testing.T) {
	t.Setenv("MC_TEST_STR", "value")
	if got := Get("MC_TEST_STR", "fb"); got != "value" {
		t.Fatalf("Get set = %q, want value", got)
	}
	if got := Get("MC_TEST_MISSING", "fb"); got != "fb" {
		t.Fatalf("Get missing = %q, want fb", got)
	}
	t.Setenv("MC_TEST_EMPTY", "")
	if got := Get("MC_TEST_EMPTY", "fb"); got != "fb" {
		t.Fatalf("Get empty = %q, want fb (empty falls back)", got)
	}
}

func TestGetInt(t *testing.T) {
	t.Setenv("MC_TEST_INT", "42")
	if got := GetInt("MC_TEST_INT", 7); got != 42 {
		t.Fatalf("GetInt = %d, want 42", got)
	}
	if got := GetInt("MC_TEST_INT_MISSING", 7); got != 7 {
		t.Fatalf("GetInt missing = %d, want 7", got)
	}
	t.Setenv("MC_TEST_INT_BAD", "notanint")
	if got := GetInt("MC_TEST_INT_BAD", 7); got != 7 {
		t.Fatalf("GetInt unparseable = %d, want fallback 7", got)
	}
}

func TestGetBool(t *testing.T) {
	t.Setenv("MC_TEST_BOOL", "true")
	if got := GetBool("MC_TEST_BOOL", false); !got {
		t.Fatalf("GetBool true = %v, want true", got)
	}
	t.Setenv("MC_TEST_BOOL_NUM", "0")
	if got := GetBool("MC_TEST_BOOL_NUM", true); got {
		t.Fatalf("GetBool 0 = %v, want false", got)
	}
	if got := GetBool("MC_TEST_BOOL_MISSING", true); !got {
		t.Fatalf("GetBool missing = %v, want fallback true", got)
	}
	t.Setenv("MC_TEST_BOOL_BAD", "maybe")
	if got := GetBool("MC_TEST_BOOL_BAD", true); !got {
		t.Fatalf("GetBool unparseable = %v, want fallback true", got)
	}
}

func TestGetDuration(t *testing.T) {
	t.Setenv("MC_TEST_DUR", "30s")
	if got := GetDuration("MC_TEST_DUR", time.Minute); got != 30*time.Second {
		t.Fatalf("GetDuration = %v, want 30s", got)
	}
	if got := GetDuration("MC_TEST_DUR_MISSING", time.Minute); got != time.Minute {
		t.Fatalf("GetDuration missing = %v, want 1m", got)
	}
	t.Setenv("MC_TEST_DUR_BAD", "nope")
	if got := GetDuration("MC_TEST_DUR_BAD", time.Minute); got != time.Minute {
		t.Fatalf("GetDuration unparseable = %v, want fallback 1m", got)
	}
}
