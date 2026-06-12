// Package env provides small helpers to read environment variables with a
// fallback, centralizing the getEnv(key, default) pattern that every service in
// the mercado-cercano ecosystem was redefining. All getters are lenient: if the
// variable is unset or empty (or set but unparseable for the typed getters),
// the fallback is returned instead of erroring — the behavior config loaders
// across the ecosystem already rely on.
package env

import (
	"os"
	"strconv"
	"time"
)

// Get returns the value of the env var key, or fallback if it is unset or empty.
func Get(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// GetInt returns key parsed as int, or fallback if unset/empty/unparseable.
func GetInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// GetBool returns key parsed as bool (1/0, t/f, true/false), or fallback if
// unset/empty/unparseable.
func GetBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// GetDuration returns key parsed as a time.Duration (e.g. "30s", "5m"), or
// fallback if unset/empty/unparseable.
func GetDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
