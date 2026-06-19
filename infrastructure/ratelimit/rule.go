// Package ratelimit implementa el motor de rate limiting por tenant/plan del ecosistema
// (ADR-003). Aísla la dependencia de Redis del resto de go-shared: solo los servicios que
// hacen rate limiting importan este paquete (condición de arquitectura A6).
package ratelimit

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Algorithm selecciona la estrategia por celda (plan × feature), ADR-003 D5.
type Algorithm string

const (
	// AlgoSlidingWindow: preciso, rechaza al exceder (AI/infra, billing-accurate).
	AlgoSlidingWindow Algorithm = "sliding_window_counter"
	// AlgoGCRA: leaky-bucket-as-meter, ritmo constante sin cola real (FREE). Devuelve
	// 429 + Retry-After SIN retener la conexión (condición A5).
	AlgoGCRA Algorithm = "gcra"
)

// RawRule es la forma JSON tal cual viene de iam (columna plans.rate_limits, ADR-003 D4).
// El servicio deserializa el JSON del plan a esta struct y la normaliza con Parse.
type RawRule struct {
	Algorithm string `json:"algorithm"`
	Limit     int    `json:"limit,omitempty"`  // sliding_window_counter
	Window    string `json:"window,omitempty"` // sliding_window_counter ("1s","1m","1h")
	Rate      string `json:"rate,omitempty"`   // gcra ("10/s")
	Burst     int    `json:"burst,omitempty"`  // gcra
}

// Rule es la regla normalizada que consume el Limiter. Ambos algoritmos se expresan como
// "Limit eventos por Window"; GCRA además usa Burst (tolerancia de ráfaga).
type Rule struct {
	Algorithm Algorithm
	Limit     int
	Window    time.Duration
	Burst     int
}

// Parse normaliza una RawRule. Para gcra convierte Rate "10/s" → Limit=10, Window=1s.
func Parse(raw RawRule) (Rule, error) {
	switch Algorithm(raw.Algorithm) {
	case AlgoSlidingWindow:
		if raw.Limit <= 0 {
			return Rule{}, fmt.Errorf("sliding_window_counter requiere limit > 0")
		}
		win, err := time.ParseDuration(raw.Window)
		if err != nil || win <= 0 {
			return Rule{}, fmt.Errorf("window inválida %q: %w", raw.Window, err)
		}
		return Rule{Algorithm: AlgoSlidingWindow, Limit: raw.Limit, Window: win}, nil

	case AlgoGCRA:
		limit, win, err := parseRate(raw.Rate)
		if err != nil {
			return Rule{}, err
		}
		burst := raw.Burst
		if burst < 0 {
			burst = 0
		}
		return Rule{Algorithm: AlgoGCRA, Limit: limit, Window: win, Burst: burst}, nil

	default:
		return Rule{}, fmt.Errorf("algoritmo desconocido %q", raw.Algorithm)
	}
}

// parseRate parsea "10/s" → (10, 1s). Unidades: s, m, h.
func parseRate(rate string) (int, time.Duration, error) {
	parts := strings.SplitN(rate, "/", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("rate inválido %q (esperado N/unidad, ej. 10/s)", rate)
	}
	n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || n <= 0 {
		return 0, 0, fmt.Errorf("rate inválido %q: numerador", rate)
	}
	unit := strings.TrimSpace(parts[1])
	if unit == "" {
		unit = "s"
	}
	win, err := time.ParseDuration("1" + unit)
	if err != nil || win <= 0 {
		return 0, 0, fmt.Errorf("rate inválido %q: unidad", rate)
	}
	return n, win, nil
}

// emissionInterval es el intervalo entre emisiones para GCRA (Window / Limit).
func (r Rule) emissionInterval() time.Duration {
	if r.Limit <= 0 {
		return r.Window
	}
	return r.Window / time.Duration(r.Limit)
}
