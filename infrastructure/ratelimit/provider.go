package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Matrix es la matriz de límites: tier → feature → Rule (ADR-003 D4).
type Matrix map[string]map[string]Rule

// FetchFunc obtiene la matriz vigente desde la fuente de verdad (típicamente el endpoint
// de planes de iam). La implementa cada servicio (go-shared no se acopla al contrato HTTP).
type FetchFunc func(ctx context.Context) (Matrix, error)

// RefreshingProvider implementa middleware.LimitsProvider cacheando la matriz con un TTL.
// Refresco LAZY con single-flight: la primera request tras vencer el TTL dispara el fetch;
// si el fetch falla, se sirve la matriz anterior (resiliencia — no perder límites por un
// iam caído). No usa goroutines de fondo (sin lifecycle que gestionar).
type RefreshingProvider struct {
	fetch FetchFunc
	ttl   time.Duration

	mu        sync.RWMutex
	matrix    Matrix
	fetchedAt time.Time
	refreshMu sync.Mutex // serializa refrescos concurrentes
}

// NewRefreshingProvider crea el provider y hace un primer fetch best-effort (si falla,
// arranca con matriz vacía → no se limita hasta que un refresh tenga éxito).
func NewRefreshingProvider(ctx context.Context, fetch FetchFunc, ttl time.Duration) *RefreshingProvider {
	p := &RefreshingProvider{fetch: fetch, ttl: ttl, matrix: Matrix{}}
	p.refresh(ctx)
	return p
}

// RuleFor devuelve la regla de la celda (tier, feature). ok=false si no hay límite
// configurado (el middleware no limita esa celda).
func (p *RefreshingProvider) RuleFor(tier, feature string) (Rule, bool) {
	p.maybeRefresh()
	p.mu.RLock()
	defer p.mu.RUnlock()
	byFeature, ok := p.matrix[tier]
	if !ok {
		return Rule{}, false
	}
	r, ok := byFeature[feature]
	return r, ok
}

func (p *RefreshingProvider) maybeRefresh() {
	p.mu.RLock()
	stale := time.Since(p.fetchedAt) >= p.ttl
	p.mu.RUnlock()
	if stale {
		p.refresh(context.Background())
	}
}

func (p *RefreshingProvider) refresh(ctx context.Context) {
	// Single-flight: si otro goroutine ya está refrescando, no duplicar.
	if !p.refreshMu.TryLock() {
		return
	}
	defer p.refreshMu.Unlock()

	m, err := p.fetch(ctx)
	if err != nil || m == nil {
		// Mantener la matriz anterior (servir stale en vez de quedarse sin límites).
		p.mu.Lock()
		if p.fetchedAt.IsZero() {
			p.fetchedAt = time.Now() // evitar reintentar en cada request si el primer fetch falló
		}
		p.mu.Unlock()
		return
	}
	p.mu.Lock()
	p.matrix = m
	p.fetchedAt = time.Now()
	p.mu.Unlock()
}
