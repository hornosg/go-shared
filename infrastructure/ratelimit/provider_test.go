package ratelimit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hornosg/go-shared/infrastructure/ratelimit"
)

func TestRefreshingProvider_ServesAndCaches(t *testing.T) {
	calls := 0
	fetch := func(_ context.Context) (ratelimit.Matrix, error) {
		calls++
		return ratelimit.Matrix{
			"FREE": {"ai.bi_query": {Algorithm: ratelimit.AlgoGCRA, Limit: 10, Window: time.Second}},
		}, nil
	}
	p := ratelimit.NewRefreshingProvider(context.Background(), fetch, time.Hour)

	r, ok := p.RuleFor("FREE", "ai.bi_query")
	if !ok || r.Limit != 10 {
		t.Fatalf("esperaba regla FREE/ai.bi_query, got %+v ok=%v", r, ok)
	}
	if _, ok := p.RuleFor("PREMIUM", "ai.bi_query"); ok {
		t.Error("PREMIUM no está en la matriz → ok debe ser false")
	}
	if _, ok := p.RuleFor("FREE", "otra"); ok {
		t.Error("feature inexistente → ok debe ser false")
	}
	// Dentro del TTL no debe re-fetchear.
	p.RuleFor("FREE", "ai.bi_query")
	if calls != 1 {
		t.Errorf("fetch llamado %d veces, esperaba 1 (TTL no vencido)", calls)
	}
}

func TestRefreshingProvider_SirveStaleAnteError(t *testing.T) {
	failNow := false
	fetch := func(_ context.Context) (ratelimit.Matrix, error) {
		if failNow {
			return nil, errors.New("iam caído")
		}
		return ratelimit.Matrix{"FREE": {"f": {Algorithm: ratelimit.AlgoSlidingWindow, Limit: 5, Window: time.Second}}}, nil
	}
	// TTL chico → el próximo RuleFor dispara refresh.
	p := ratelimit.NewRefreshingProvider(context.Background(), fetch, time.Millisecond)
	failNow = true
	time.Sleep(3 * time.Millisecond)

	r, ok := p.RuleFor("FREE", "f")
	if !ok || r.Limit != 5 {
		t.Errorf("ante fetch fallido debe servirse la matriz anterior (stale), got %+v ok=%v", r, ok)
	}
}
