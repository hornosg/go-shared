package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/hornosg/go-shared/infrastructure/ratelimit"
)

func newLimiter(t *testing.T) ratelimit.Limiter {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return ratelimit.NewRedisLimiter(client)
}

func TestParse(t *testing.T) {
	cases := []struct {
		name string
		raw  ratelimit.RawRule
		ok   bool
		alg  ratelimit.Algorithm
		lim  int
		win  time.Duration
	}{
		{"sliding ok", ratelimit.RawRule{Algorithm: "sliding_window_counter", Limit: 100, Window: "1s"}, true, ratelimit.AlgoSlidingWindow, 100, time.Second},
		{"gcra ok", ratelimit.RawRule{Algorithm: "gcra", Rate: "10/s", Burst: 5}, true, ratelimit.AlgoGCRA, 10, time.Second},
		{"gcra minuto", ratelimit.RawRule{Algorithm: "gcra", Rate: "30/m"}, true, ratelimit.AlgoGCRA, 30, time.Minute},
		{"sliding sin limit", ratelimit.RawRule{Algorithm: "sliding_window_counter", Window: "1s"}, false, "", 0, 0},
		{"sliding window mala", ratelimit.RawRule{Algorithm: "sliding_window_counter", Limit: 5, Window: "xx"}, false, "", 0, 0},
		{"algoritmo desconocido", ratelimit.RawRule{Algorithm: "token_bucket"}, false, "", 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := ratelimit.Parse(c.raw)
			if c.ok && err != nil {
				t.Fatalf("esperaba ok, error: %v", err)
			}
			if !c.ok {
				if err == nil {
					t.Fatal("esperaba error")
				}
				return
			}
			if r.Algorithm != c.alg || r.Limit != c.lim || r.Window != c.win {
				t.Errorf("got %+v", r)
			}
		})
	}
}

func TestSlidingWindow_AllowThenDeny(t *testing.T) {
	lim := newLimiter(t)
	rule := ratelimit.Rule{Algorithm: ratelimit.AlgoSlidingWindow, Limit: 3, Window: time.Minute}
	ctx := context.Background()
	key := "ratelimit:tenantA:ai.bi_query"

	for i := 0; i < 3; i++ {
		d, err := lim.Allow(ctx, key, rule)
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allowed {
			t.Fatalf("request %d debería pasar", i+1)
		}
		if d.Limit != 3 {
			t.Errorf("limit = %d, want 3", d.Limit)
		}
	}

	d, err := lim.Allow(ctx, key, rule)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Fatal("4ta request debería ser rechazada")
	}
	if d.RetryAfter <= 0 {
		t.Errorf("retry-after debería ser > 0, got %v", d.RetryAfter)
	}
}

func TestSlidingWindow_AislaPorClave(t *testing.T) {
	lim := newLimiter(t)
	rule := ratelimit.Rule{Algorithm: ratelimit.AlgoSlidingWindow, Limit: 1, Window: time.Minute}
	ctx := context.Background()

	// Distinto tenant en la clave → contador independiente (aislamiento multi-tenant).
	d1, _ := lim.Allow(ctx, "ratelimit:tenantA:f", rule)
	d2, _ := lim.Allow(ctx, "ratelimit:tenantB:f", rule)
	if !d1.Allowed || !d2.Allowed {
		t.Fatal("tenants distintos no deben compartir cuota")
	}
	d3, _ := lim.Allow(ctx, "ratelimit:tenantA:f", rule)
	if d3.Allowed {
		t.Fatal("segundo request del mismo tenant debe rechazarse (limit 1)")
	}
}

func TestGCRA_BurstCeroRechazaInmediato(t *testing.T) {
	lim := newLimiter(t)
	// rate 5/s, burst 0 → emission 200ms, sin tolerancia: solo 1 inmediato, el 2do espera.
	rule := ratelimit.Rule{Algorithm: ratelimit.AlgoGCRA, Limit: 5, Window: time.Second, Burst: 0}
	ctx := context.Background()
	key := "ratelimit:tenantA:gcra"

	d1, err := lim.Allow(ctx, key, rule)
	if err != nil {
		t.Fatal(err)
	}
	if !d1.Allowed {
		t.Fatal("primer request GCRA debe pasar")
	}
	d2, err := lim.Allow(ctx, key, rule)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Allowed {
		t.Fatal("segundo request inmediato con burst 0 debe rechazarse")
	}
	if d2.RetryAfter <= 0 {
		t.Errorf("GCRA debe devolver retry-after > 0 (sin sleep), got %v", d2.RetryAfter)
	}
}

func TestGCRA_PermiteBurst(t *testing.T) {
	lim := newLimiter(t)
	// rate 2/s, burst 2 → emission 500ms, tolerancia 1s → ~3 inmediatos antes de rechazar.
	rule := ratelimit.Rule{Algorithm: ratelimit.AlgoGCRA, Limit: 2, Window: time.Second, Burst: 2}
	ctx := context.Background()
	key := "ratelimit:tenantA:gcra-burst"

	allowed := 0
	for i := 0; i < 6; i++ {
		d, err := lim.Allow(ctx, key, rule)
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed {
			allowed++
		}
	}
	if allowed < 2 || allowed > 4 {
		t.Errorf("con burst 2 esperaba ~3 permitidos inmediatos, got %d", allowed)
	}
}
