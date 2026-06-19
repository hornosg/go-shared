package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"

	"github.com/hornosg/go-shared/infrastructure/ratelimit"
)

type staticProvider struct {
	rule ratelimit.Rule
	ok   bool
}

func (s staticProvider) RuleFor(_, _ string) (ratelimit.Rule, bool) { return s.rule, s.ok }

type errLimiter struct{}

func (errLimiter) Allow(_ context.Context, _ string, _ ratelimit.Rule) (ratelimit.Decision, error) {
	return ratelimit.Decision{}, errors.New("redis down")
}

func realLimiter(t *testing.T) ratelimit.Limiter {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return ratelimit.NewRedisLimiter(client)
}

// engine arma un router con tenant_id + claim plan preseteados y el middleware bajo prueba.
func engine(mw gin.HandlerFunc, tier string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("tenant_id", "tenantA")
		c.Set("jwt_claims", jwt.MapClaims{"plan": map[string]interface{}{"tier": tier}})
		c.Next()
	})
	r.Use(mw)
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func do(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/x", nil)
	r.ServeHTTP(w, req)
	return w
}

func TestRateLimit_AllowThenDeny(t *testing.T) {
	mw := RateLimit(RateLimitConfig{
		Limiter:  realLimiter(t),
		Provider: staticProvider{rule: ratelimit.Rule{Algorithm: ratelimit.AlgoSlidingWindow, Limit: 1, Window: time.Minute}, ok: true},
		Feature:  "ai.bi_query",
	})
	r := engine(mw, "FREE")

	w1 := do(r)
	if w1.Code != http.StatusOK {
		t.Fatalf("1er request: got %d, want 200", w1.Code)
	}
	if w1.Header().Get("RateLimit-Limit") != "1" {
		t.Errorf("falta header RateLimit-Limit, got %q", w1.Header().Get("RateLimit-Limit"))
	}

	w2 := do(r)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("2do request: got %d, want 429", w2.Code)
	}
	if w2.Header().Get("Retry-After") == "" {
		t.Error("429 debe incluir Retry-After")
	}
}

func TestRateLimit_ObserveOnly(t *testing.T) {
	exceeded := 0
	mw := RateLimit(RateLimitConfig{
		Limiter:         realLimiter(t),
		Provider:        staticProvider{rule: ratelimit.Rule{Algorithm: ratelimit.AlgoSlidingWindow, Limit: 1, Window: time.Minute}, ok: true},
		Feature:         "ai.bi_query",
		ObserveOnly:     true,
		OnLimitExceeded: func(_ *gin.Context, _ string) { exceeded++ },
	})
	r := engine(mw, "FREE")

	if do(r).Code != http.StatusOK {
		t.Fatal("observe-only: 1er request 200")
	}
	// El 2do excede el límite pero en observe-only NO se rechaza.
	w2 := do(r)
	if w2.Code != http.StatusOK {
		t.Fatalf("observe-only: 2do request debe pasar (no rechazar), got %d", w2.Code)
	}
	if exceeded != 1 {
		t.Errorf("OnLimitExceeded debió dispararse 1 vez, got %d", exceeded)
	}
}

func TestRateLimit_SinReglaPasa(t *testing.T) {
	mw := RateLimit(RateLimitConfig{
		Limiter:  realLimiter(t),
		Provider: staticProvider{ok: false}, // no hay límite configurado para la celda
		Feature:  "ai.bi_query",
	})
	if do(engine(mw, "FREE")).Code != http.StatusOK {
		t.Fatal("sin regla configurada debe pasar")
	}
}

func TestRateLimit_FailOpen(t *testing.T) {
	called := false
	mw := RateLimit(RateLimitConfig{
		Limiter:              errLimiter{},
		Provider:             staticProvider{rule: ratelimit.Rule{Algorithm: ratelimit.AlgoSlidingWindow, Limit: 1, Window: time.Minute}, ok: true},
		Feature:              "ai.bi_query",
		FailClosed:           false,
		OnBackendUnavailable: func(_ *gin.Context, _ error) { called = true },
	})
	if do(engine(mw, "FREE")).Code != http.StatusOK {
		t.Fatal("fail-open: Redis caído debe dejar pasar")
	}
	if !called {
		t.Error("OnBackendUnavailable debió invocarse")
	}
}

func TestRateLimit_FailClosed(t *testing.T) {
	mw := RateLimit(RateLimitConfig{
		Limiter:    errLimiter{},
		Provider:   staticProvider{rule: ratelimit.Rule{Algorithm: ratelimit.AlgoSlidingWindow, Limit: 1, Window: time.Minute}, ok: true},
		Feature:    "pim.bulk_import",
		FailClosed: true,
	})
	if do(engine(mw, "FREE")).Code != http.StatusServiceUnavailable {
		t.Fatal("fail-closed: Redis caído debe responder 503")
	}
}

func TestPlanTierFromContext_DefaultFree(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// Sin jwt_claims → FREE.
	if got := PlanTierFromContext(c); got != PlanTierFree {
		t.Errorf("got %q, want FREE", got)
	}
	c.Set("jwt_claims", jwt.MapClaims{"plan": map[string]interface{}{"tier": "PREMIUM"}})
	if got := PlanTierFromContext(c); got != "PREMIUM" {
		t.Errorf("got %q, want PREMIUM", got)
	}
}
