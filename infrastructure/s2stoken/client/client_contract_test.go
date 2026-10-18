package client

// Tests de contrato del cliente emisor escritos en la fase TEST (ACC-E09 T3) desde el Contrato de la
// épica: caché por (aud, scope), renovación antes del vencimiento real aunque iam declare un
// expires_in mayor, timeout y métrica de errores de emisión.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// echoIAM emite un token que codifica (aud, scope, n) sin validar la aserción; expiresIn configurable.
func echoIAM(t *testing.T, expiresIn int, delay time.Duration) (*httptest.Server, *atomic.Int32) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + r.PostForm.Get("audience") + "|" + r.PostForm.Get("scope") + "|" +
			strconv.Itoa(int(n)) + `","token_type":"service","expires_in":` + strconv.Itoa(expiresIn) + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func contractClient(t *testing.T, url string, ck *clock, reg *prometheus.Registry, timeout time.Duration) *Client {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Subject: "catalog-bff", Key: key, TokenURL: url, Timeout: timeout, Registerer: reg, Now: ck.now})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Un token pedido para (aud, scope) nunca se sirve a otro aud ni a otro scope: si la caché se
// indexara sólo por aud, un emisor enviaría a un destino un token con el scope de otro llamado.
func TestCache_IndexadaPorAudYScope(t *testing.T) {
	srv, calls := echoIAM(t, 300, 0)
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c := contractClient(t, srv.URL, ck, prometheus.NewRegistry(), 0)
	ctx := context.Background()

	stockRead, err := c.Token(ctx, "stock-service", "stock:read")
	if err != nil {
		t.Fatal(err)
	}
	iamRead, _ := c.Token(ctx, "account-service", "stock:read")
	stockAdmin, _ := c.Token(ctx, "stock-service", "stock:read", "stock:write")
	if calls.Load() != 3 || stockRead == iamRead || stockRead == stockAdmin || iamRead == stockAdmin {
		t.Fatalf("la caché mezcló (aud, scope): calls=%d %q %q %q", calls.Load(), stockRead, iamRead, stockAdmin)
	}
	if again, _ := c.Token(ctx, "stock-service", "stock:read"); again != stockRead || calls.Load() != 3 {
		t.Fatalf("no reutilizó el token de (stock-service, stock:read): calls=%d", calls.Load())
	}
}

// iam declara expires_in mayor que el TTL del contrato (300 s): el cliente no puede extender su
// caché más allá del vencimiento real del token, o enviaría tokens vencidos (401 en el receptor).
func TestCache_NoConfiaEnUnExpiresInMayorAlTTL(t *testing.T) {
	srv, calls := echoIAM(t, 86400, 0)
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c := contractClient(t, srv.URL, ck, prometheus.NewRegistry(), 0)
	ctx := context.Background()
	first, err := c.Token(ctx, "stock-service", "stock:read")
	if err != nil {
		t.Fatal(err)
	}
	ck.t = ck.t.Add(299 * time.Second)
	again, _ := c.Token(ctx, "stock-service", "stock:read")
	if again == first || calls.Load() != 2 {
		t.Fatalf("sirvió de caché un token a 1 s del TTL del contrato: calls=%d", calls.Load())
	}
}

// Con iam colgado el cliente corta por timeout (no bloquea al llamador) y cuenta el error en
// s2s_token_issue_errors_total.
func TestTimeout_CortaYCuentaElError(t *testing.T) {
	srv, _ := echoIAM(t, 300, 5*time.Second)
	reg := prometheus.NewRegistry()
	c := contractClient(t, srv.URL, &clock{t: time.Unix(1_800_000_000, 0)}, reg, 100*time.Millisecond)
	start := time.Now()
	_, err := c.Token(context.Background(), "stock-service", "stock:read")
	if !errors.Is(err, ErrIssue) {
		t.Fatalf("se esperaba ErrIssue por timeout: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("el timeout no cortó: %s", elapsed)
	}
	total := 0.0
	for _, v := range gathered(t, reg) {
		total += v
	}
	if total < 1 {
		t.Fatal("el timeout no se contó en s2s_token_issue_errors_total")
	}
}

// Sin aud o sin scope no se emite nada: un token sin scope sería un token comodín.
func TestToken_AudYScopeObligatorios(t *testing.T) {
	srv, calls := echoIAM(t, 300, 0)
	c := contractClient(t, srv.URL, &clock{t: time.Unix(1_800_000_000, 0)}, prometheus.NewRegistry(), 0)
	for _, tc := range []struct {
		aud    string
		scopes []string
	}{{"", []string{"stock:read"}}, {"stock-service", nil}, {"stock-service", []string{" "}}} {
		if _, err := c.Token(context.Background(), tc.aud, tc.scopes...); err == nil {
			t.Fatalf("aud=%q scopes=%q aceptado", tc.aud, tc.scopes)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("se llamó a iam con aud/scope vacíos: %d", calls.Load())
	}
}
