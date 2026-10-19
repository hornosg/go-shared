package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/hornosg/go-shared/infrastructure/s2stoken"
)

// slowIAM devuelve un fake de iam que no responde hasta que se cierra release.
func slowIAM(t *testing.T, f *fakeIAM, release chan struct{}) {
	t.Helper()
	inner := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		inner.ServeHTTP(w, r)
	})
}

// H-3: quien espera el single-flight abandona con su contexto, sin quedar atado a la emisión de otro.
func TestSingleFlight_ElQueEsperaAbandonaConSuContexto(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newClient(t, prometheus.NewRegistry(), ck)
	release := make(chan struct{})
	slowIAM(t, f, release)
	defer close(release)

	go func() { _, _ = c.Token(context.Background(), "stock-service", "a:read", "b:read") }()
	time.Sleep(50 * time.Millisecond) // el primero ya tomó el single-flight y está emitiendo

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Token(ctx, "stock-service", "a:read", "b:read")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, se esperaba DeadlineExceeded", err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("el que espera tardó %v: quedó atado a la emisión ajena", el)
	}
}

// H-3: el que emite también abandona con su contexto, y la emisión en curso igual queda cacheada para
// los demás (su cancelación no aborta una renovación que sirve a todos).
func TestSingleFlight_ElQueEmiteAbandonaYLaEmisionSeCachea(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newClient(t, prometheus.NewRegistry(), ck)
	release := make(chan struct{})
	slowIAM(t, f, release)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Token(ctx, "stock-service", "a:read", "b:read"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, se esperaba DeadlineExceeded", err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("el emisor tardó %v en abandonar", el)
	}
	close(release)
	tok, err := c.Token(context.Background(), "stock-service", "a:read", "b:read")
	if err != nil || tok == "" {
		t.Fatalf("token tras la emisión abandonada: %q %v", tok, err)
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("llamadas a iam = %d, se esperaba 1 (la emisión abandonada se cachea)", n)
	}
}

// H-7: con Host fijado, un request a otro host no sale y no lleva el token.
func TestTransport_HostDistintoNoRecibeElToken(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newClient(t, prometheus.NewRegistry(), ck)
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		if r.Header.Get(s2stoken.HeaderServiceToken) != "" {
			t.Error("el token llegó a un host ajeno")
		}
	}))
	defer other.Close()
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(s2stoken.HeaderServiceToken) == "" {
			w.WriteHeader(401)
		}
	}))
	defer recv.Close()
	u, _ := url.Parse(recv.URL)
	hc := &http.Client{Transport: &Transport{Client: c, Audience: "stock-service", Scopes: []string{"a:read", "b:read"}, Host: u.Host}}

	resp, err := hc.Get(recv.URL + "/x")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("destino configurado: %v %v", resp, err)
	}
	resp.Body.Close()
	if _, err := hc.Get(other.URL + "/x"); !errors.Is(err, ErrHostMismatch) {
		t.Fatalf("err = %v, se esperaba ErrHostMismatch", err)
	}
	if otherHits.Load() != 0 {
		t.Fatal("el request al host ajeno salió")
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("llamadas a iam = %d, se esperaba 1", n)
	}
}
