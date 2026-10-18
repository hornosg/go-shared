package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// multiAudIAM emite para cualquier aud y permite fallar por aud. No verifica la aserción: eso ya lo
// cubre newFakeIAM; acá importa el circuito y el caché por destino.
type multiAudIAM struct {
	srv    *httptest.Server
	mu     sync.Mutex
	status map[string]int
	calls  map[string]int
	seq    atomic.Int32
}

func newMultiAudIAM(t *testing.T) *multiAudIAM {
	f := &multiAudIAM{status: map[string]int{}, calls: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		aud := r.PostForm.Get("audience")
		f.mu.Lock()
		f.calls[aud]++
		code, ok := f.status[aud]
		f.mu.Unlock()
		if ok && code != 200 {
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + aud + `-` + strconv.Itoa(int(f.seq.Add(1))) + `","token_type":"service","expires_in":300}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *multiAudIAM) set(aud string, code int) {
	f.mu.Lock()
	f.status[aud] = code
	f.mu.Unlock()
}

func (f *multiAudIAM) count(aud string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[aud]
}

func newMultiAudClient(t *testing.T, ck *clock) (*Client, *multiAudIAM) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := newMultiAudIAM(t)
	c, err := New(Config{Subject: "catalog-bff", Key: key, TokenURL: f.srv.URL, FailureThreshold: 3, OpenFor: 30 * time.Second, Registerer: prometheus.NewRegistry(), Now: ck.now})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

// H-6 (revisión de T3): el circuito es por aud. Un destino con iam respondiendo 5xx no corta la emisión
// hacia otro, y el éxito del otro no cierra el circuito del primero.
func TestBreaker_SegundoAudNoQuedaCortado(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newMultiAudClient(t, ck)
	ctx := context.Background()
	f.set("stock-service", 500)
	for i := 0; i < 3; i++ {
		_, _ = c.Token(ctx, "stock-service", "stock:read")
	}
	if _, err := c.Token(ctx, "stock-service", "stock:read"); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("el circuito de stock no se abrió: %v", err)
	}
	tok, err := c.Token(ctx, "iam-service", "config:read")
	if err != nil || tok == "" || f.count("iam-service") != 1 {
		t.Fatalf("el circuito abierto de stock cortó a iam-service: tok=%q err=%v calls=%d", tok, err, f.count("iam-service"))
	}
	if _, err := c.Token(ctx, "stock-service", "stock:read"); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("el éxito de otro aud cerró el circuito de stock: %v", err)
	}
	if f.count("stock-service") != 3 {
		t.Fatalf("con el circuito abierto se llamó a iam por stock: %d", f.count("stock-service"))
	}
}

// H-6: camino de adopción de Refresh. Dos llamadores recibieron 401 con el mismo token; el primero lo
// renueva y el segundo adopta el nuevo sin volver a llamar a iam, aunque iam esté caído en ese momento.
func TestRefresh_AdoptaElTokenRenovadoPorOtroLlamador(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newMultiAudClient(t, ck)
	ctx := context.Background()
	old, err := c.Token(ctx, "stock-service", "stock:read")
	if err != nil {
		t.Fatal(err)
	}
	ck.t = ck.t.Add(MinReissueAge + time.Second)
	renewed, ok, err := c.Refresh(ctx, old, "stock-service", "stock:read")
	if err != nil || !ok || renewed == old || f.count("stock-service") != 2 {
		t.Fatalf("el primer Refresh no renovó: tok=%q ok=%v err=%v calls=%d", renewed, ok, err, f.count("stock-service"))
	}
	f.set("stock-service", 503)
	adopted, ok, err := c.Refresh(ctx, old, "stock-service", "stock:read")
	if err != nil || !ok || adopted != renewed {
		t.Fatalf("el segundo Refresh no adoptó el token renovado: tok=%q ok=%v err=%v", adopted, ok, err)
	}
	if f.count("stock-service") != 2 {
		t.Fatalf("la adopción volvió a llamar a iam: %d", f.count("stock-service"))
	}
}

// H-6: un token cacheado distinto del rechazado pero ya vencido no se adopta: se re-emite.
func TestRefresh_NoAdoptaUnTokenVencido(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newMultiAudClient(t, ck)
	ctx := context.Background()
	cached, err := c.Token(ctx, "stock-service", "stock:read")
	if err != nil {
		t.Fatal(err)
	}
	ck.t = ck.t.Add(301 * time.Second) // pasado el exp del cacheado
	got, ok, err := c.Refresh(ctx, "otro-token-rechazado", "stock-service", "stock:read")
	if err != nil || !ok || got == cached || f.count("stock-service") != 2 {
		t.Fatalf("adoptó un token vencido: tok=%q cached=%q ok=%v err=%v calls=%d", got, cached, ok, err, f.count("stock-service"))
	}
}
