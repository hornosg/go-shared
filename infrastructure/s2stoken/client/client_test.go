package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hornosg/go-shared/infrastructure/jwtkeyring"
	"github.com/hornosg/go-shared/infrastructure/s2stoken"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type fakeIAM struct {
	srv    *httptest.Server
	calls  atomic.Int32
	status atomic.Int32
}

// newFakeIAM verifica la aserción como iam (kid, iss=sub, aud fijo, vida ≤ 60 s) y emite.
func newFakeIAM(t *testing.T, pub *rsa.PublicKey) *fakeIAM {
	f := &fakeIAM{}
	f.status.Store(200)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if code := int(f.status.Load()); code != 200 {
			w.WriteHeader(code)
			return
		}
		_ = r.ParseForm()
		claims := jwt.MapClaims{}
		tok, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(s2stoken.AssertionAudience)).
			ParseWithClaims(r.PostForm.Get("client_assertion"), claims, func(*jwt.Token) (any, error) { return pub, nil })
		iat, _ := claims.GetIssuedAt()
		exp, _ := claims.GetExpirationTime()
		if err != nil || tok.Header["kid"] != jwtkeyring.KID(pub) || claims["iss"] != "catalog-bff" || claims["sub"] != "catalog-bff" ||
			claims["jti"] == "" || exp.Sub(iat.Time) > 60*time.Second || r.PostForm.Get("grant_type") != "client_credentials" ||
			r.PostForm.Get("audience") != "stock-service" || r.PostForm.Get("scope") != "a:read b:read" {
			t.Errorf("aserción o form inválidos: %v %v %v", err, claims, r.PostForm)
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + string(rune('0'+f.calls.Load())) + `","token_type":"service","expires_in":300}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func newClient(t *testing.T, reg *prometheus.Registry, ck *clock) (*Client, *fakeIAM) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeIAM(t, &key.PublicKey)
	c, err := New(Config{Subject: "catalog-bff", Key: key, TokenURL: f.srv.URL, FailureThreshold: 3, OpenFor: 30 * time.Second, Registerer: reg, Now: ck.now})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestCache_NoReemiteAntesDelVencimiento(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newClient(t, prometheus.NewRegistry(), ck)
	ctx := context.Background()
	first, err := c.Token(ctx, "stock-service", "b:read", "a:read")
	if err != nil {
		t.Fatal(err)
	}
	ck.t = ck.t.Add(239 * time.Second)                         // exp − 61 s
	again, _ := c.Token(ctx, "stock-service", "a:read b:read") // mismo (aud, scope) en otro orden
	if again != first || f.calls.Load() != 1 {
		t.Fatalf("re-emitió antes de exp-60s: calls=%d", f.calls.Load())
	}
	ck.t = ck.t.Add(2 * time.Second) // exp − 59 s: renovar
	renewed, _ := c.Token(ctx, "stock-service", "a:read", "b:read")
	if renewed == first || f.calls.Load() != 2 {
		t.Fatalf("no renovó a los exp-60s: calls=%d", f.calls.Load())
	}
	c.Invalidate("stock-service", "a:read", "b:read")
	_, _ = c.Token(ctx, "stock-service", "a:read", "b:read")
	if f.calls.Load() != 3 {
		t.Fatal("Invalidate no forzó la re-emisión")
	}
}

func TestCircuitBreaker_SeAbreYExponeLaMetrica(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	reg := prometheus.NewRegistry()
	c, f := newClient(t, reg, ck)
	f.status.Store(500)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := c.Token(ctx, "stock-service", "a:read", "b:read"); !errors.Is(err, ErrIssue) {
			t.Fatalf("intento %d: %v", i, err)
		}
	}
	if _, err := c.Token(ctx, "stock-service", "a:read", "b:read"); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("el circuito no se abrió: %v", err)
	}
	if f.calls.Load() != 3 {
		t.Fatalf("con el circuito abierto se llamó a iam: %d", f.calls.Load())
	}
	got := gathered(t, reg)
	if got["http_5xx"] != 3 || got["circuit_open"] != 1 {
		t.Fatalf("s2s_token_issue_errors_total expuesta en el registry = %v", got)
	}
	// Medio abierto tras OpenFor: deja pasar un intento; con éxito se cierra.
	ck.t = ck.t.Add(31 * time.Second)
	f.status.Store(200)
	if _, err := c.Token(ctx, "stock-service", "a:read", "b:read"); err != nil || f.calls.Load() != 4 {
		t.Fatalf("medio abierto: err=%v calls=%d", err, f.calls.Load())
	}
}

func TestErrores_NoIncluyenTokenNiAsercion(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newClient(t, prometheus.NewRegistry(), ck)
	f.status.Store(401)
	_, err := c.Token(context.Background(), "stock-service", "a:read", "b:read")
	if err == nil || strings.Contains(err.Error(), "ey") {
		t.Fatalf("error inesperado o con material de token: %v", err)
	}
}

func TestTransport_PoneHeaderYReemiteUnaVezAnte401(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newClient(t, prometheus.NewRegistry(), ck)
	var seen []string
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get(s2stoken.HeaderServiceToken))
		if len(seen) == 1 {
			ck.t = ck.t.Add(MinReissueAge + time.Second) // el token ya no es «recién emitido»
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer recv.Close()
	hc := &http.Client{Transport: &Transport{Client: c, Audience: "stock-service", Scopes: []string{"a:read", "b:read"}}}
	resp, err := hc.Post(recv.URL, "application/json", strings.NewReader(`{}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("err=%v resp=%v", err, resp)
	}
	if len(seen) != 2 || seen[0] == "" || seen[0] == seen[1] || f.calls.Load() != 2 {
		t.Fatalf("no re-emitió una sola vez: seen=%v calls=%d", seen, f.calls.Load())
	}
}

// O-3: un 401 sobre un token recién emitido no es por vencimiento (puede ser el Bearer del usuario o un
// receptor desfasado): no se re-emite, el 401 llega tal cual y no se consume el cupo de iam.
func TestTransport_401SobreTokenRecienEmitidoNoReemite(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newClient(t, prometheus.NewRegistry(), ck)
	hits := 0
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(401) }))
	defer recv.Close()
	hc := &http.Client{Transport: &Transport{Client: c, Audience: "stock-service", Scopes: []string{"a:read", "b:read"}}}
	for i := 0; i < 5; i++ {
		resp, err := hc.Post(recv.URL, "application/json", strings.NewReader(`{}`))
		if err != nil || resp.StatusCode != 401 {
			t.Fatalf("err=%v resp=%v", err, resp)
		}
	}
	if f.calls.Load() != 1 || hits != 5 {
		t.Fatalf("emisiones=%d (se espera 1), pedidos al receptor=%d (se espera 5)", f.calls.Load(), hits)
	}
}

// O-2: una redirección del receptor hacia otro host no recibe el token.
func TestTransport_NoReenviaElTokenEnRedirecciones(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newClient(t, prometheus.NewRegistry(), ck)
	leaked := ""
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get(s2stoken.HeaderServiceToken)
		w.WriteHeader(200)
	}))
	defer other.Close()
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer recv.Close()
	hc := &http.Client{Transport: &Transport{Client: c, Audience: "stock-service", Scopes: []string{"a:read", "b:read"}}}
	if _, err := hc.Get(recv.URL); err != nil {
		t.Fatal(err)
	}
	if leaked != "" {
		t.Fatalf("el token se reenvió a otro host tras una redirección: %q", leaked)
	}
}

// O-2: el cliente de emisión no sigue 307/308: la aserción no sale hacia otro host.
func TestEmision_NoSigueRedirecciones(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	gotAssertion := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotAssertion = r.PostForm.Get("client_assertion") != ""
		w.WriteHeader(200)
	}))
	defer other.Close()
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer iam.Close()
	c, err := New(Config{Subject: "catalog-bff", Key: key, TokenURL: iam.URL, Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background(), "stock-service", "a:read"); err == nil {
		t.Fatal("una redirección de iam no puede dar un token")
	}
	if gotAssertion {
		t.Fatal("la aserción se reenvió a otro host por una redirección 307")
	}
}

// O-3: un 4xx permanente de iam (aud mal configurado) no abre el circuito de los demás destinos y se
// resuelve con backoff; el circuito es por aud.
func TestBreaker_PorAudYSinContar4xx(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newClient(t, prometheus.NewRegistry(), ck)
	f.status.Store(403)
	ctx := context.Background()
	for i := 0; i < 6; i++ {
		_, _ = c.Token(ctx, "stock-service", "a:read", "b:read")
	}
	if f.calls.Load() != 1 {
		t.Fatalf("el backoff de un 4xx permanente debe evitar martillar a iam: %d llamadas", f.calls.Load())
	}
	// El 4xx no abrió el circuito: pasado el backoff, con iam sano, emite.
	f.status.Store(200)
	ck.t = ck.t.Add(DefaultRetryBackoff + time.Second)
	if _, err := c.Token(ctx, "stock-service", "a:read", "b:read"); err != nil {
		t.Fatalf("un 4xx permanente no debe dejar el circuito abierto: %v", err)
	}
}

// O-3: la cancelación del contexto del request del usuario no es un fallo de iam.
func TestBreaker_CancelacionDelRequestNoEsFallo(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newClient(t, prometheus.NewRegistry(), ck)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 10; i++ {
		_, _ = c.Token(cancelled, "stock-service", "a:read", "b:read")
	}
	if _, err := c.Token(context.Background(), "stock-service", "a:read", "b:read"); err != nil {
		t.Fatalf("las cancelaciones del request abrieron el circuito: %v (llamadas a iam=%d)", err, f.calls.Load())
	}
}

func TestModeFor(t *testing.T) {
	t.Setenv("S2S_MODE_STOCK_SERVICE", "token")
	if m, err := ModeFor("stock-service"); err != nil || m != ModeToken {
		t.Fatal(m, err)
	}
	if m, err := ModeFor("pim-service"); err != nil || m != ModeLegacy {
		t.Fatal("ausente debe ser legacy", m, err)
	}
	t.Setenv("S2S_MODE_PIM_SERVICE", "tokn")
	if _, err := ModeFor("pim-service"); err == nil {
		t.Fatal("un modo no reconocido debe fallar")
	}
}

func TestLoadPrivateKeyYNew(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	p := filepath.Join(t.TempDir(), "k.pem")
	_ = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	if got, err := LoadPrivateKey(p); err != nil || got.N.Cmp(key.N) != 0 {
		t.Fatal(err)
	}
	pubDer, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	_ = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}), 0o600)
	if _, err := LoadPrivateKey(p); err == nil {
		t.Fatal("una pública no es una privada de emisor")
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := New(Config{Subject: "x", Key: small, TokenURL: "http://iam/s2s", Registerer: prometheus.NewRegistry()}); err == nil {
		t.Fatal("RSA 1024 debe rechazarse")
	}
}

// gathered lee s2s_token_issue_errors_total{aud="stock-service"} desde el registry, como lo vería
// un scrape de Prometheus.
func gathered(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, mf := range families {
		if mf.GetName() != "s2s_token_issue_errors_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["aud"] == "stock-service" {
				out[labels["reason"]] = m.GetCounter().GetValue()
			}
		}
	}
	return out
}

// H-2: con iam caído, un 401 sobre un token vigente y viejo no vacía la entrada: el token sigue sirviendo
// hasta su exp y el 401 llega tal cual (no hay reintento útil con el mismo token).
func TestRefresh_ConIAMCaidoConservaElTokenVigente(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c, f := newClient(t, prometheus.NewRegistry(), ck)
	ctx := context.Background()
	tok, err := c.Token(ctx, "stock-service", "a:read", "b:read")
	if err != nil {
		t.Fatal(err)
	}
	ck.t = ck.t.Add(MinReissueAge + time.Second)
	f.status.Store(503)
	got, ok, rerr := c.Refresh(ctx, tok, "stock-service", "a:read", "b:read")
	if ok || got != "" || rerr != nil {
		t.Fatalf("sin re-emisión útil debe devolver ok=false: tok=%q ok=%v err=%v", got, ok, rerr)
	}
	again, err := c.Token(ctx, "stock-service", "a:read", "b:read")
	if err != nil || again != tok {
		t.Fatalf("la entrada se vació con iam caído: tok=%q err=%v", again, err)
	}
}

// N-5 (revisión de T3): una privada legible por grupo u otros no se usa.
func TestLoadPrivateKey_RechazaPermisosAbiertos(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604} {
		p := filepath.Join(t.TempDir(), "k.pem")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrivateKey(p); err == nil {
			t.Fatalf("modo %#o aceptado", mode)
		}
	}
	p := filepath.Join(t.TempDir(), "k.pem")
	_ = os.WriteFile(p, raw, 0o400)
	if _, err := LoadPrivateKey(p); err != nil {
		t.Fatalf("modo 0400 rechazado: %v", err)
	}
}
