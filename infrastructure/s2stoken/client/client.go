// Package client es el lado EMISOR del token de servicio (ACC-E09 T3, ADR-006 «Emisión y
// renovación»): carga la privada del emisor, firma la aserción private_key_jwt, pide el token a iam
// (directo por lab-network), lo cachea por (aud, scope) y lo renueva a los exp − 60 s. Tiene timeout,
// circuit breaker y la métrica s2s_token_issue_errors_total.
//
// Es un paquete aparte de s2stoken a propósito: un receptor puro no enlaza la carga de privadas.
// Ningún error ni log de este paquete incluye el token ni la aserción.
package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hornosg/go-shared/infrastructure/jwtkeyring"
	"github.com/hornosg/go-shared/infrastructure/s2stoken"
)

// Valores por defecto (ADR-006).
const (
	DefaultTimeout          = 5 * time.Second
	DefaultRenewBefore      = 60 * time.Second
	DefaultFailureThreshold = 5
	DefaultOpenFor          = 30 * time.Second
	// DefaultRetryBackoff: tras un rechazo 4xx de iam (aud o scope mal configurado) no se vuelve a pedir
	// durante este tiempo; ese error es permanente y no debe martillar a iam ni abrir el circuito.
	DefaultRetryBackoff = 5 * time.Second
	// MinReissueAge: un 401 del receptor sólo descarta un token cacheado si tiene al menos esta edad; uno
	// recién emitido que el receptor rechaza no se arregla pidiendo otro (O-3 de la revisión L4 de T3).
	MinReissueAge = 30 * time.Second
	// AssertionLifetime es exp − iat de la aserción; iam rechaza más de 60 s.
	AssertionLifetime = 60 * time.Second

	assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// ErrCircuitOpen: el breaker está abierto y no hay token cacheado vigente; no se llama a iam.
var ErrCircuitOpen = errors.New("s2s client: circuito abierto hacia iam")

// ErrIssue envuelve todo fallo de emisión (transporte, status, respuesta inválida).
var ErrIssue = errors.New("s2s client: emisión del token de servicio fallida")

// Config del emisor.
type Config struct {
	// Subject es el nombre canónico del emisor (iss = sub de la aserción): catalog-bff, sales…
	Subject string
	// Key es la privada del emisor (LoadPrivateKey). El kid sale de su pública, igual que en iam.
	Key *rsa.PrivateKey
	// TokenURL es el endpoint de emisión de iam por lab-network (http://lab-iam:8080/api/v1/s2s/token).
	TokenURL string
	// HTTPClient opcional; su Timeout se pisa con Timeout si es cero.
	HTTPClient *http.Client
	// Timeout por solicitud de emisión. 0 → DefaultTimeout.
	Timeout time.Duration
	// RenewBefore: el token se renueva cuando faltan menos que esto para exp. 0 → 60 s.
	RenewBefore time.Duration
	// FailureThreshold: fallos consecutivos que abren el circuito. 0 → 5.
	FailureThreshold int
	// OpenFor: cuánto queda abierto el circuito antes de dejar pasar un intento. 0 → 30 s.
	OpenFor time.Duration
	// Registerer de la métrica. nil → prometheus.DefaultRegisterer.
	Registerer prometheus.Registerer
	// Now fija el reloj en tests. nil → time.Now.
	Now func() time.Time
}

type entry struct {
	// lock es el single-flight de la entrada: un canal de capacidad 1 en vez de un sync.Mutex para que
	// quien espera pueda abandonar con su contexto (H-3 de la revisión L4 de T3). Lo libera quien lo
	// tomó o, si hubo emisión, la goroutine que la corre.
	lock      chan struct{}
	token     string
	issuedAt  time.Time
	renewAt   time.Time
	expiresAt time.Time
	// lastErr y retryAt: backoff tras un rechazo permanente (4xx) de iam.
	lastErr error
	retryAt time.Time
}

// breaker es el circuito de UN destino (aud): un aud mal configurado no corta a los demás.
type breaker struct {
	failures  int
	openUntil time.Time
}

// Client emite y cachea tokens de servicio. Seguro para uso concurrente.
type Client struct {
	cfg      Config
	kid      string
	http     *http.Client
	errors   *prometheus.CounterVec
	mu       sync.Mutex
	entries  map[string]*entry
	breakers map[string]*breaker
}

// New valida la config y registra la métrica.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Subject) == "" {
		return nil, errors.New("s2s client: Subject vacío")
	}
	if cfg.Key == nil {
		return nil, errors.New("s2s client: clave privada ausente")
	}
	if cfg.Key.N.BitLen() < 2048 {
		return nil, errors.New("s2s client: clave RSA menor a 2048 bits")
	}
	if _, err := url.ParseRequestURI(cfg.TokenURL); err != nil {
		return nil, fmt.Errorf("s2s client: TokenURL inválida: %w", err)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.RenewBefore == 0 {
		cfg.RenewBefore = DefaultRenewBefore
	}
	if cfg.FailureThreshold == 0 {
		cfg.FailureThreshold = DefaultFailureThreshold
	}
	if cfg.OpenFor == 0 {
		cfg.OpenFor = DefaultOpenFor
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	// El cliente de emisión NO sigue redirecciones: un 307/308 reenviaría la aserción (canjeable por iam
	// durante 60 s) a otro host (O-2 de la revisión L4 de T3). Se trabaja sobre una copia.
	hc := &http.Client{}
	if cfg.HTTPClient != nil {
		copied := *cfg.HTTPClient
		hc = &copied
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if hc.Timeout == 0 {
		hc.Timeout = cfg.Timeout
	}
	counter, err := registerCounter(cfg.Registerer)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:      cfg,
		kid:      jwtkeyring.KID(&cfg.Key.PublicKey),
		http:     hc,
		errors:   counter,
		entries:  map[string]*entry{},
		breakers: map[string]*breaker{},
	}, nil
}

func registerCounter(reg prometheus.Registerer) (*prometheus.CounterVec, error) {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "s2s_token_issue_errors_total",
		Help: "Fallos al obtener un token de servicio de iam, por aud y motivo.",
	}, []string{"aud", "reason"})
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing, nil
			}
		}
		return nil, fmt.Errorf("s2s client: registrar métrica: %w", err)
	}
	return c, nil
}

// Token devuelve un token de servicio para (aud, scopes), del caché si sigue vigente.
func (c *Client) Token(ctx context.Context, aud string, scopes ...string) (string, error) {
	scope := normalizeScope(scopes)
	if strings.TrimSpace(aud) == "" || scope == "" {
		return "", errors.New("s2s client: aud y scope son obligatorios")
	}
	e := c.entry(aud, scope)
	if err := e.acquire(ctx); err != nil {
		return "", err
	}
	tok, err, handedOff := c.obtainLocked(ctx, e, aud, scope)
	if !handedOff {
		e.release()
	}
	return tok, err
}

// Refresh es la reacción a un 401 del receptor para el token `sent`. Single-flight por entrada: si otro
// ya renovó el token, devuelve el nuevo; si el cacheado es el mismo y es más joven que MinReissueAge no
// re-emite (el 401 no es por vencimiento: puede ser el Bearer del usuario o un receptor desfasado en una
// rotación) y devuelve ok=false para que el llamador entregue el 401 tal cual.
func (c *Client) Refresh(ctx context.Context, sent, aud string, scopes ...string) (string, bool, error) {
	scope := normalizeScope(scopes)
	if strings.TrimSpace(aud) == "" || scope == "" {
		return "", false, errors.New("s2s client: aud y scope son obligatorios")
	}
	e := c.entry(aud, scope)
	if err := e.acquire(ctx); err != nil {
		return "", false, err
	}
	now := c.cfg.Now()
	if e.token != "" && e.token != sent && now.Before(e.expiresAt) {
		tok := e.token
		e.release()
		return tok, true, nil
	}
	if e.token == sent && now.Sub(e.issuedAt) < MinReissueAge {
		e.release()
		return "", false, nil
	}
	// Se fuerza la renovación SIN vaciar la entrada: si iam no responde (circuito abierto, backoff 4xx) el
	// token vigente sigue sirviendo hasta su exp (H-2 de la revisión L4 de T3).
	e.renewAt = time.Time{}
	tok, err, handedOff := c.obtainLocked(ctx, e, aud, scope)
	if !handedOff {
		e.release()
	}
	if err != nil || tok == sent {
		return "", false, err // sin token distinto del rechazado no hay reintento útil
	}
	return tok, true, nil
}

// Invalidate descarta el token cacheado de (aud, scopes). Uso explícito (p. ej. rotación forzada);
// Transport usa Refresh, que no descarta a ciegas.
func (c *Client) Invalidate(aud string, scopes ...string) {
	e := c.entry(aud, normalizeScope(scopes))
	_ = e.acquire(context.Background())
	e.token, e.issuedAt, e.renewAt, e.expiresAt = "", time.Time{}, time.Time{}, time.Time{}
	e.release()
}

// acquire toma el single-flight de la entrada o abandona cuando el contexto del llamador termina. Si la
// entrada está libre la toma aunque el contexto ya esté cancelado: así un token cacheado sigue sirviendo.
func (e *entry) acquire(ctx context.Context) error {
	select {
	case e.lock <- struct{}{}:
		return nil
	default:
	}
	select {
	case e.lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *entry) release() { <-e.lock }

// obtainLocked devuelve el token cacheado o lo emite. Llamar con el single-flight de e tomado.
// handedOff=true significa que la emisión quedó en curso en otra goroutine, que es la que libera el
// single-flight: el llamador NO debe liberarlo.
func (c *Client) obtainLocked(ctx context.Context, e *entry, aud, scope string) (tok string, err error, handedOff bool) {
	now := c.cfg.Now()
	if e.token != "" && now.Before(e.renewAt) {
		return e.token, nil, false
	}
	valid := e.token != "" && now.Before(e.expiresAt)
	// Rechazo permanente reciente de iam: no se vuelve a pedir hasta el backoff.
	if e.lastErr != nil && now.Before(e.retryAt) {
		if valid {
			return e.token, nil, false
		}
		return "", e.lastErr, false
	}
	if !c.allow(aud, now) {
		c.errors.WithLabelValues(aud, "circuit_open").Inc()
		// Un token todavía vigente (aunque ya en ventana de renovación) es mejor que ninguno.
		if valid {
			return e.token, nil, false
		}
		return "", ErrCircuitOpen, false
	}
	// La emisión no cuelga del contexto del request del usuario: su cancelación no es un fallo de iam
	// ni debe abortar una renovación que sirve a los demás requests. Corre en su propia goroutine, que
	// guarda el resultado y libera el single-flight; el llamador espera el resultado o su contexto
	// (H-3 de la revisión L4 de T3), lo que llegue primero.
	ictx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.cfg.Timeout)
	type result struct {
		tok string
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer cancel()
		defer e.release()
		tok, err := c.issueAndStore(ictx, e, aud, scope, now, valid)
		done <- result{tok, err}
	}()
	select {
	case r := <-done:
		return r.tok, r.err, true
	case <-ctx.Done():
		return "", ctx.Err(), true
	}
}

// issueAndStore emite y guarda el resultado en la entrada. Corre con el single-flight de e tomado.
func (c *Client) issueAndStore(ctx context.Context, e *entry, aud, scope string, now time.Time, valid bool) (string, error) {
	token, ttl, reason, err := c.issue(ctx, aud, scope, now)
	if err != nil {
		c.errors.WithLabelValues(aud, reason).Inc()
		if tripsBreaker(reason) {
			c.recordFailure(aud, now)
		} else {
			e.lastErr, e.retryAt = err, now.Add(DefaultRetryBackoff)
		}
		if valid {
			return e.token, nil
		}
		return "", err
	}
	c.recordSuccess(aud)
	e.lastErr, e.retryAt = nil, time.Time{}
	e.token, e.issuedAt = token, now
	e.expiresAt = now.Add(ttl)
	e.renewAt = e.expiresAt.Add(-c.cfg.RenewBefore)
	return token, nil
}

// tripsBreaker: sólo los fallos que indican a iam caído o saturado cuentan para el circuito. Un 4xx
// distinto de 429 (aud o scope mal configurado) es permanente y se resuelve con backoff, no abriendo.
func tripsBreaker(reason string) bool {
	switch reason {
	case "transport", "http_5xx", "http_429", "decode":
		return true
	default:
		return false
	}
}

func (c *Client) entry(aud, scope string) *entry {
	key := aud + "\x00" + scope
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		e = &entry{lock: make(chan struct{}, 1)}
		c.entries[key] = e
	}
	return e
}

func (c *Client) breakerFor(aud string) *breaker {
	b, ok := c.breakers[aud]
	if !ok {
		b = &breaker{}
		c.breakers[aud] = b
	}
	return b
}

// allow: cerrado → sí; abierto → no hasta openUntil; pasado openUntil (medio abierto) deja pasar el
// intento, y un fallo lo vuelve a abrir porque failures sigue sobre el umbral.
func (c *Client) allow(aud string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.breakerFor(aud)
	return b.failures < c.cfg.FailureThreshold || !now.Before(b.openUntil)
}

func (c *Client) recordFailure(aud string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.breakerFor(aud)
	b.failures++
	if b.failures >= c.cfg.FailureThreshold {
		b.openUntil = now.Add(c.cfg.OpenFor)
	}
}

func (c *Client) recordSuccess(aud string) {
	c.mu.Lock()
	b := c.breakerFor(aud)
	b.failures, b.openUntil = 0, time.Time{}
	c.mu.Unlock()
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// issue pide el token a iam. Devuelve el motivo de la métrica (baja cardinalidad) junto al error.
func (c *Client) issue(ctx context.Context, aud, scope string, now time.Time) (string, time.Duration, string, error) {
	assertion, err := c.assertion(now)
	if err != nil {
		return "", 0, "sign", fmt.Errorf("%w: firma de la aserción", ErrIssue)
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {assertionType},
		"client_assertion":      {assertion},
		"audience":              {aud},
		"scope":                 {scope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, "transport", fmt.Errorf("%w: request", ErrIssue)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", 0, "transport", fmt.Errorf("%w: transporte hacia iam", ErrIssue)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		reason := "http_5xx"
		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			reason = "http_429"
		case resp.StatusCode < 500:
			reason = "http_4xx"
		}
		return "", 0, reason, fmt.Errorf("%w: iam respondió %d", ErrIssue, resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" || tr.ExpiresIn <= 0 {
		return "", 0, "decode", fmt.Errorf("%w: respuesta de iam inválida", ErrIssue)
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl > s2stoken.TTL {
		ttl = s2stoken.TTL
	}
	return tr.AccessToken, ttl, "", nil
}

func (c *Client) assertion(now time.Time) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": c.cfg.Subject,
		"sub": c.cfg.Subject,
		"aud": s2stoken.AssertionAudience,
		"iat": now.Unix(),
		"exp": now.Add(AssertionLifetime).Unix(),
		"jti": hex.EncodeToString(jti),
	})
	tok.Header["kid"] = c.kid
	return tok.SignedString(c.cfg.Key)
}

func normalizeScope(scopes []string) string {
	set := map[string]struct{}{}
	for _, s := range scopes {
		for _, f := range strings.Fields(s) {
			set[f] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// LoadPrivateKey lee la privada RSA del emisor (PKCS#8 o PKCS#1, ≥ 2048 bits) generada por
// s2s-keygen. La pública correspondiente vive en infra/s2s-keys/<servicio>/.
//
// La clave sólo se lee si el archivo no es accesible por grupo ni por otros (modo ≤ 0600, N-5 de
// la revisión de T3): una privada legible por el resto del host permite firmar aserciones a
// nombre del servicio, así que se rechaza al arrancar en vez de usarse.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	// Se abre una sola vez y se comprueba el modo del MISMO descriptor que se lee: no hay ventana entre
	// el stat y la lectura (F-4 de la revisión L4 de T3b). Stat sigue symlinks (secrets de k8s).
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("s2s client: leer clave privada: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("s2s client: leer clave privada: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("s2s client: la clave privada tiene permisos %#o; se exige 0600 o más restrictivo", perm)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("s2s client: leer clave privada: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("s2s client: la clave privada no es PEM")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("s2s client: PKCS#8 inválido")
		}
		rk, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("s2s client: la clave privada no es RSA")
		}
		key = rk
	case "RSA PRIVATE KEY":
		if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return nil, errors.New("s2s client: PKCS#1 inválido")
		}
	default:
		return nil, errors.New("s2s client: bloque PEM no es una clave privada")
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("s2s client: clave RSA menor a 2048 bits")
	}
	return key, nil
}
