package s2stoken

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hornosg/go-shared/infrastructure/jwtkeyring"
)

// Fixtures: una clave efímera de "iam" montada en el keyring y otra ajena (p. ej. la de un emisor),
// que nunca está en el keyring. Sin secretos compartidos: el HS256 de los negativos se firma con
// un literal de test, que es justamente lo que el verificador debe rechazar.

var fixedNow = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

type fixture struct {
	iam    *rsa.PrivateKey
	other  *rsa.PrivateKey
	ring   *jwtkeyring.Keyring
	iamKID string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	iam, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&iam.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	kid := jwtkeyring.KID(&iam.PublicKey)
	if err := os.WriteFile(filepath.Join(dir, kid+".pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	ring, err := jwtkeyring.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{iam: iam, other: other, ring: ring, iamKID: kid}
}

func (f fixture) cfg(scopes ...string) Config {
	return Config{
		Keyring:        f.ring,
		Audience:       "stock-service",
		Namespace:      "mc",
		RequiredScopes: scopes,
		AnyScope:       len(scopes) == 0, // los tests que no piden scope lo dicen explícito
		Now:            func() time.Time { return fixedNow },
	}
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":          Issuer,
		"sub":          "catalog-bff-service",
		"aud":          "stock-service",
		"scope":        "stock:read config:read",
		"token_use":    TokenUse,
		"tenant_scope": TenantScopeSystem,
		"namespace":    "mc",
		"iat":          fixedNow.Add(-10 * time.Second).Unix(),
		"nbf":          fixedNow.Add(-10 * time.Second).Unix(),
		"exp":          fixedNow.Add(TTL - 10*time.Second).Unix(),
		"jti":          "3f1c2b9e-6c1d-4a51-9a59-4f3c3d0f8e11",
	}
}

func (f fixture) signRS256(t *testing.T, key *rsa.PrivateKey, kid, typ string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	if typ != "" {
		tok.Header["typ"] = typ
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f fixture) service(t *testing.T, mutate func(jwt.MapClaims)) string {
	t.Helper()
	c := validClaims()
	if mutate != nil {
		mutate(c)
	}
	return f.signRS256(t, f.iam, f.iamKID, TokenType, c)
}

func wantStatus(t *testing.T, err error, status int, sentinel error) {
	t.Helper()
	if err == nil {
		t.Fatalf("se esperaba rechazo %d, Verify aceptó", status)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("error %v no envuelve %v", err, sentinel)
	}
	t.Logf("rechazo: %v", err)
	if got := StatusCode(err); got != status {
		t.Fatalf("StatusCode = %d, se esperaba %d (%v)", got, status, err)
	}
}

func TestVerify_TokenDeServicioValido(t *testing.T) {
	f := newFixture(t)
	p, err := Verify(f.service(t, nil), f.cfg("stock:read"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.Subject != "catalog-bff-service" || p.Audience != "stock-service" || !p.IsSystem() ||
		!p.HasScope("config:read") || p.KID != f.iamKID || p.Namespace != "mc" {
		t.Fatalf("principal inesperado: %+v", p)
	}
	if StatusCode(nil) != 200 {
		t.Fatal("StatusCode(nil) debe ser 200")
	}
}

func TestVerify_RechazaHS256(t *testing.T) {
	f := newFixture(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims())
	tok.Header["kid"] = f.iamKID
	tok.Header["typ"] = TokenType
	s, err := tok.SignedString([]byte("secreto-compartido-de-test"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(s, f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
}

func TestVerify_RechazaAlgNone(t *testing.T) {
	f := newFixture(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims())
	tok.Header["typ"] = TokenType
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(s, f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
}

func TestVerify_RechazaFirmaDeClaveAjenaAlKeyring(t *testing.T) {
	f := newFixture(t)
	// Firmado por un emisor con su propia privada, con kid propio o con el kid de iam.
	c := validClaims()
	_, err := Verify(f.signRS256(t, f.other, jwtkeyring.KID(&f.other.PublicKey), TokenType, c), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
	_, err = Verify(f.signRS256(t, f.other, f.iamKID, TokenType, c), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
}

func TestVerify_RechazaAudAjeno(t *testing.T) {
	f := newFixture(t)
	_, err := Verify(f.service(t, func(c jwt.MapClaims) { c["aud"] = "customer-service" }), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
}

func TestVerify_RechazaAudEnArrayOAusente(t *testing.T) {
	f := newFixture(t)
	_, err := Verify(f.service(t, func(c jwt.MapClaims) { c["aud"] = []string{"stock-service"} }), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
	_, err = Verify(f.service(t, func(c jwt.MapClaims) { delete(c, "aud") }), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
}

func TestVerify_RechazaScopeInsuficiente(t *testing.T) {
	f := newFixture(t)
	_, err := Verify(f.service(t, nil), f.cfg("stock:reserve"))
	wantStatus(t, err, 403, ErrForbidden)
	// Un scope que es prefijo de otro no cuenta.
	_, err = Verify(f.service(t, func(c jwt.MapClaims) { c["scope"] = "stock:readx" }), f.cfg("stock:read"))
	wantStatus(t, err, 403, ErrForbidden)
}

func TestVerify_RechazaNamespaceAjeno(t *testing.T) {
	f := newFixture(t)
	_, err := Verify(f.service(t, func(c jwt.MapClaims) { c["namespace"] = "riotless" }), f.cfg())
	wantStatus(t, err, 403, ErrForbidden)
	_, err = Verify(f.service(t, func(c jwt.MapClaims) { delete(c, "namespace") }), f.cfg())
	wantStatus(t, err, 403, ErrForbidden)
}

func TestVerify_RechazaTokenVencido(t *testing.T) {
	f := newFixture(t)
	// Vencido hace más que el leeway.
	_, err := Verify(f.service(t, func(c jwt.MapClaims) {
		c["iat"] = fixedNow.Add(-TTL - time.Minute).Unix()
		c["nbf"] = fixedNow.Add(-TTL - time.Minute).Unix()
		c["exp"] = fixedNow.Add(-Leeway - time.Second).Unix()
	}), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
	// Dentro del leeway todavía vale.
	if _, err := Verify(f.service(t, func(c jwt.MapClaims) {
		c["iat"] = fixedNow.Add(-TTL).Unix()
		c["nbf"] = fixedNow.Add(-TTL).Unix()
		c["exp"] = fixedNow.Add(-Leeway + time.Second).Unix()
	}), f.cfg()); err != nil {
		t.Fatalf("dentro del leeway debía aceptar: %v", err)
	}
}

func TestVerify_RechazaExpIatAusentesOVidaLarga(t *testing.T) {
	f := newFixture(t)
	_, err := Verify(f.service(t, func(c jwt.MapClaims) { delete(c, "exp") }), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
	_, err = Verify(f.service(t, func(c jwt.MapClaims) { delete(c, "iat") }), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
	_, err = Verify(f.service(t, func(c jwt.MapClaims) { c["exp"] = fixedNow.Add(time.Hour).Unix() }), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
}

// Un token de usuario de iam (mismo firmador, mismo keyring) no vale como token de servicio:
// iss distinto, sin token_use, sin typ s2s.
func TestVerify_RechazaTokenDeUsuarioComoTokenDeServicio(t *testing.T) {
	f := newFixture(t)
	user := jwt.MapClaims{
		"iss":       UserIssuer,
		"sub":       "8f8e6a3c-0000-4000-8000-000000000001",
		"aud":       "stock-service",
		"tenant_id": "tenant-a",
		"roles":     []string{"admin"},
		"namespace": "mc",
		"scope":     "stock:read",
		"iat":       fixedNow.Add(-10 * time.Second).Unix(),
		"exp":       fixedNow.Add(10 * time.Minute).Unix(),
		"jti":       "user-jti",
	}
	_, err := Verify(f.signRS256(t, f.iam, f.iamKID, "JWT", user), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)

	// Aunque se le agregue typ s2s y token_use, el iss de usuario lo frena.
	user["token_use"] = TokenUse
	user["tenant_scope"] = TenantScopeUser
	_, err = Verify(f.signRS256(t, f.iam, f.iamKID, TokenType, user), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
}

func TestVerify_RechazaClaimsDeContratoFaltantes(t *testing.T) {
	f := newFixture(t)
	cases := map[string]func(jwt.MapClaims){
		"iss de usuario":         func(c jwt.MapClaims) { c["iss"] = UserIssuer },
		"token_use ausente":      func(c jwt.MapClaims) { delete(c, "token_use") },
		"token_use de usuario":   func(c jwt.MapClaims) { c["token_use"] = "access" },
		"sub ausente":            func(c jwt.MapClaims) { delete(c, "sub") },
		"jti ausente":            func(c jwt.MapClaims) { delete(c, "jti") },
		"tenant_scope ausente":   func(c jwt.MapClaims) { delete(c, "tenant_scope") },
		"tenant_scope inventado": func(c jwt.MapClaims) { c["tenant_scope"] = "admin" },
		"nbf futuro":             func(c jwt.MapClaims) { c["nbf"] = fixedNow.Add(time.Minute).Unix() },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(f.service(t, mutate), f.cfg())
			wantStatus(t, err, 401, ErrUnauthenticated)
		})
	}
	// typ distinto de s2s+jwt, con claims de servicio impecables.
	_, err := Verify(f.signRS256(t, f.iam, f.iamKID, "JWT", validClaims()), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
	_, err = Verify(f.signRS256(t, f.iam, f.iamKID, "", validClaims()), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
}

func TestVerify_ConfigInvalidaRechazaTodo(t *testing.T) {
	f := newFixture(t)
	tok := f.service(t, nil)
	for name, cfg := range map[string]Config{
		"sin keyring":   {Audience: "stock-service", Namespace: "mc", Now: f.cfg().Now},
		"sin audience":  {Keyring: f.ring, Namespace: "mc", Now: f.cfg().Now},
		"sin namespace": {Keyring: f.ring, Audience: "stock-service", Now: f.cfg().Now},
	} {
		t.Run(name, func(t *testing.T) {
			if cfg.Validate() == nil {
				t.Fatal("Validate debía fallar")
			}
			_, err := Verify(tok, cfg)
			wantStatus(t, err, 401, ErrUnauthenticated)
		})
	}
}

func TestStatusCode_ErrorDesconocidoEs401(t *testing.T) {
	if StatusCode(errors.New("otro")) != 401 {
		t.Fatal("un error desconocido debe tratarse como no autenticado")
	}
}

// O-1 (review L4 de T3a): sin scopes declarados la config es inválida; el valor por defecto deniega.
func TestVerify_SinScopesRequeridosRechazaPorDefecto(t *testing.T) {
	f := newFixture(t)
	cfg := f.cfg()
	cfg.AnyScope = false
	_, err := Verify(f.service(t, nil), cfg)
	wantStatus(t, err, 401, ErrUnauthenticated)
	if cfg.Validate() == nil {
		t.Fatal("Validate debe rechazar RequiredScopes vacío sin AnyScope")
	}
}

func TestVerify_AnyScopeExplicitoAceptaTokenSinScope(t *testing.T) {
	f := newFixture(t)
	cfg := f.cfg()
	cfg.AnyScope = true
	tok := f.service(t, func(c jwt.MapClaims) { c["scope"] = "" })
	if _, err := Verify(tok, cfg); err != nil {
		t.Fatalf("AnyScope explícito debe aceptar: %v", err)
	}
}

// B-3: un receptor configurado con el aud de la aserción de iam es una mala configuración.
func TestVerify_RechazaAudDeReceptorIgualAlDeLaAserción(t *testing.T) {
	f := newFixture(t)
	cfg := f.cfg("stock:read")
	cfg.Audience = AssertionAudience
	_, err := Verify(f.service(t, func(c jwt.MapClaims) { c["aud"] = AssertionAudience }), cfg)
	wantStatus(t, err, 401, ErrUnauthenticated)
}

// B-5: HS256 firmado con la PÚBLICA de iam como secreto (el ataque clásico de confusión de algoritmo).
func TestVerify_RechazaHS256FirmadoConLaPublicaComoSecreto(t *testing.T) {
	f := newFixture(t)
	der, err := x509.MarshalPKIXPublicKey(&f.iam.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims())
	tok.Header["kid"] = f.iamKID
	tok.Header["typ"] = TokenType
	signed, err := tok.SignedString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	_, verr := Verify(signed, f.cfg("stock:read"))
	wantStatus(t, verr, 401, ErrUnauthenticated)
}
