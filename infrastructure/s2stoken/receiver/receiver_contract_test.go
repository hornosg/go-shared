package receiver_test

// Tests de contrato del combinador receptor (ACC-E09 T3, ADR-006 «Alcance de tenant» y «Transición»),
// escritos en la fase TEST desde el Contrato de la épica, no desde la implementación. Cubren el
// Bearer de usuario adversarial, que un token system nunca herede tenant ni roles del Bearer y la
// lista S2S_DENY_SUB a nivel del núcleo (sin gin ni net/http).

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hornosg/go-shared/infrastructure/jwtkeyring"
	"github.com/hornosg/go-shared/infrastructure/s2stoken"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/receiver"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/s2stest"
)

const aud = "stock-service"

func cfgFor(iam *s2stest.IAM, logs *bytes.Buffer) receiver.Config {
	return receiver.Config{
		Service:   s2stoken.Config{Keyring: iam.Keyring, Audience: aud, Namespace: "mc", RequiredScopes: []string{"stock:read"}},
		AllowUser: true,
		System:    receiver.SystemDenied,
		Logger:    slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
}

func svc(t *testing.T, iam *s2stest.IAM, sub, tenantScope string) string {
	return iam.SignService(t, s2stest.ServiceClaims(sub, aud, tenantScope, "stock:read"))
}

func wantStatus(t *testing.T, err error, code int) {
	t.Helper()
	if err == nil {
		t.Fatalf("se esperaba %d y se aceptó", code)
	}
	if got := s2stoken.StatusCode(err); got != code {
		t.Fatalf("status %d, se espera %d (%v)", got, code, err)
	}
}

// Control positivo: sin él, los negativos de abajo podrían pasar porque todo falla.
func TestAuthenticate_ControlPositivo(t *testing.T) {
	iam := s2stest.NewIAM(t)
	res, err := receiver.Authenticate(cfgFor(iam, &bytes.Buffer{}), svc(t, iam, "sales", "user"),
		"Bearer "+iam.SignUser(t, s2stest.UserClaims("u-1", "T1", "admin")), "")
	if err != nil {
		t.Fatal(err)
	}
	if res.TenantID != "T1" || res.Service.Subject != "sales" || len(res.Roles) != 1 || res.Roles[0] != "admin" {
		t.Fatalf("resultado inesperado: %+v", res)
	}
}

func TestAuthenticate_XServiceTokenVacio401(t *testing.T) {
	iam := s2stest.NewIAM(t)
	for _, tok := range []string{"", "   "} {
		_, err := receiver.Authenticate(cfgFor(iam, &bytes.Buffer{}), tok, "Bearer "+iam.SignUser(t, s2stest.UserClaims("u", "T1")), "T1")
		wantStatus(t, err, 401)
	}
}

// El Bearer del usuario se verifica con el mismo rigor que un verificador de usuario de la flota:
// cualquier Bearer que un verificador de usuario rechace también se rechaza acá, aunque el token de
// servicio sea válido.
func TestAuthenticate_BearerDeUsuarioAdversarial(t *testing.T) {
	iam := s2stest.NewIAM(t)
	other := s2stest.NewIAM(t)
	tok := svc(t, iam, "sales", "user")

	expired := s2stest.UserClaims("u", "T1")
	expired["exp"] = time.Now().Add(-10 * time.Minute).Unix()
	noExp := s2stest.UserClaims("u", "T1")
	delete(noExp, "exp")
	foreignIss := s2stest.UserClaims("u", "T1")
	foreignIss["iss"] = "otro-idp"
	noIss := s2stest.UserClaims("u", "T1")
	delete(noIss, "iss")
	asService := s2stest.UserClaims("u", "T1")
	asService["token_use"] = s2stoken.TokenUse
	foreignNS := s2stest.UserClaims("u", "T1")
	foreignNS["namespace"] = "otro"

	cases := []struct {
		name   string
		bearer string
		want   int
	}{
		{"vencido", "Bearer " + iam.SignUser(t, expired), 401},
		{"sin exp", "Bearer " + iam.SignUser(t, noExp), 401},
		{"firmado por una clave fuera del keyring", "Bearer " + other.SignUser(t, s2stest.UserClaims("u", "T1")), 401},
		{"HS256 con la pública de iam como secreto (confusión de algoritmo)", "Bearer " + hs256WithPublicKey(t, iam, s2stest.UserClaims("u", "T1")), 401},
		{"alg none", "Bearer " + algNone(t, s2stest.UserClaims("u", "T1")), 401},
		{"iss ajeno", "Bearer " + iam.SignUser(t, foreignIss), 401},
		{"sin iss", "Bearer " + iam.SignUser(t, noIss), 401},
		{"token_use=service en el Bearer", "Bearer " + iam.SignUser(t, asService), 401},
		{"token de servicio como Bearer", "Bearer " + svc(t, iam, "sales", "user"), 401},
		{"sin prefijo Bearer", iam.SignUser(t, s2stest.UserClaims("u", "T1")), 401},
		{"esquema Basic", "Basic dTpw", 401},
		{"namespace ajeno", "Bearer " + iam.SignUser(t, foreignNS), 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := receiver.Authenticate(cfgFor(iam, &bytes.Buffer{}), tok, tc.bearer, "")
			wantStatus(t, err, tc.want)
		})
	}
}

// ADR-006: en tenant_scope=system el Bearer nunca amplía lo que da el token. Si un token de sistema
// heredara los roles o el tenant del Bearer, un servicio con un scope de lectura de sistema podría
// actuar como cualquier usuario cuyo Bearer consiga.
func TestAuthenticate_SystemNoHeredaTenantNiRolesDelBearer(t *testing.T) {
	iam := s2stest.NewIAM(t)
	bearer := "Bearer " + iam.SignUser(t, s2stest.UserClaims("u-1", "T1", "system_admin"))

	cfg := cfgFor(iam, &bytes.Buffer{})
	cfg.System = receiver.SystemGlobal
	res, err := receiver.Authenticate(cfg, svc(t, iam, "catalog-bff", "system"), bearer, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.TenantID != "" || res.UserClaims != nil || len(res.Roles) != 0 {
		t.Fatalf("SystemGlobal heredó del Bearer: %+v", res)
	}

	cfg.System = receiver.SystemPerTenant
	res, err = receiver.Authenticate(cfg, svc(t, iam, "catalog-bff", "system"), bearer, "11111111-1111-1111-1111-111111111119")
	if err != nil {
		t.Fatal(err)
	}
	if res.TenantID != "11111111-1111-1111-1111-111111111119" || res.UserClaims != nil || len(res.Roles) != 0 {
		t.Fatalf("SystemPerTenant heredó del Bearer o ignoró el header: %+v", res)
	}
}

func TestAuthenticate_TokenUserEnRutaSoloDeSistema403(t *testing.T) {
	iam := s2stest.NewIAM(t)
	cfg := cfgFor(iam, &bytes.Buffer{})
	cfg.AllowUser = false
	cfg.System = receiver.SystemGlobal
	_, err := receiver.Authenticate(cfg, svc(t, iam, "sales", "user"), "Bearer "+iam.SignUser(t, s2stest.UserClaims("u", "T1")), "")
	wantStatus(t, err, 403)
}

func TestAuthenticate_TenantScopeDesconocido4xx(t *testing.T) {
	iam := s2stest.NewIAM(t)
	for _, ts := range []string{"tenant", "", "SYSTEM"} {
		c := s2stest.ServiceClaims("sales", aud, ts, "stock:read")
		if ts == "" {
			delete(c, "tenant_scope")
		}
		_, err := receiver.Authenticate(cfgFor(iam, &bytes.Buffer{}), iam.SignService(t, c),
			"Bearer "+iam.SignUser(t, s2stest.UserClaims("u", "T1")), "T1")
		if err == nil {
			t.Fatalf("tenant_scope=%q aceptado", ts)
		}
		if code := s2stoken.StatusCode(err); code != 401 && code != 403 {
			t.Fatalf("tenant_scope=%q: status %d", ts, code)
		}
	}
}

// La lista deniega sólo a los subs listados: el control positivo evita que un «rechaza todo» pase
// por denegación selectiva.
func TestAuthenticate_DenySubSelectiva(t *testing.T) {
	iam := s2stest.NewIAM(t)
	cfg := cfgFor(iam, &bytes.Buffer{})
	d, err := receiver.ParseDenySub(" sales , pim-service ")
	if err != nil || d.Invalid() {
		t.Fatalf("lista válida con espacios rechazada: %v", err)
	}
	cfg.DenySub = d
	bearer := "Bearer " + iam.SignUser(t, s2stest.UserClaims("u", "T1"))
	for _, sub := range []string{"sales", "pim-service"} {
		_, err := receiver.Authenticate(cfg, svc(t, iam, sub, "user"), bearer, "")
		wantStatus(t, err, 401)
	}
	if _, err := receiver.Authenticate(cfg, svc(t, iam, "catalog-bff", "user"), bearer, ""); err != nil {
		t.Fatalf("un sub no listado quedó denegado: %v", err)
	}
	if _, err := receiver.ParseDenySub(""); err != nil {
		t.Fatalf("S2S_DENY_SUB vacía debe ser válida: %v", err)
	}
}

// Un S2S_DENY_SUB no parseable rechaza el token aun cuando la firma es válida y el sub no figura.
func TestAuthenticate_DenySubNoParseableRechazaTodo(t *testing.T) {
	iam := s2stest.NewIAM(t)
	cfg := cfgFor(iam, &bytes.Buffer{})
	d, err := receiver.ParseDenySub("catalog-bff,../etc")
	if err == nil || !d.Invalid() {
		t.Fatal("valor no parseable aceptado")
	}
	cfg.DenySub = d
	for _, ts := range []string{"user", "system"} {
		c := cfg
		c.System = receiver.SystemGlobal
		_, err := receiver.Authenticate(c, svc(t, iam, "sales", ts), "Bearer "+iam.SignUser(t, s2stest.UserClaims("u", "T1")), "")
		wantStatus(t, err, 401)
	}
}

// Los errores del combinador terminan en logs (reason): nunca deben arrastrar un token.
func TestAuthenticate_ErroresYLogsSinTokens(t *testing.T) {
	iam := s2stest.NewIAM(t)
	logs := &bytes.Buffer{}
	tok := svc(t, iam, "sales", "user")
	bearerTok := iam.SignUser(t, s2stest.UserClaims("u", "T1"))
	var errs []error
	for _, call := range []func() error{
		func() error {
			_, e := receiver.Authenticate(cfgFor(iam, logs), tok, "Bearer "+bearerTok, "T2")
			return e
		},
		func() error { _, e := receiver.Authenticate(cfgFor(iam, logs), tok, "Bearer "+tok, ""); return e },
		func() error {
			_, e := receiver.Authenticate(cfgFor(iam, logs), bearerTok, "Bearer "+bearerTok, "")
			return e
		},
	} {
		err := call()
		if err == nil {
			t.Fatal("se esperaba rechazo")
		}
		errs = append(errs, err)
	}
	for _, s := range []string{tok, bearerTok} {
		sig := s[strings.LastIndex(s, ".")+1:]
		for _, err := range errs {
			if strings.Contains(err.Error(), sig) {
				t.Fatalf("un error contiene un token: %v", err)
			}
		}
		if strings.Contains(logs.String(), sig) {
			t.Fatal("un log contiene un token")
		}
	}
	if !errors.Is(errs[0], s2stoken.ErrForbidden) {
		t.Fatalf("tenant discordante debería ser ErrForbidden: %v", errs[0])
	}
}

func hs256WithPublicKey(t *testing.T, iam *s2stest.IAM, claims jwt.MapClaims) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&iam.Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	secret := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = jwtkeyring.KID(&iam.Key.PublicKey)
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func algNone(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
