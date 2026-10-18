package s2sauth_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hornosg/go-shared/infrastructure/middleware"
	"github.com/hornosg/go-shared/infrastructure/middleware/s2sauth"
	"github.com/hornosg/go-shared/infrastructure/s2stoken"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/receiver"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/s2stest"
)

const aud = "stock-service"

type harness struct {
	iam         *s2stest.IAM
	legacyCalls int
	logs        *bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	gin.SetMode(gin.TestMode)
	return &harness{iam: s2stest.NewIAM(t), logs: &bytes.Buffer{}}
}

func (h *harness) cfg(mode receiver.SystemTenantMode, deny string) receiver.Config {
	d, _ := receiver.ParseDenySub(deny)
	return receiver.Config{
		Service:          s2stoken.Config{Keyring: h.iam.Keyring, Audience: aud, Namespace: "mc", RequiredScopes: []string{"stock:read"}},
		AllowUser:        true,
		System:           mode,
		SystemOnlyScopes: []string{"stock:admin"},
		DenySub:          d,
		Logger:           slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
}

// router: el combinador con una credencial heredada de prueba (X-Legacy-Key: ok) o la que se pase.
func (h *harness) router(cfg receiver.Config, legacy gin.HandlerFunc) *gin.Engine {
	if legacy == nil {
		legacy = func(c *gin.Context) {
			h.legacyCalls++
			if c.GetHeader("X-Legacy-Key") != "ok" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "legacy"})
				return
			}
			c.Next()
		}
	}
	r := gin.New()
	r.GET("/r", s2sauth.Middleware(cfg, legacy), func(c *gin.Context) {
		tenant, _ := c.Get("tenant_id")
		auth, _ := c.Get(s2sauth.ContextAuth)
		c.JSON(http.StatusOK, gin.H{"tenant": tenant, "auth": auth})
	})
	return r
}

func do(r http.Handler, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/r", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func (h *harness) svc(t *testing.T, tenantScope, scope string) string {
	return h.iam.SignService(t, s2stest.ServiceClaims("sales", aud, tenantScope, scope))
}

func (h *harness) user(t *testing.T, tenant string) string {
	return "Bearer " + h.iam.SignUser(t, s2stest.UserClaims("u-1", tenant, "admin"))
}

func want(t *testing.T, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("status %d, se espera %d (body %s)", w.Code, code, w.Body.String())
	}
}

func TestUserScope_ConBearer_UsaTenantDelBearer(t *testing.T) {
	h := newHarness(t)
	r := h.router(h.cfg(receiver.SystemDenied, ""), nil)
	w := do(r, map[string]string{"X-Service-Token": h.svc(t, "user", "stock:read"), "Authorization": h.user(t, "T1")})
	want(t, w, 200)
	if !strings.Contains(w.Body.String(), `"tenant":"T1"`) || !strings.Contains(w.Body.String(), `"auth":"token"`) {
		t.Fatalf("tenant del Bearer no aplicado: %s", w.Body.String())
	}
	want(t, do(r, map[string]string{"X-Service-Token": h.svc(t, "user", "stock:read"), "Authorization": h.user(t, "T1"), "X-Tenant-ID": "T1"}), 200)
	if h.legacyCalls != 0 {
		t.Fatal("con X-Service-Token no se consulta la heredada")
	}
}

func TestRechaza_TokenDeServicioEnAuthorization(t *testing.T) {
	h := newHarness(t)
	// Heredada real: TenantValidation sobre el mismo keyring.
	legacy := middleware.TenantValidation(middleware.TenantValidationConfig{JWTPublicKeyDir: h.iam.Dir, Namespace: "mc"})
	r := h.router(h.cfg(receiver.SystemDenied, ""), legacy)
	want(t, do(r, map[string]string{"Authorization": "Bearer " + h.svc(t, "system", "stock:read"), "X-Tenant-ID": "T1"}), 401)
	// Y como Bearer "de usuario" acompañando un token user.
	want(t, do(r, map[string]string{"X-Service-Token": h.svc(t, "user", "stock:read"), "Authorization": "Bearer " + h.svc(t, "user", "stock:read")}), 401)
}

func TestRechaza_TokenDeUsuarioEnXServiceToken(t *testing.T) {
	h := newHarness(t)
	r := h.router(h.cfg(receiver.SystemDenied, ""), nil)
	tok := h.iam.SignUser(t, s2stest.UserClaims("u-1", "T1"))
	want(t, do(r, map[string]string{"X-Service-Token": tok, "Authorization": "Bearer " + tok, "X-Legacy-Key": "ok"}), 401)
}

func TestRechaza_TokenUserSinBearer401(t *testing.T) {
	h := newHarness(t)
	r := h.router(h.cfg(receiver.SystemDenied, ""), nil)
	want(t, do(r, map[string]string{"X-Service-Token": h.svc(t, "user", "stock:read"), "X-Tenant-ID": "T1"}), 401)
}

func TestRechaza_BearerSinTenantID403(t *testing.T) {
	h := newHarness(t)
	r := h.router(h.cfg(receiver.SystemDenied, ""), nil)
	want(t, do(r, map[string]string{"X-Service-Token": h.svc(t, "user", "stock:read"), "Authorization": h.user(t, "")}), 403)
}

func TestSystem_SoloEnRutasMarcadas(t *testing.T) {
	h := newHarness(t)
	tok := h.svc(t, "system", "stock:read")
	// Ruta no marcada de sistema: 403 con o sin X-Tenant-ID.
	want(t, do(h.router(h.cfg(receiver.SystemDenied, ""), nil), map[string]string{"X-Service-Token": tok, "X-Tenant-ID": "T1"}), 403)
	want(t, do(h.router(h.cfg(receiver.SystemDenied, ""), nil), map[string]string{"X-Service-Token": tok}), 403)
	// Sistema global: X-Tenant-ID presente → 403; ausente → 200.
	want(t, do(h.router(h.cfg(receiver.SystemGlobal, ""), nil), map[string]string{"X-Service-Token": tok, "X-Tenant-ID": "T1"}), 403)
	want(t, do(h.router(h.cfg(receiver.SystemGlobal, ""), nil), map[string]string{"X-Service-Token": tok}), 200)
	// Sistema por tenant: exige X-Tenant-ID, lo acepta y lo loguea con el sub; el Bearer se ignora.
	pt := h.router(h.cfg(receiver.SystemPerTenant, ""), nil)
	want(t, do(pt, map[string]string{"X-Service-Token": tok}), 403)
	w := do(pt, map[string]string{"X-Service-Token": tok, "X-Tenant-ID": "11111111-1111-1111-1111-111111111119", "Authorization": h.user(t, "T1")})
	want(t, w, 200)
	if !strings.Contains(w.Body.String(), `"tenant":"11111111-1111-1111-1111-111111111119"`) || !strings.Contains(h.logs.String(), `"event":"s2s_system_tenant"`) {
		t.Fatalf("tenant de sistema no aplicado o no logueado: %s / %s", w.Body.String(), h.logs.String())
	}
}

func TestRechaza_TokenInvalidoSinDowngradeALaHeredada(t *testing.T) {
	h := newHarness(t)
	r := h.router(h.cfg(receiver.SystemDenied, ""), nil)
	want(t, do(r, map[string]string{"X-Legacy-Key": "ok"}), 200) // la heredada sola funciona
	h.legacyCalls = 0
	other := s2stest.NewIAM(t) // firmado por una clave fuera del keyring
	for _, bad := range []string{"basura", other.SignService(t, s2stest.ServiceClaims("sales", aud, "user", "stock:read"))} {
		w := do(r, map[string]string{"X-Service-Token": bad, "X-Legacy-Key": "ok", "Authorization": h.user(t, "T1")})
		want(t, w, 401)
		if strings.TrimSpace(w.Body.String()) != `{"error":"Unauthorized"}` {
			t.Fatalf("C-2: el cuerpo no es genérico: %s", w.Body.String())
		}
	}
	if h.legacyCalls != 0 {
		t.Fatalf("un token inválido cayó a la credencial heredada (%d)", h.legacyCalls)
	}
}

func TestRechaza_TenantDiscordante403(t *testing.T) {
	h := newHarness(t)
	r := h.router(h.cfg(receiver.SystemDenied, ""), nil)
	want(t, do(r, map[string]string{"X-Service-Token": h.svc(t, "user", "stock:read"), "Authorization": h.user(t, "T1"), "X-Tenant-ID": "T2"}), 403)
	if !strings.Contains(h.logs.String(), `"event":"s2s_tenant_mismatch"`) || !strings.Contains(h.logs.String(), `"sub":"sales"`) {
		t.Fatalf("falta el log s2s_tenant_mismatch con sub: %s", h.logs.String())
	}
}

func TestDenySub(t *testing.T) {
	h := newHarness(t)
	if _, err := receiver.ParseDenySub("sales, catalog-bff"); err != nil {
		t.Fatal(err)
	}
	want(t, do(h.router(h.cfg(receiver.SystemDenied, "sales"), nil), map[string]string{"X-Service-Token": h.svc(t, "user", "stock:read"), "Authorization": h.user(t, "T1")}), 401)
	// No parseable: rechaza todo token de servicio y mantiene a los usuarios (heredada).
	for _, raw := range []string{"Sales", "sales;pim", "sales,,pim", "a b"} {
		d, err := receiver.ParseDenySub(raw)
		if err == nil || !d.Invalid() {
			t.Fatalf("%q debería ser no parseable", raw)
		}
		r := h.router(h.cfg(receiver.SystemDenied, raw), nil)
		want(t, do(r, map[string]string{"X-Service-Token": h.svc(t, "user", "stock:read"), "Authorization": h.user(t, "T1")}), 401)
		want(t, do(r, map[string]string{"X-Legacy-Key": "ok"}), 200)
	}
}

func TestRechaza_ScopeDeSistemaConTokenUser403(t *testing.T) {
	h := newHarness(t)
	r := h.router(h.cfg(receiver.SystemDenied, ""), nil)
	want(t, do(r, map[string]string{"X-Service-Token": h.svc(t, "user", "stock:read stock:admin"), "Authorization": h.user(t, "T1")}), 403)
	want(t, do(r, map[string]string{"X-Service-Token": h.svc(t, "user", "stock:write"), "Authorization": h.user(t, "T1")}), 403)
}

func TestSinHeredada_SinTokenDa401(t *testing.T) {
	h := newHarness(t)
	r := gin.New()
	r.GET("/r", s2sauth.Middleware(h.cfg(receiver.SystemDenied, ""), nil), func(c *gin.Context) { c.Status(200) })
	want(t, do(r, map[string]string{"X-Legacy-Key": "ok"}), 401)
}

func TestLogsNoContienenTokens(t *testing.T) {
	h := newHarness(t)
	r := h.router(h.cfg(receiver.SystemDenied, ""), nil)
	tok := h.svc(t, "user", "stock:read")
	bearer := h.user(t, "T1")
	do(r, map[string]string{"X-Service-Token": tok, "Authorization": bearer, "X-Tenant-ID": "T2"})
	do(r, map[string]string{"X-Service-Token": tok})
	do(r, map[string]string{"X-Service-Token": tok, "Authorization": bearer})
	// Se busca la firma (último segmento): el header JWT es igual en todos los tokens y no es secreto.
	for name, jwtStr := range map[string]string{"servicio": tok, "usuario": strings.TrimPrefix(bearer, "Bearer ")} {
		sig := jwtStr[strings.LastIndex(jwtStr, ".")+1:]
		if strings.Contains(h.logs.String(), sig) {
			t.Fatalf("un log contiene el token de %s", name)
		}
	}
}
