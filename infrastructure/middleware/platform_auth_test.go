package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const platformTestSecret = "test-secret-min-32-chars-for-hs256-xxxxx"

// platformSignToken firma un JWT HS256 con los claims dados, mismo esquema que iam-service.
//
// Completa `exp` con una hora hacia adelante si el caller no lo fijó, porque el middleware ahora
// lo EXIGE (jwt.WithExpirationRequired). Los tests que quieren probar la expiración pasan el suyo:
// vencido (TokenExpirado) o explícitamente ausente (TokenSinExp, que setea exp a nil).
func platformSignToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, fijado := claims["exp"]; !fijado {
		claims["exp"] = time.Now().Add(1 * time.Hour).Unix()
	}
	if claims["exp"] == nil {
		delete(claims, "exp") // el caller pidió explícitamente un token SIN exp
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(platformTestSecret))
	if err != nil {
		t.Fatalf("no se pudo firmar el token de test: %v", err)
	}
	return signed
}

// platformRouter arma el mismo pipeline que catalog-service main.go: VerifyPlatformJWT +
// RequireRole, contra una ruta de datos de prueba.
func platformRouter() *gin.Engine {
	router := gin.New()
	group := router.Group("/api/v1")
	group.Use(
		VerifyPlatformJWT(PlatformAuthConfig{JWTSecret: platformTestSecret, Namespace: "mc"}),
		RequireRole("system_admin"),
	)
	group.GET("/whoami", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return router
}

func platformDoRequest(router *gin.Engine, bearer string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	router.ServeHTTP(w, req)
	return w
}

func TestVerifyPlatformJWT_SinToken_401(t *testing.T) {
	router := platformRouter()
	w := platformDoRequest(router, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("esperaba 401 sin token, obtuve %d", w.Code)
	}
}

func TestVerifyPlatformJWT_HeaderSinBearer_401(t *testing.T) {
	router := platformRouter()
	w := platformDoRequest(router, "Basic algo")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("esperaba 401 con header no-Bearer, obtuve %d", w.Code)
	}
}

func TestVerifyPlatformJWT_FirmaInvalida_401(t *testing.T) {
	router := platformRouter()
	otherSecret := "otro-secreto-completamente-distinto-xxxx"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"namespace": "mc", "roles": []string{"system_admin"},
	})
	signed, err := token.SignedString([]byte(otherSecret))
	if err != nil {
		t.Fatalf("no se pudo firmar: %v", err)
	}
	w := platformDoRequest(router, "Bearer "+signed)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("esperaba 401 con firma inválida, obtuve %d", w.Code)
	}
}

func TestVerifyPlatformJWT_TokenExpirado_401(t *testing.T) {
	router := platformRouter()
	token := platformSignToken(t, jwt.MapClaims{
		"namespace": "mc",
		"roles":     []string{"system_admin"},
		"exp":       time.Now().Add(-1 * time.Hour).Unix(),
	})
	w := platformDoRequest(router, "Bearer "+token)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("esperaba 401 con token expirado, obtuve %d", w.Code)
	}
}

// Un token SIN claim `exp` no caduca nunca: jwt/v5 valida la expiración sólo si el claim está
// presente. Con `system_admin` y sin RLS debajo (las 14 tablas de plataforma no llevan
// `tenant_id`), eso sería una llave maestra permanente sobre todo el catálogo. El middleware
// exige la presencia del claim, no sólo que sea futuro.
func TestVerifyPlatformJWT_TokenSinExp_401(t *testing.T) {
	router := platformRouter()
	token := platformSignToken(t, jwt.MapClaims{
		"namespace": "mc",
		"roles":     []string{"system_admin"},
		"exp":       nil, // nil = el helper NO lo completa: token sin exp, a propósito
	})
	w := platformDoRequest(router, "Bearer "+token)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("esperaba 401 con token sin exp (no caduca nunca), obtuve %d", w.Code)
	}
}

func TestVerifyPlatformJWT_JWTValido_RolTenantComun_403(t *testing.T) {
	router := platformRouter()
	token := platformSignToken(t, jwt.MapClaims{
		"namespace": "mc",
		"tenant_id": "11111111-1111-1111-1111-111111111111",
		"roles":     []string{"tenant_admin"},
	})
	w := platformDoRequest(router, "Bearer "+token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("esperaba 403 con rol tenant común contra ruta de plataforma, obtuve %d", w.Code)
	}
}

func TestVerifyPlatformJWT_SinClaimRoles_403(t *testing.T) {
	router := platformRouter()
	token := platformSignToken(t, jwt.MapClaims{"namespace": "mc"})
	w := platformDoRequest(router, "Bearer "+token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("esperaba 403 sin claim roles, obtuve %d", w.Code)
	}
}

func TestVerifyPlatformJWT_NamespaceDistinto_403(t *testing.T) {
	router := platformRouter()
	token := platformSignToken(t, jwt.MapClaims{
		"namespace": "otro-proyecto",
		"roles":     []string{"system_admin"},
	})
	w := platformDoRequest(router, "Bearer "+token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("esperaba 403 con namespace distinto, obtuve %d", w.Code)
	}
}

func TestVerifyPlatformJWT_SystemAdminValido_200(t *testing.T) {
	router := platformRouter()
	token := platformSignToken(t, jwt.MapClaims{
		"namespace": "mc",
		"roles":     []string{"system_admin"},
	})
	w := platformDoRequest(router, "Bearer "+token)
	if w.Code != http.StatusOK {
		t.Fatalf("esperaba 200 con JWT system_admin válido, obtuve %d (body=%s)", w.Code, w.Body.String())
	}
}

// D3.1: el rol se deriva EXCLUSIVAMENTE del claim `roles` del JWT verificado. Un header
// de rol crudo forjado por el cliente no debe alcanzar para autorizar — el middleware
// sólo lee `Authorization`.
func TestVerifyPlatformJWT_HeaderDeRolForjado_NoOtorgaAcceso(t *testing.T) {
	router := platformRouter()
	token := platformSignToken(t, jwt.MapClaims{
		"namespace": "mc",
		"roles":     []string{"tenant_admin"},
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Forged-Role-Header", "system_admin")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("un header de rol crudo forjado NO debe otorgar acceso; esperaba 403, obtuve %d", w.Code)
	}
}
