package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-secret-key-at-least-32-characters-long"

func generateTestToken(tenantID, namespace string) string {
	claims := jwt.MapClaims{
		"tenant_id": tenantID,
		"user_id":   "user-123",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	if namespace != "" {
		claims["namespace"] = namespace
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(testSecret))
	return signed
}

func setupRouter(cfg TenantValidationConfig) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TenantValidation(cfg))
	r.GET("/api/v1/test", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	r.POST("/api/v1/auth/login", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	return r
}

func TestTenantValidation_MatchingTenant(t *testing.T) {
	r := setupRouter(TenantValidationConfig{JWTSecret: testSecret})
	token := generateTestToken("tenant-AAA", "")
	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", "tenant-AAA")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTenantValidation_MismatchedTenant(t *testing.T) {
	r := setupRouter(TenantValidationConfig{JWTSecret: testSecret})
	token := generateTestToken("tenant-AAA", "")
	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", "tenant-BBB")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTenantValidation_MissingTenantHeader(t *testing.T) {
	r := setupRouter(TenantValidationConfig{JWTSecret: testSecret})
	token := generateTestToken("tenant-AAA", "")
	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTenantValidation_ExcludedRoute(t *testing.T) {
	r := setupRouter(TenantValidationConfig{
		JWTSecret:      testSecret,
		ExcludedRoutes: []string{"/api/v1/auth/*", "/health"},
	})
	req, _ := http.NewRequest("POST", "/api/v1/auth/login", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("excluded route should pass, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTenantValidation_NoAuthHeader(t *testing.T) {
	r := setupRouter(TenantValidationConfig{JWTSecret: testSecret})
	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

// tokenWithoutTenant firma un token válido SIN claim tenant_id (simula un token de
// servicio S2S legacy).
func tokenWithoutTenant() string {
	claims := jwt.MapClaims{
		"user_id": "svc-onboarding",
		"exp":     time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(testSecret))
	return signed
}

// Default (RejectMissingTenant=false): el bypass histórico se preserva — un token sin
// tenant_id pasa. Garantiza que activar el rollout no rompe la flota en bloque.
func TestTenantValidation_MissingTenantClaim_BypassDefault(t *testing.T) {
	r := setupRouter(TenantValidationConfig{JWTSecret: testSecret})
	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenWithoutTenant())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("default debe preservar el bypass (200), got %d: %s", w.Code, w.Body.String())
	}
}

// Flag activado: el bypass se cierra — token sin tenant_id ⇒ 403 (cierra el IDOR).
func TestTenantValidation_MissingTenantClaim_RejectWhenEnabled(t *testing.T) {
	r := setupRouter(TenantValidationConfig{JWTSecret: testSecret, RejectMissingTenant: true})
	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenWithoutTenant())
	req.Header.Set("X-Tenant-ID", "tenant-AAA")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("con RejectMissingTenant debe ser 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTenantValidation_NamespaceMatch(t *testing.T) {
	r := setupRouter(TenantValidationConfig{JWTSecret: testSecret, Namespace: "mc"})
	token := generateTestToken("tenant-AAA", "mc")
	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", "tenant-AAA")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTenantValidation_NamespaceMismatch(t *testing.T) {
	r := setupRouter(TenantValidationConfig{JWTSecret: testSecret, Namespace: "mc"})
	token := generateTestToken("tenant-AAA", "other-project")
	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", "tenant-AAA")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("expected 403 on namespace mismatch, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTenantValidation_NamespaceNotConfigured_SkipsCheck(t *testing.T) {
	// When Namespace is empty, tokens without namespace claim pass freely.
	r := setupRouter(TenantValidationConfig{JWTSecret: testSecret})
	token := generateTestToken("tenant-AAA", "")
	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", "tenant-AAA")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200 when namespace not configured, got %d: %s", w.Code, w.Body.String())
	}
}
