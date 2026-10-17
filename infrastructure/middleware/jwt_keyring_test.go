package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// ACC-E03 T5b — aceptación dual en TenantValidation y VerifyPlatformJWT.

// kidT2 es el kid del par generado en ACC-E03 T2 (iam-service keys/jwt_signing.json).
const kidT2 = "acc-69a4a91f940a"

func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	return k
}

func publicPEM(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// keyringDir arma un JWT_PUBLIC_KEY_DIR con una pública por archivo.
func keyringDir(t *testing.T, pubs ...*rsa.PublicKey) string {
	t.Helper()
	dir := t.TempDir()
	for _, pub := range pubs {
		name := KeyringKID(pub) + ".pem"
		if err := os.WriteFile(filepath.Join(dir, name), publicPEM(t, pub), 0o600); err != nil {
			t.Fatalf("write pem: %v", err)
		}
	}
	return dir
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign rs256: %v", err)
	}
	return s
}

// algNoneToken: header {"alg":"none"} sin firma.
func algNoneToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	return s
}

// confusionToken: HS256 firmado usando el PEM PÚBLICO como secreto HMAC, con el kid real —
// la trampa clásica RS/HS.
func confusionToken(t *testing.T, pub *rsa.PublicKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = KeyringKID(pub)
	s, err := tok.SignedString(publicPEM(t, pub))
	if err != nil {
		t.Fatalf("sign confusion: %v", err)
	}
	return s
}

func userClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"tenant_id": "tenant-a",
		"user_id":   "user-123",
		"namespace": "mc",
		"roles":     []string{"system_admin"},
		"iss":       "iam-service",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}
}

func dualTenantRouter(t *testing.T, dir string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TenantValidation(TenantValidationConfig{JWTSecret: testSecret, JWTPublicKeyDir: dir, RejectMissingTenant: true}))
	r.GET("/api/v1/test", func(c *gin.Context) {
		claims, _ := c.Get("jwt_claims")
		mc, _ := claims.(jwt.MapClaims)
		c.JSON(200, gin.H{"tenant_id": c.GetString("tenant_id"), "user_id": mc["user_id"]})
	})
	return r
}

func dualPlatformRouter(t *testing.T, dir string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(VerifyPlatformJWT(PlatformAuthConfig{JWTSecret: testSecret, JWTPublicKeyDir: dir, Namespace: "mc"}))
	r.GET("/admin", RequireRole("system_admin"), func(c *gin.Context) { c.Status(200) })
	return r
}

func doBearer(r *gin.Engine, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestKeyringKID_CoincideConElKidDeT2(t *testing.T) {
	ring, err := LoadPublicKeyring("testdata")
	if err != nil {
		t.Fatalf("load testdata keyring: %v", err)
	}
	if got := ring.KIDs(); len(got) != 1 || got[0] != kidT2 {
		t.Fatalf("kid derivado = %v, se espera [%s] (misma derivación que SigningKeyKID de iam)", got, kidT2)
	}
}

func TestDual_TenantValidation_RS256Valido_PasaYPueblaClaims(t *testing.T) {
	key := genRSAKey(t)
	r := dualTenantRouter(t, keyringDir(t, &key.PublicKey))
	w := doBearer(r, "/api/v1/test", signRS256(t, key, KeyringKID(&key.PublicKey), userClaims()))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"user_id":"user-123"`) {
		t.Fatalf("RS256 válido: code=%d body=%s", w.Code, w.Body.String())
	}
}

// ACC-E03 T6 (criterio c, flota): un HS256 firmado con el JWT_SECRET de la flota —el mismo valor
// configurado en JWTSecret— se rechaza con 401 en los dos middlewares. Si diera 200 la raíz de
// confianza seguiría compartida.
func TestT6_HS256ConElSecretoDeLaFlota_401(t *testing.T) {
	key := genRSAKey(t)
	dir := keyringDir(t, &key.PublicKey)
	legacy := signLegacyHS256(userClaims())
	if w := doBearer(dualTenantRouter(t, dir), "/api/v1/test", legacy); w.Code != http.StatusUnauthorized {
		t.Errorf("TenantValidation aceptó HS256 tras el cutover: code=%d", w.Code)
	}
	if w := doBearer(dualPlatformRouter(t, dir), "/admin", legacy); w.Code != http.StatusUnauthorized {
		t.Errorf("VerifyPlatformJWT aceptó HS256 tras el cutover: code=%d", w.Code)
	}
}

func TestDual_Negativos_401(t *testing.T) {
	key := genRSAKey(t)
	other := genRSAKey(t)
	dir := keyringDir(t, &key.PublicKey)
	kid := KeyringKID(&key.PublicKey)

	hs384 := jwt.NewWithClaims(jwt.SigningMethodHS384, userClaims())
	hs384Str, _ := hs384.SignedString([]byte(testSecret))

	cases := map[string]string{
		"RS256 firmado con OTRA clave (kid conocido)": signRS256(t, other, kid, userClaims()),
		"RS256 con kid desconocido":                   signRS256(t, other, KeyringKID(&other.PublicKey), userClaims()),
		"RS256 sin kid":                               signRS256(t, key, "", userClaims()),
		"alg:none":                                    algNoneToken(t, userClaims()),
		"HS256 con la pública como secreto (RS/HS)":   confusionToken(t, &key.PublicKey, userClaims()),
		"HS384 con el secreto (familia HMAC cerrada)": hs384Str,
	}
	routers := map[string]struct {
		r    *gin.Engine
		path string
	}{
		"TenantValidation":  {dualTenantRouter(t, dir), "/api/v1/test"},
		"VerifyPlatformJWT": {dualPlatformRouter(t, dir), "/admin"},
	}
	for rn, rt := range routers {
		for cn, tok := range cases {
			if w := doBearer(rt.r, rt.path, tok); w.Code != http.StatusUnauthorized {
				t.Errorf("%s / %s: code=%d, se espera 401", rn, cn, w.Code)
			}
		}
	}
}

func TestDual_VerifyPlatformJWT_RS256Valido_200(t *testing.T) {
	key := genRSAKey(t)
	r := dualPlatformRouter(t, keyringDir(t, &key.PublicKey))
	if w := doBearer(r, "/admin", signRS256(t, key, KeyringKID(&key.PublicKey), userClaims())); w.Code != http.StatusOK {
		t.Fatalf("RS256 válido system_admin: code=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDual_VerifyPlatformJWT_RS256SinExp_401(t *testing.T) {
	key := genRSAKey(t)
	r := dualPlatformRouter(t, keyringDir(t, &key.PublicKey))
	c := userClaims()
	delete(c, "exp")
	if w := doBearer(r, "/admin", signRS256(t, key, KeyringKID(&key.PublicKey), c)); w.Code != http.StatusUnauthorized {
		t.Fatalf("RS256 sin exp debe seguir rechazado (WithExpirationRequired): code=%d", w.Code)
	}
}

func TestDual_Rotacion_DosClavesEnElKeyring(t *testing.T) {
	k1, k2 := genRSAKey(t), genRSAKey(t)
	r := dualTenantRouter(t, keyringDir(t, &k1.PublicKey, &k2.PublicKey))
	for name, k := range map[string]*rsa.PrivateKey{"kid1": k1, "kid2": k2} {
		if w := doBearer(r, "/api/v1/test", signRS256(t, k, KeyringKID(&k.PublicKey), userClaims())); w.Code != http.StatusOK {
			t.Errorf("%s en gracia: code=%d", name, w.Code)
		}
	}
	// Retirado k1 del keyring → sus tokens dejan de validar.
	r2 := dualTenantRouter(t, keyringDir(t, &k2.PublicKey))
	if w := doBearer(r2, "/api/v1/test", signRS256(t, k1, KeyringKID(&k1.PublicKey), userClaims())); w.Code != http.StatusUnauthorized {
		t.Fatalf("kid1 retirado: code=%d, se espera 401", w.Code)
	}
}

func TestDual_SinKeyringFueraDeRelease_RS256Rechazado(t *testing.T) {
	key := genRSAKey(t)
	r := dualTenantRouter(t, "")
	if w := doBearer(r, "/api/v1/test", signRS256(t, key, KeyringKID(&key.PublicKey), userClaims())); w.Code != http.StatusUnauthorized {
		t.Fatalf("sin keyring, RS256 debe dar 401: code=%d", w.Code)
	}
}

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: se esperaba panic (fatal de arranque)", name)
		}
	}()
	fn()
}

func TestDual_ArranqueFailClosed(t *testing.T) {
	key := genRSAKey(t)

	dup := t.TempDir()
	pemBytes := publicPEM(t, &key.PublicKey)
	_ = os.WriteFile(filepath.Join(dup, "a.pem"), pemBytes, 0o600)
	_ = os.WriteFile(filepath.Join(dup, "b.pem"), pemBytes, 0o600)

	priv := t.TempDir()
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	_ = os.WriteFile(filepath.Join(priv, "oops.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)

	garbage := t.TempDir()
	_ = os.WriteFile(filepath.Join(garbage, "x.pem"), []byte("no soy un pem"), 0o600)

	weak := t.TempDir()
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	_ = os.WriteFile(filepath.Join(weak, "weak.pem"), publicPEM(t, &small.PublicKey), 0o600)

	gin.SetMode(gin.TestMode)
	for name, dir := range map[string]string{
		"kid duplicado":      dup,
		"PEM privado":        priv,
		"PEM inválido":       garbage,
		"RSA-1024":           weak,
		"directorio vacío":   t.TempDir(),
		"directorio ausente": filepath.Join(t.TempDir(), "no-existe"),
	} {
		d := dir
		mustPanic(t, "TenantValidation/"+name, func() {
			TenantValidation(TenantValidationConfig{JWTSecret: testSecret, JWTPublicKeyDir: d})
		})
		mustPanic(t, "VerifyPlatformJWT/"+name, func() {
			VerifyPlatformJWT(PlatformAuthConfig{JWTSecret: testSecret, JWTPublicKeyDir: d})
		})
	}

	gin.SetMode(gin.ReleaseMode)
	defer gin.SetMode(gin.TestMode)
	mustPanic(t, "TenantValidation/release sin keyring", func() {
		TenantValidation(TenantValidationConfig{JWTSecret: testSecret})
	})
	mustPanic(t, "VerifyPlatformJWT/release sin keyring", func() {
		VerifyPlatformJWT(PlatformAuthConfig{JWTSecret: testSecret})
	})
}

// TestDual_ClaveRealDeT2 firma con la privada REAL de T2 (no versionada) cuando
// ACC_E03_T2_PRIVATE_KEY_FILE apunta a ella, y verifica contra el keyring de testdata.
func TestDual_ClaveRealDeT2(t *testing.T) {
	path := os.Getenv("ACC_E03_T2_PRIVATE_KEY_FILE")
	if path == "" {
		t.Skip("ACC_E03_T2_PRIVATE_KEY_FILE no seteada — corrida opcional con la clave real de T2")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read T2 key: %v", err)
	}
	block, _ := pem.Decode(raw)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse T2 key: %v", err)
	}
	key := parsed.(*rsa.PrivateKey)
	r := dualTenantRouter(t, "testdata")
	if w := doBearer(r, "/api/v1/test", signRS256(t, key, kidT2, userClaims())); w.Code != http.StatusOK {
		t.Fatalf("token RS256 con la clave real de T2: code=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDual_KeyringDesdeElEntorno(t *testing.T) {
	key := genRSAKey(t)
	t.Setenv("JWT_PUBLIC_KEY_DIR", keyringDir(t, &key.PublicKey))
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// Config SIN JWTPublicKeyDir: el wiring actual de la flota, sin tocar.
	r.Use(TenantValidation(TenantValidationConfig{JWTSecret: testSecret, RejectMissingTenant: true}))
	r.GET("/api/v1/test", func(c *gin.Context) { c.Status(200) })
	if w := doBearer(r, "/api/v1/test", signRS256(t, key, KeyringKID(&key.PublicKey), userClaims())); w.Code != http.StatusOK {
		t.Fatalf("keyring desde JWT_PUBLIC_KEY_DIR: code=%d", w.Code)
	}
}
