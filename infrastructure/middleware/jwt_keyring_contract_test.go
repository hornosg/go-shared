package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// ACC-E03 T5b — tests de CONTRATO (fase TEST, @dev-qa). Escritos contra el Contrato de la épica,
// no contra la implementación: completan los casos que los tests de EXEC no ejercitan.

// Contrato: "`none`/otros → rechazo" y "paridad WithValidMethods({HS256, RS256})". Un token
// firmado con la clave CORRECTA y el kid CORRECTO pero con otro alg de la familia RSA/HMAC tiene
// que caer: si pasara, el verificador elige por familia y no por alg fijado.
func TestContratoT5b_OtrosAlgsConLaClaveCorrecta_401(t *testing.T) {
	key := genRSAKey(t)
	dir := keyringDir(t, &key.PublicKey)
	kid := KeyringKID(&key.PublicKey)

	sign := func(m jwt.SigningMethod, k interface{}) string {
		tok := jwt.NewWithClaims(m, userClaims())
		tok.Header["kid"] = kid
		s, err := tok.SignedString(k)
		if err != nil {
			t.Fatalf("sign %s: %v", m.Alg(), err)
		}
		return s
	}
	cases := map[string]string{
		"RS384 con la privada correcta": sign(jwt.SigningMethodRS384, key),
		"RS512 con la privada correcta": sign(jwt.SigningMethodRS512, key),
		"PS256 con la privada correcta": sign(jwt.SigningMethodPS256, key),
		"HS512 con el secreto legacy":   sign(jwt.SigningMethodHS512, []byte(testSecret)),
	}
	for rn, rt := range map[string]struct {
		r    *gin.Engine
		path string
	}{
		"TenantValidation":  {dualTenantRouter(t, dir), "/api/v1/test"},
		"VerifyPlatformJWT": {dualPlatformRouter(t, dir), "/admin"},
	} {
		for cn, tok := range cases {
			if w := doBearer(rt.r, rt.path, tok); w.Code != http.StatusUnauthorized {
				t.Errorf("%s / %s: code=%d, se espera 401", rn, cn, w.Code)
			}
		}
	}
}

// La rama RS256 no puede saltearse la validación de exp: un RS256 bien firmado pero vencido → 401.
func TestContratoT5b_RS256Expirado_401(t *testing.T) {
	key := genRSAKey(t)
	dir := keyringDir(t, &key.PublicKey)
	c := userClaims()
	c["exp"] = time.Now().Add(-1 * time.Minute).Unix()
	tok := signRS256(t, key, KeyringKID(&key.PublicKey), c)

	if w := doBearer(dualTenantRouter(t, dir), "/api/v1/test", tok); w.Code != http.StatusUnauthorized {
		t.Errorf("TenantValidation RS256 expirado: code=%d, se espera 401", w.Code)
	}
	if w := doBearer(dualPlatformRouter(t, dir), "/admin", tok); w.Code != http.StatusUnauthorized {
		t.Errorf("VerifyPlatformJWT RS256 expirado: code=%d, se espera 401", w.Code)
	}
}

// Cross-tenant: los controles de claims (tenant, namespace) que vienen DESPUÉS de verificar la firma
// tienen que seguir aplicando cuando el token entra por la rama RS256 (sales maneja dinero).
func TestContratoT5b_RS256ConTenantONamespaceAjeno_403(t *testing.T) {
	key := genRSAKey(t)
	dir := keyringDir(t, &key.PublicKey)
	kid := KeyringKID(&key.PublicKey)

	otroTenant := userClaims()
	otroTenant["tenant_id"] = "tenant-b" // doBearer manda X-Tenant-ID: tenant-a
	if w := doBearer(dualTenantRouter(t, dir), "/api/v1/test", signRS256(t, key, kid, otroTenant)); w.Code != http.StatusForbidden {
		t.Errorf("RS256 con tenant ajeno: code=%d, se espera 403", w.Code)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TenantValidation(TenantValidationConfig{JWTSecret: testSecret, JWTPublicKeyDir: dir, Namespace: "mc", RejectMissingTenant: true}))
	r.GET("/api/v1/test", func(c *gin.Context) { c.Status(200) })
	otroNS := userClaims()
	otroNS["namespace"] = "otro-proyecto"
	if w := doBearer(r, "/api/v1/test", signRS256(t, key, kid, otroNS)); w.Code != http.StatusForbidden {
		t.Errorf("RS256 con namespace ajeno: code=%d, se espera 403", w.Code)
	}

	sinTenant := userClaims()
	delete(sinTenant, "tenant_id")
	if w := doBearer(dualTenantRouter(t, dir), "/api/v1/test", signRS256(t, key, kid, sinTenant)); w.Code != http.StatusForbidden {
		t.Errorf("RS256 sin tenant_id con RejectMissingTenant: code=%d, se espera 403", w.Code)
	}

	noAdmin := userClaims()
	noAdmin["roles"] = []string{"tenant_admin"}
	if w := doBearer(dualPlatformRouter(t, dir), "/admin", signRS256(t, key, kid, noAdmin)); w.Code != http.StatusForbidden {
		t.Errorf("VerifyPlatformJWT RS256 sin system_admin: code=%d, se espera 403", w.Code)
	}
}

// Contrato: "kid por thumbprint RFC 7638 por archivo". El kid sale del material, nunca del nombre
// del archivo: un archivo mal nombrado no puede hacer que un kid inventado resuelva a esa clave.
func TestContratoT5b_KidDerivadoDelMaterialNoDelNombreDelArchivo(t *testing.T) {
	key := genRSAKey(t)
	dir := t.TempDir()
	const nombre = "acc-000000000000"
	if err := os.WriteFile(filepath.Join(dir, nombre+".pem"), publicPEM(t, &key.PublicKey), 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	r := dualTenantRouter(t, dir)

	if w := doBearer(r, "/api/v1/test", signRS256(t, key, nombre, userClaims())); w.Code != http.StatusUnauthorized {
		t.Errorf("kid = nombre del archivo: code=%d, se espera 401 (el kid no sale del nombre)", w.Code)
	}
	if w := doBearer(r, "/api/v1/test", signRS256(t, key, KeyringKID(&key.PublicKey), userClaims())); w.Code != http.StatusOK {
		t.Errorf("kid derivado del material: code=%d, se espera 200", w.Code)
	}
}

// Contrato: "jamás la pública como secreto HMAC". Variantes de la confusión RS/HS además del PEM:
// el DER PKIX y el módulo crudo. Ninguna puede pasar como HS256.
func TestContratoT5b_ConfusionRSHS_VariantesDelMaterialPublico_401(t *testing.T) {
	key := genRSAKey(t)
	dir := keyringDir(t, &key.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for name, secret := range map[string][]byte{
		"DER PKIX":                     der,
		"módulo N":                     key.PublicKey.N.Bytes(),
		"PEM sin salto de línea final": publicPEM(t, &key.PublicKey)[:len(publicPEM(t, &key.PublicKey))-1],
	} {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaims())
		tok.Header["kid"] = KeyringKID(&key.PublicKey)
		s, err := tok.SignedString(secret)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if w := doBearer(dualTenantRouter(t, dir), "/api/v1/test", s); w.Code != http.StatusUnauthorized {
			t.Errorf("TenantValidation confusión RS/HS (%s): code=%d, se espera 401", name, w.Code)
		}
		if w := doBearer(dualPlatformRouter(t, dir), "/admin", s); w.Code != http.StatusUnauthorized {
			t.Errorf("VerifyPlatformJWT confusión RS/HS (%s): code=%d, se espera 401", name, w.Code)
		}
	}
}

// kid con tipo no-string en el header → 401, sin panic.
func TestContratoT5b_KidNoString_401(t *testing.T) {
	key := genRSAKey(t)
	r := dualTenantRouter(t, keyringDir(t, &key.PublicKey))
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, userClaims())
	tok.Header["kid"] = 12345
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if w := doBearer(r, "/api/v1/test", s); w.Code != http.StatusUnauthorized {
		t.Fatalf("kid numérico: code=%d, se espera 401", w.Code)
	}
}

// Contrato: "jamás HMAC con clave vacía". Con keyring y JWTSecret vacío, la rama HS256 no puede
// aceptar un token firmado con secreto vacío (en VerifyPlatformJWT no hay panic de arranque que
// lo ataje antes).
func TestContratoT5b_SecretoVacioConKeyring(t *testing.T) {
	key := genRSAKey(t)
	dir := keyringDir(t, &key.PublicKey)
	empty := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaims())
	emptyStr, err := empty.SignedString([]byte(""))
	if err != nil {
		t.Fatalf("sign empty: %v", err)
	}

	gin.SetMode(gin.TestMode)
	// ACC-E03 T6: JWTSecret es opcional — sin secreto, con keyring, arranca y rechaza el HS256.
	tv := gin.New()
	tv.Use(TenantValidation(TenantValidationConfig{JWTSecret: "", JWTPublicKeyDir: dir, RejectMissingTenant: true}))
	tv.GET("/api/v1/test", func(c *gin.Context) { c.Status(200) })
	if w := doBearer(tv, "/api/v1/test", emptyStr); w.Code != http.StatusUnauthorized {
		t.Errorf("TenantValidation HS256 con secreto vacío: code=%d, se espera 401", w.Code)
	}

	pa := gin.New()
	pa.Use(VerifyPlatformJWT(PlatformAuthConfig{JWTSecret: "", JWTPublicKeyDir: dir, Namespace: "mc"}))
	pa.GET("/admin", RequireRole("system_admin"), func(c *gin.Context) { c.Status(200) })
	if w := doBearer(pa, "/admin", emptyStr); w.Code != http.StatusUnauthorized {
		t.Errorf("VerifyPlatformJWT HS256 con secreto vacío: code=%d, se espera 401", w.Code)
	}
}

// El campo de config gana sobre JWT_PUBLIC_KEY_DIR: una clave sólo presente en el directorio del
// entorno no puede colarse cuando el servicio configuró otro keyring explícito.
func TestContratoT5b_ConfigGanaSobreElEntorno(t *testing.T) {
	cfgKey, envKey := genRSAKey(t), genRSAKey(t)
	t.Setenv("JWT_PUBLIC_KEY_DIR", keyringDir(t, &envKey.PublicKey))
	r := dualTenantRouter(t, keyringDir(t, &cfgKey.PublicKey))

	if w := doBearer(r, "/api/v1/test", signRS256(t, envKey, KeyringKID(&envKey.PublicKey), userClaims())); w.Code != http.StatusUnauthorized {
		t.Errorf("clave del entorno con dir de config explícito: code=%d, se espera 401", w.Code)
	}
	if w := doBearer(r, "/api/v1/test", signRS256(t, cfgKey, KeyringKID(&cfgKey.PublicKey), userClaims())); w.Code != http.StatusOK {
		t.Errorf("clave del dir de config: code=%d, se espera 200", w.Code)
	}
}

// Contrato: "keyring ... PEM inválido → no arranca". Casos que los tests de EXEC no cubren: dos
// bloques en un archivo, pública no-RSA (EC), y un archivo inválido mezclado con uno válido (un PEM
// roto no puede quedar ignorado en silencio porque haya otro bueno al lado).
func TestContratoT5b_ArranqueFailClosed_CasosAdicionales(t *testing.T) {
	key := genRSAKey(t)
	good := publicPEM(t, &key.PublicKey)

	dosBloques := t.TempDir()
	_ = os.WriteFile(filepath.Join(dosBloques, "k.pem"), append(append([]byte{}, good...), publicPEM(t, &genRSAKey(t).PublicKey)...), 0o600)

	ec := t.TempDir()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	_ = os.WriteFile(filepath.Join(ec, "ec.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER}), 0o600)

	mezcla := t.TempDir()
	_ = os.WriteFile(filepath.Join(mezcla, "a-bueno.pem"), good, 0o600)
	_ = os.WriteFile(filepath.Join(mezcla, "z-roto.pem"), []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"), 0o600)

	gin.SetMode(gin.TestMode)
	for name, dir := range map[string]string{
		"dos bloques PEM en un archivo":  dosBloques,
		"pública EC (no RSA)":            ec,
		"un .pem roto junto a uno bueno": mezcla,
	} {
		d := dir
		mustPanic(t, "TenantValidation/"+name, func() {
			TenantValidation(TenantValidationConfig{JWTSecret: testSecret, JWTPublicKeyDir: d})
		})
		mustPanic(t, "VerifyPlatformJWT/"+name, func() {
			VerifyPlatformJWT(PlatformAuthConfig{JWTSecret: testSecret, JWTPublicKeyDir: d})
		})
	}

	// Dir configurado por ENTORNO y roto → también fatal (el fallback no es una vía para saltear
	// la validación de arranque).
	t.Setenv("JWT_PUBLIC_KEY_DIR", ec)
	mustPanic(t, "TenantValidation/env roto", func() {
		TenantValidation(TenantValidationConfig{JWTSecret: testSecret})
	})
}

// Release con keyring válido arranca y verifica RS256 (control inverso del panic de release: el
// fail-closed no puede ser "release nunca arranca").
func TestContratoT5b_ReleaseConKeyringValido_Arranca(t *testing.T) {
	key := genRSAKey(t)
	dir := keyringDir(t, &key.PublicKey)
	gin.SetMode(gin.ReleaseMode)
	defer gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(TenantValidation(TenantValidationConfig{JWTSecret: testSecret, JWTPublicKeyDir: dir, RejectMissingTenant: true}))
	r.GET("/api/v1/test", func(c *gin.Context) { c.Status(200) })
	if w := doBearer(r, "/api/v1/test", signRS256(t, key, KeyringKID(&key.PublicKey), userClaims())); w.Code != http.StatusOK {
		t.Fatalf("release con keyring válido: code=%d, se espera 200", w.Code)
	}
}
