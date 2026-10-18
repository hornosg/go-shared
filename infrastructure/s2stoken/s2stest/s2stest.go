// Package s2stest arma fixtures RS256 para probar receptores del token de servicio (ACC-E09 T3):
// una clave efímera de "iam", su keyring en un directorio temporal y firmantes de tokens de servicio
// y de usuario con los claims de contrato de ADR-006. Sólo para tests; lo usan go-shared y la flota.
package s2stest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hornosg/go-shared/infrastructure/jwtkeyring"
	"github.com/hornosg/go-shared/infrastructure/s2stoken"
)

// IAM es un firmador de prueba con su keyring público.
type IAM struct {
	Key     *rsa.PrivateKey
	Dir     string
	Keyring *jwtkeyring.Keyring
}

// NewIAM genera una clave RSA 2048 efímera y su keyring.
func NewIAM(t testing.TB) *IAM {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "iam.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	ring, err := jwtkeyring.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &IAM{Key: key, Dir: dir, Keyring: ring}
}

// ServiceClaims devuelve claims válidos de un token de servicio de sub hacia aud.
func ServiceClaims(sub, aud, tenantScope, scope string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": s2stoken.Issuer, "sub": sub, "aud": aud, "scope": scope,
		"token_use": s2stoken.TokenUse, "tenant_scope": tenantScope, "namespace": "mc",
		"iat": now.Unix(), "exp": now.Add(s2stoken.TTL).Unix(), "jti": "jti-" + sub + "-" + aud,
	}
}

// UserClaims devuelve claims válidos de un token de usuario de iam. tenant vacío → sin tenant_id.
func UserClaims(userID, tenant string, roles ...string) jwt.MapClaims {
	c := jwt.MapClaims{
		"iss": s2stoken.UserIssuer, "user_id": userID, "namespace": "mc", "roles": roles,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}
	if tenant != "" {
		c["tenant_id"] = tenant
	}
	return c
}

// SignService firma un token de servicio (typ s2s+jwt).
func (i *IAM) SignService(t testing.TB, claims jwt.MapClaims) string {
	return i.sign(t, claims, s2stoken.TokenType)
}

// SignUser firma un token de usuario (typ JWT).
func (i *IAM) SignUser(t testing.TB, claims jwt.MapClaims) string {
	return i.sign(t, claims, "JWT")
}

func (i *IAM) sign(t testing.TB, claims jwt.MapClaims, typ string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = jwtkeyring.KID(&i.Key.PublicKey)
	tok.Header["typ"] = typ
	s, err := tok.SignedString(i.Key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
