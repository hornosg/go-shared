package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hornosg/go-shared/infrastructure/s2stoken"
)

// Fixture RS256 de paquete para los tests de happy path que no tienen *testing.T a mano
// (generateTestToken, platformRouter). Desde ACC-E03 T6 los middlewares sólo aceptan RS256 por
// kid, así que los fixtures que antes firmaban HS256 con testSecret firman con esta clave y los
// routers cargan su keyring.
var (
	fixtureOnce sync.Once
	fixtureKey  *rsa.PrivateKey
	fixtureDir  string
)

func rs256Fixture() (*rsa.PrivateKey, string) {
	fixtureOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			panic(err)
		}
		dir, err := os.MkdirTemp("", "go-shared-keyring-*")
		if err != nil {
			panic(err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		if err := os.WriteFile(filepath.Join(dir, "fixture.pem"), pemBytes, 0o600); err != nil {
			panic(err)
		}
		fixtureKey, fixtureDir = key, dir
	})
	return fixtureKey, fixtureDir
}

func signFixtureRS256(claims jwt.MapClaims) (string, error) {
	// Los tokens de usuario reales llevan iss=iam-service (iam 63a0329); desde ACC-E09 T3 los
	// verificadores de usuario lo exigen. Un test que necesite un token sin iss usa signFixtureRaw.
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = s2stoken.UserIssuer
	}
	return signFixtureRaw(claims)
}

func signFixtureRaw(claims jwt.MapClaims) (string, error) {
	key, _ := rs256Fixture()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = KeyringKID(&key.PublicKey)
	return token.SignedString(key)
}

func fixtureKeyringDir() string {
	_, dir := rs256Fixture()
	return dir
}

// signLegacyHS256 firma con el secreto compartido de la flota: el token que T6 tiene que rechazar.
func signLegacyHS256(claims jwt.MapClaims) string {
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))
	if err != nil {
		panic(err)
	}
	return signed
}
