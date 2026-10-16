package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hornosg/go-shared/infrastructure/jwtkeyring"
)

// La lógica de la aceptación dual de ACC-E03 (ADR-003 §f + addendum T5a §C, rev. 2) vive en
// infrastructure/jwtkeyring, sin gin, para que webdata (chi) y catalog la reusen sin copiarla.
// Estos alias conservan la API pública de middleware (v0.18.0) y los tests existentes.

// PublicKeyring es el conjunto de públicas RSA activas del firmador, indexadas por kid.
type PublicKeyring = jwtkeyring.Keyring

// LoadPublicKeyring lee todos los `*.pem` de dir (ver jwtkeyring.Load).
func LoadPublicKeyring(dir string) (*PublicKeyring, error) { return jwtkeyring.Load(dir) }

// KeyringKID deriva el kid igual que iam-service (ver jwtkeyring.KID).
var KeyringKID = jwtkeyring.KID

var dualAcceptedMethods = jwtkeyring.AcceptedMethods

func publicKeyDir(configured string) string { return jwtkeyring.Dir(configured) }

// resolvePublicKeyring: dir configurado → tiene que cargar o panic; dir vacío en GIN_MODE=release
// → panic; fuera de release → keyring ausente.
func resolvePublicKeyring(configured string) *PublicKeyring {
	ring, err := jwtkeyring.Resolve(configured, gin.Mode() == gin.ReleaseMode)
	if err != nil {
		panic(err.Error())
	}
	return ring
}

func dualKeyFunc(secret string, ring *PublicKeyring) jwt.Keyfunc {
	return jwtkeyring.Keyfunc(secret, ring)
}

func parseDual(tokenStr string, claims jwt.Claims, secret string, ring *PublicKeyring, opts ...jwt.ParserOption) error {
	return jwtkeyring.ParseDual(tokenStr, claims, secret, ring, opts...)
}
