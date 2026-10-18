// Package jwtkeyring verifica tokens de usuario de la flota con RS256 por kid (ACC-E03). No
// depende de gin, así que lo pueden consumir servicios chi (webdata) y verificadores propios
// (catalog) sin copiar el selector criptográfico.
package jwtkeyring

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Verificación de tokens de usuario tras el cutover de ACC-E03 (T6, ADR-003 §f + addendum T5a).
//
// Regla de selección — por el header del token, nunca por intento y error:
//
//	alg RS256        → la pública cuyo kid coincide con el del header (keyring JWT_PUBLIC_KEY_DIR)
//	HS256 / none / … → rechazo
//
// Hasta v0.18.0 había una ventana dual que aceptaba HS256 con el secreto compartido de la flota
// (JWT_SECRET). T6 la cerró: ningún secreto simétrico verifica tokens de usuario. El parámetro
// secret de Keyfunc/ParseDual se conserva para no romper la compilación de los consumidores y se
// IGNORA (Deprecated: se retira en la próxima versión mayor).

// AcceptedMethods: sólo RS256. Doble control espejo de Keyfunc vía WithValidMethods.
var AcceptedMethods = []string{jwt.SigningMethodRS256.Alg()}

const (
	keyringKIDPrefix    = "acc"
	keyringKIDHexLength = 12
	minKeyringRSABits   = 2048
)

// Keyring es el conjunto de claves públicas RSA activas del firmador de iam/account,
// indexadas por kid. Es inmutable una vez cargado: rotar es cambiar los archivos del
// directorio y recrear el servicio (ciclo publicar → firmar → gracia → retirar, ADR-003 §C).
type Keyring struct {
	keys map[string]*rsa.PublicKey
}

// Load lee todos los `*.pem` de dir. Cada archivo debe contener exactamente una
// clave pública RSA (PKIX, bloque "PUBLIC KEY") de ≥2048 bits. El kid de cada clave se DERIVA
// del material (KID) — la config nunca declara un kid a mano que pueda divergir.
//
// Falla (error) si el directorio no existe o no es legible, si no hay ningún .pem, si un .pem
// no es una pública RSA válida (incluido un PEM privado puesto por error), o si dos archivos
// derivan el mismo kid. Un keyring roto es config rota: el servicio no debe arrancar.
func Load(dir string) (*Keyring, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("jwt keyring: directorio vacío")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		return nil, fmt.Errorf("jwt keyring: %w", err)
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		return nil, fmt.Errorf("jwt keyring: %w", statErr)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("jwt keyring: %s no contiene ningún .pem", dir)
	}
	sort.Strings(paths)

	ring := &Keyring{keys: make(map[string]*rsa.PublicKey, len(paths))}
	origin := make(map[string]string, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("jwt keyring: %w", err)
		}
		pub, err := parseRSAPublicPEM(raw)
		if err != nil {
			return nil, fmt.Errorf("jwt keyring: %s: %w", filepath.Base(p), err)
		}
		kid := KID(pub)
		if prev, dup := origin[kid]; dup {
			return nil, fmt.Errorf("jwt keyring: kid duplicado %s (%s y %s)", kid, prev, filepath.Base(p))
		}
		origin[kid] = filepath.Base(p)
		ring.keys[kid] = pub
	}
	return ring, nil
}

// PublicKeyFor devuelve la pública activa para kid. Receptor nil = keyring ausente → (nil, false):
// un *Keyring nil dentro de una interfaz no es nil (lección de ACC-E03 T4b), así que el
// método tolera el receptor nil en vez de desreferenciarlo.
func (k *Keyring) PublicKeyFor(kid string) (*rsa.PublicKey, bool) {
	if k == nil {
		return nil, false
	}
	pub, ok := k.keys[kid]
	return pub, ok
}

// KIDs devuelve los kid cargados, ordenados (para logs de arranque y tests).
func (k *Keyring) KIDs() []string {
	if k == nil {
		return nil
	}
	out := make([]string, 0, len(k.keys))
	for kid := range k.keys {
		out = append(out, kid)
	}
	sort.Strings(out)
	return out
}

// KID deriva el kid igual que iam-service (`SigningKeyKID`, ADR-003 §c):
// "acc-" + primeros 12 hex del SHA-256 del thumbprint canónico RFC 7638 {e, kty, n}.
func KID(pub *rsa.PublicKey) string {
	canonical := map[string]string{
		"e":   base64.RawURLEncoding.EncodeToString(exponentBytes(pub.E)),
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
	}
	// json.Marshal de un map ordena las claves (e < kty < n), el orden que exige RFC 7638.
	canonicalJSON, _ := json.Marshal(canonical)
	sum := sha256.Sum256(canonicalJSON)
	return keyringKIDPrefix + "-" + hex.EncodeToString(sum[:])[:keyringKIDHexLength]
}

func exponentBytes(v int) []byte {
	b := make([]byte, 4)
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte(v)
		v >>= 8
	}
	return b[i:]
}

func parseRSAPublicPEM(raw []byte) (*rsa.PublicKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no es PEM")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("más de un bloque PEM: un archivo por clave")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("bloque %q: se espera una pública PKIX (\"PUBLIC KEY\")", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("la pública debe ser RSA (got %T)", parsed)
	}
	if pub.N.BitLen() < minKeyringRSABits {
		return nil, fmt.Errorf("la pública debe ser RSA-%d o mayor (got %d bits)", minKeyringRSABits, pub.N.BitLen())
	}
	return pub, nil
}

// Dir resuelve el directorio del keyring: el campo de config gana; si viene vacío, se
// toma JWT_PUBLIC_KEY_DIR del entorno. El fallback existe para que la flota adopte el keyring con
// sólo bumpear go-shared y montar el directorio en su compose — sin tocar el main.go de cada
// consumidor, que además dejaría de compilar con GOWORK=off contra la versión fijada.
func Dir(configured string) string {
	if dir := strings.TrimSpace(configured); dir != "" {
		return dir
	}
	return strings.TrimSpace(os.Getenv("JWT_PUBLIC_KEY_DIR"))
}

// Resolve aplica la validación de arranque fail-closed (ADR-003 addendum §C): dir configurado →
// tiene que cargar o devuelve error (el servicio no debe arrancar, en cualquier modo); dir vacío con
// release=true → error; dir vacío fuera de release → keyring ausente (nil), la rama RS256 rechaza
// todo (desarrollo y tests que sólo ejercitan HS256).
func Resolve(configured string, release bool) (*Keyring, error) {
	dir := Dir(configured)
	if dir == "" {
		if release {
			return nil, errors.New("JWT_PUBLIC_KEY_DIR must be set in release mode (ACC-E03: keyring RS256 de la flota)")
		}
		return nil, nil
	}
	return Load(dir)
}

// Keyfunc implementa la regla RS256-only: la pública del keyring por el kid del header; ring nil →
// rechaza todo. secret se ignora (Deprecated, ver arriba): un HS256 se rechaza aunque venga
// firmado con el JWT_SECRET de la flota.
//
// Deprecated: usar RS256Keyfunc, que no recibe secreto. Se retira en la próxima versión mayor.
func Keyfunc(_ string, ring *Keyring) jwt.Keyfunc {
	return RS256Keyfunc(ring)
}

// RS256Keyfunc es la regla RS256-only sin parámetro de secreto (ACC-E09 T3a, ADR-006 «Contrato de
// go-shared»): la pública del keyring por el kid del header; cualquier otro alg o ring nil → rechazo.
// Es la que usan los verificadores nuevos (s2stoken); no hay forma de pasarle un secreto simétrico.
func RS256Keyfunc(ring *Keyring) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("método de firma no aceptado: %v", t.Header["alg"])
		}
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token RS256 sin kid en el header")
		}
		pub, ok := ring.PublicKeyFor(kid)
		if !ok {
			return nil, fmt.Errorf("kid desconocido o retirado: %s", kid)
		}
		return pub, nil
	}
}

// ParseDual parsea con Keyfunc + WithValidMethods(AcceptedMethods) como doble control. Conserva el
// nombre de la ventana dual por compatibilidad; desde T6 sólo acepta RS256 (secret se ignora).
func ParseDual(tokenStr string, claims jwt.Claims, _ string, ring *Keyring, opts ...jwt.ParserOption) error {
	opts = append([]jwt.ParserOption{jwt.WithValidMethods(AcceptedMethods)}, opts...)
	_, err := jwt.NewParser(opts...).ParseWithClaims(tokenStr, claims, RS256Keyfunc(ring))
	return err
}
