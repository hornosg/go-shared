package s2stoken

// Tests de contrato de ACC-E09 T3a (fase TEST, escritos contra el texto de la épica y ADR-006, no
// contra la implementación). Complementan s2stoken_test.go con: constantes de contrato fijadas,
// ausencia estructural de HMAC/secreto/framework, precedencia 401 sobre 403, kid y rotación,
// algoritmos RSA distintos de RS256 y bordes de exp/iat/TTL.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hornosg/go-shared/infrastructure/jwtkeyring"
)

// --- Constantes de contrato (ADR-006 «Claims»): cambiarlas es una migración coordinada de la flota,
// así que un cambio silencioso tiene que romper este test.

func TestContrato_ConstantesFijadasPorADR006(t *testing.T) {
	cases := map[string][2]string{
		"Issuer":            {Issuer, "iam-service/s2s"},
		"UserIssuer":        {UserIssuer, "iam-service"},
		"TokenUse":          {TokenUse, "service"},
		"TokenType":         {TokenType, "s2s+jwt"},
		"TenantScopeUser":   {TenantScopeUser, "user"},
		"TenantScopeSystem": {TenantScopeSystem, "system"},
	}
	for name, c := range cases {
		if c[0] != c[1] {
			t.Errorf("%s = %q, ADR-006 fija %q", name, c[0], c[1])
		}
	}
	if Issuer == UserIssuer {
		t.Error("el iss del token de servicio debe ser distinto del de usuario")
	}
	if TTL != 300*time.Second {
		t.Errorf("TTL = %s, ADR-006 fija exp = iat + 300 s", TTL)
	}
	if Leeway != 30*time.Second {
		t.Errorf("Leeway = %s, ADR-006 fija 30 s", Leeway)
	}
}

// --- Sin rama HMAC, sin parámetro de secreto compartido, sin gin ni net/http (Contrato de T3a).

func parseProdFiles(t *testing.T, dir string) []*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, m := range matches {
		if strings.HasSuffix(m, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, m, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatalf("sin archivos de producción en %s", dir)
	}
	return files
}

func TestContrato_SinGinNiNetHTTP(t *testing.T) {
	// s2stoken y su única dependencia local (jwtkeyring) deben quedar libres de framework.
	for _, dir := range []string{".", filepath.Join("..", "jwtkeyring")} {
		for _, f := range parseProdFiles(t, dir) {
			for _, imp := range f.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				if path == "net/http" || strings.Contains(path, "gin-gonic") || strings.HasPrefix(path, "net/http/") {
					t.Errorf("%s importa %q: el núcleo no debe depender de gin ni de net/http", dir, path)
				}
			}
		}
	}
}

func TestContrato_SinRamaHMACNiSecretoEnElNucleo(t *testing.T) {
	forbiddenSelectors := map[string]bool{
		"SigningMethodHMAC":  true,
		"SigningMethodHS256": true,
		"SigningMethodHS384": true,
		"SigningMethodHS512": true,
	}
	for _, f := range parseProdFiles(t, ".") {
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if forbiddenSelectors[sel.Sel.Name] {
				t.Errorf("s2stoken referencia %s: el núcleo no puede tener rama HMAC", sel.Sel.Name)
			}
			// La Keyfunc deprecada recibe un secreto; el núcleo debe usar la variante sin él.
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "jwtkeyring" && sel.Sel.Name == "Keyfunc" {
				t.Error("s2stoken usa jwtkeyring.Keyfunc (con parámetro de secreto); debe usar RS256Keyfunc")
			}
			return true
		})
	}

	// Config no ofrece ningún lugar donde poner un secreto simétrico.
	ct := reflect.TypeOf(Config{})
	for i := 0; i < ct.NumField(); i++ {
		fld := ct.Field(i)
		if strings.Contains(strings.ToLower(fld.Name), "secret") || fld.Type == reflect.TypeOf([]byte(nil)) {
			t.Errorf("Config.%s (%s) parece un secreto compartido", fld.Name, fld.Type)
		}
	}

	// La Keyfunc nueva no tiene parámetro de secreto: sólo el keyring.
	kt := reflect.TypeOf(jwtkeyring.RS256Keyfunc)
	if kt.NumIn() != 1 || kt.In(0) != reflect.TypeOf((*jwtkeyring.Keyring)(nil)) {
		t.Errorf("RS256Keyfunc tiene firma %s; se espera func(*Keyring) jwt.Keyfunc", kt)
	}
}

// El token de servicio no lleva tenant, usuario ni roles (ADR-006): ni los claims ni el Principal
// tienen dónde exponerlos, aunque un token los traiga de contrabando.
func TestContrato_SinTenantUsuarioNiRoles(t *testing.T) {
	banned := []string{"tenant_id", "tenantid", "tenant", "roles", "act", "user_id", "userid", "email"}
	for _, typ := range []reflect.Type{reflect.TypeOf(Claims{}), reflect.TypeOf(Principal{})} {
		for i := 0; i < typ.NumField(); i++ {
			fld := typ.Field(i)
			tag := strings.Split(fld.Tag.Get("json"), ",")[0]
			for _, b := range banned {
				if strings.EqualFold(fld.Name, b) || strings.EqualFold(tag, b) {
					t.Errorf("%s.%s (json %q) expone tenant/usuario/roles", typ.Name(), fld.Name, tag)
				}
			}
		}
	}
}

// --- Errores tipados: lo que no es credencial válida es 401 aunque ADEMÁS le falte scope o
// namespace. Un 403 delataría a quien no está autenticado qué le falta.

func TestVerify_401TienePrecedenciaSobre403(t *testing.T) {
	f := newFixture(t)
	cfg := f.cfg("stock:reserve") // el token válido no trae stock:reserve → sería 403

	cases := map[string]string{
		"aud ajeno + namespace ajeno + scope faltante": f.service(t, func(c jwt.MapClaims) {
			c["aud"] = "customer-service"
			c["namespace"] = "riotless"
		}),
		"vencido + scope faltante": f.service(t, func(c jwt.MapClaims) {
			c["iat"] = fixedNow.Add(-TTL - time.Hour).Unix()
			c["nbf"] = fixedNow.Add(-TTL - time.Hour).Unix()
			c["exp"] = fixedNow.Add(-time.Hour).Unix()
		}),
		"iss de usuario + namespace ajeno": f.service(t, func(c jwt.MapClaims) {
			c["iss"] = UserIssuer
			c["namespace"] = "riotless"
		}),
		"firma ajena + scope faltante": f.signRS256(t, f.other, f.iamKID, TokenType, validClaims()),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(tok, cfg)
			wantStatus(t, err, 401, ErrUnauthenticated)
			if errors.Is(err, ErrForbidden) {
				t.Fatalf("un 401 no debe envolver también ErrForbidden: %v", err)
			}
		})
	}

	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, func() jwt.MapClaims {
		c := validClaims()
		c["namespace"] = "riotless"
		return c
	}())
	hs.Header["kid"] = f.iamKID
	hs.Header["typ"] = TokenType
	s, err := hs.SignedString([]byte("secreto-compartido-de-test"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(s, cfg)
	wantStatus(t, err, 401, ErrUnauthenticated)
}

func TestVerify_403NoEnvuelve401(t *testing.T) {
	f := newFixture(t)
	_, err := Verify(f.service(t, nil), f.cfg("stock:reserve"))
	wantStatus(t, err, 403, ErrForbidden)
	if errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("un 403 no debe envolver también ErrUnauthenticated: %v", err)
	}
}

// --- RS256 por kid.

func TestVerify_RechazaKidAusenteODesconocido(t *testing.T) {
	f := newFixture(t)
	_, err := Verify(f.signRS256(t, f.iam, "", TokenType, validClaims()), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
	_, err = Verify(f.signRS256(t, f.iam, "acc-000000000000", TokenType, validClaims()), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
}

// Otros algoritmos de la familia RSA, firmados con la clave legítima de iam y su kid: sólo RS256 vale.
func TestVerify_RechazaAlgoritmosRSADistintosDeRS256(t *testing.T) {
	f := newFixture(t)
	for _, m := range []jwt.SigningMethod{
		jwt.SigningMethodRS384, jwt.SigningMethodRS512,
		jwt.SigningMethodPS256, jwt.SigningMethodPS384, jwt.SigningMethodPS512,
	} {
		t.Run(m.Alg(), func(t *testing.T) {
			tok := jwt.NewWithClaims(m, validClaims())
			tok.Header["kid"] = f.iamKID
			tok.Header["typ"] = TokenType
			s, err := tok.SignedString(f.iam)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Verify(s, f.cfg())
			wantStatus(t, err, 401, ErrUnauthenticated)
		})
	}
}

// Rotación (ADR-003/ADR-006): con dos claves en el keyring, vale cualquiera por su propio kid, pero
// el kid tiene que corresponder a la clave que firmó.
func TestVerify_RotacionResuelvePorKid(t *testing.T) {
	keys := make([]*rsa.PrivateKey, 2)
	kids := make([]string, 2)
	dir := t.TempDir()
	for i := range keys {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		keys[i], kids[i] = k, jwtkeyring.KID(&k.PublicKey)
		if err := os.WriteFile(filepath.Join(dir, kids[i]+".pem"),
			pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ring, err := jwtkeyring.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{ring: ring}
	cfg := f.cfg()

	for i := range keys {
		p, err := Verify(f.signRS256(t, keys[i], kids[i], TokenType, validClaims()), cfg)
		if err != nil {
			t.Fatalf("clave %d con su kid debía aceptar: %v", i, err)
		}
		if p.KID != kids[i] {
			t.Fatalf("Principal.KID = %q, se espera %q", p.KID, kids[i])
		}
	}
	// Firmado por la clave 1 declarando el kid de la 0.
	_, err = Verify(f.signRS256(t, keys[1], kids[0], TokenType, validClaims()), cfg)
	wantStatus(t, err, 401, ErrUnauthenticated)
}

// --- exp / iat / vida ≤ TTL.

func TestVerify_VidaExactaTTLValeUnSegundoMasNo(t *testing.T) {
	f := newFixture(t)
	iat := fixedNow.Add(-10 * time.Second)
	if _, err := Verify(f.service(t, func(c jwt.MapClaims) {
		c["iat"], c["nbf"], c["exp"] = iat.Unix(), iat.Unix(), iat.Add(TTL).Unix()
	}), f.cfg()); err != nil {
		t.Fatalf("vida exactamente TTL debía aceptar: %v", err)
	}
	_, err := Verify(f.service(t, func(c jwt.MapClaims) {
		c["iat"], c["nbf"], c["exp"] = iat.Unix(), iat.Unix(), iat.Add(TTL+time.Second).Unix()
	}), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)
}

func TestVerify_IatFuturoFueraDelLeeway(t *testing.T) {
	f := newFixture(t)
	future := fixedNow.Add(2 * time.Minute)
	_, err := Verify(f.service(t, func(c jwt.MapClaims) {
		c["iat"], c["nbf"], c["exp"] = future.Unix(), future.Unix(), future.Add(TTL).Unix()
	}), f.cfg())
	wantStatus(t, err, 401, ErrUnauthenticated)

	// Desfasaje de reloj dentro del leeway: vale.
	skew := fixedNow.Add(Leeway - 5*time.Second)
	if _, err := Verify(f.service(t, func(c jwt.MapClaims) {
		c["iat"], c["nbf"], c["exp"] = skew.Unix(), skew.Unix(), skew.Add(TTL).Unix()
	}), f.cfg()); err != nil {
		t.Fatalf("iat dentro del leeway debía aceptar: %v", err)
	}
}

// Sin Now inyectado usa el reloj real: un token recién emitido vale y uno vencido no.
func TestVerify_RelojPorDefecto(t *testing.T) {
	f := newFixture(t)
	cfg := f.cfg()
	cfg.Now = nil
	now := time.Now()
	fresh := f.service(t, func(c jwt.MapClaims) {
		c["iat"], c["nbf"], c["exp"] = now.Unix(), now.Unix(), now.Add(TTL).Unix()
	})
	if _, err := Verify(fresh, cfg); err != nil {
		t.Fatalf("token recién emitido con reloj real: %v", err)
	}
	old := now.Add(-time.Hour)
	_, err := Verify(f.service(t, func(c jwt.MapClaims) {
		c["iat"], c["nbf"], c["exp"] = old.Unix(), old.Unix(), old.Add(TTL).Unix()
	}), cfg)
	wantStatus(t, err, 401, ErrUnauthenticated)
}

// --- aud / namespace / scope: igualdad exacta.

func TestVerify_AudYNamespaceSonIgualdadExacta(t *testing.T) {
	f := newFixture(t)
	for name, aud := range map[string]string{
		"mayúsculas":         "Stock-Service",
		"espacio final":      "stock-service ",
		"prefijo":            "stock-service-v2",
		"aud de la aserción": AssertionAudience,
	} {
		t.Run("aud "+name, func(t *testing.T) {
			_, err := Verify(f.service(t, func(c jwt.MapClaims) { c["aud"] = aud }), f.cfg())
			wantStatus(t, err, 401, ErrUnauthenticated)
		})
	}
	_, err := Verify(f.service(t, func(c jwt.MapClaims) { c["namespace"] = "MC" }), f.cfg())
	wantStatus(t, err, 403, ErrForbidden)
}

func TestVerify_ExigeTodosLosScopesRequeridos(t *testing.T) {
	f := newFixture(t)
	// Le falta uno de dos.
	_, err := Verify(f.service(t, nil), f.cfg("stock:read", "stock:reserve"))
	wantStatus(t, err, 403, ErrForbidden)
	// scope vacío con una ruta que exige scope.
	_, err = Verify(f.service(t, func(c jwt.MapClaims) { c["scope"] = "" }), f.cfg("stock:read"))
	wantStatus(t, err, 403, ErrForbidden)
	// Un scope con comodín no amplía nada.
	_, err = Verify(f.service(t, func(c jwt.MapClaims) { c["scope"] = "stock:*" }), f.cfg("stock:read"))
	wantStatus(t, err, 403, ErrForbidden)
	// Todos presentes, en otro orden y con espacios extra: vale.
	if _, err := Verify(f.service(t, func(c jwt.MapClaims) { c["scope"] = "  config:read   stock:read " }),
		f.cfg("stock:read", "config:read")); err != nil {
		t.Fatalf("todos los scopes presentes debía aceptar: %v", err)
	}
}

// scope en array (formato OAuth ajeno al contrato) no decodifica: no es un token de servicio válido.
func TestVerify_ScopeMalTipadoEs401(t *testing.T) {
	f := newFixture(t)
	_, err := Verify(f.service(t, func(c jwt.MapClaims) { c["scope"] = []string{"stock:read"} }), f.cfg("stock:read"))
	wantStatus(t, err, 401, ErrUnauthenticated)
}

// --- Entrada que no es un JWT.

func TestVerify_EntradaNoJWT(t *testing.T) {
	f := newFixture(t)
	valid := f.service(t, nil)
	for name, in := range map[string]string{
		"vacío":           "",
		"basura":          "no-es-un-jwt",
		"tres partes":     "a.b.c",
		"con prefijo":     "Bearer " + valid,
		"firma recortada": valid[:strings.LastIndex(valid, ".")+1],
		"firma alterada":  valid[:len(valid)-4] + "AAAA",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(in, f.cfg())
			wantStatus(t, err, 401, ErrUnauthenticated)
		})
	}
}
