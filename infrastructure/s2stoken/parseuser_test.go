package s2stoken_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hornosg/go-shared/infrastructure/s2stoken"
	"github.com/hornosg/go-shared/infrastructure/s2stoken/s2stest"
)

// claimsPropios imita el struct de webdata: no declara token_use ni iss, así que el contrato tiene
// que aplicarse sobre el payload completo y no sobre lo que el struct conoce (N-1).
type claimsPropios struct {
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

func TestParseUser(t *testing.T) {
	iam := s2stest.NewIAM(t)
	user := iam.SignUser(t, s2stest.UserClaims("u-1", "T1", "admin"))
	sinIss := s2stest.UserClaims("u-1", "T1")
	delete(sinIss, "iss")
	svc := iam.SignService(t, s2stest.ServiceClaims("sales", "webdata-service", "user", "webdata:read"))
	disfrazado := s2stest.UserClaims("u-1", "T1")
	disfrazado["token_use"] = "service"
	sinExp := s2stest.UserClaims("u-1", "T1")
	delete(sinExp, "exp")
	hs, err := jwt.NewWithClaims(jwt.SigningMethodHS256, s2stest.UserClaims("u-1", "T1")).SignedString([]byte("JWT_SECRET"))
	if err != nil {
		t.Fatal(err)
	}
	ajeno := s2stest.NewIAM(t).SignUser(t, s2stest.UserClaims("u-1", "T1"))

	for _, newClaims := range map[string]func() jwt.Claims{
		"map":    func() jwt.Claims { return jwt.MapClaims{} },
		"struct": func() jwt.Claims { return &claimsPropios{} },
	} {
		if err := s2stoken.ParseUser(user, newClaims(), iam.Keyring); err != nil {
			t.Fatalf("token de usuario válido rechazado: %v", err)
		}
		for name, tok := range map[string]string{
			"token de servicio":       svc,
			"usuario sin iss":         iam.SignUser(t, sinIss),
			"token_use=service":       iam.SignUser(t, disfrazado),
			"sin exp":                 iam.SignUser(t, sinExp),
			"HS256":                   hs,
			"clave fuera del keyring": ajeno,
		} {
			err := s2stoken.ParseUser(tok, newClaims(), iam.Keyring)
			if !errors.Is(err, s2stoken.ErrUnauthenticated) {
				t.Fatalf("%s: err = %v, se espera ErrUnauthenticated", name, err)
			}
		}
	}
	if err := s2stoken.ParseUser(user, jwt.MapClaims{}, nil); !errors.Is(err, s2stoken.ErrUnauthenticated) {
		t.Fatalf("keyring nil: err = %v", err)
	}
}

// mentiroso imita un struct propio que mapea GetExpirationTime a otro lado: el parser creería que el
// token vence en una hora aunque el payload diga que ya venció (C-1 de la revisión L4 de T3b).
type mentiroso struct{ jwt.RegisteredClaims }

func (mentiroso) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Now().Add(time.Hour)), nil
}

func TestParseUser_ExpSeCompruebaSobreElPayload(t *testing.T) {
	iam := s2stest.NewIAM(t)
	vencido := s2stest.UserClaims("u-1", "T1")
	vencido["exp"] = time.Now().Add(-time.Hour).Unix()
	tok := iam.SignUser(t, vencido)
	if err := s2stoken.ParseUser(tok, jwt.MapClaims{}, iam.Keyring); !errors.Is(err, s2stoken.ErrUnauthenticated) {
		t.Fatalf("token vencido aceptado: %v", err)
	}
	if err := s2stoken.ParseUser(tok, &mentiroso{}, iam.Keyring); !errors.Is(err, s2stoken.ErrUnauthenticated) {
		t.Fatalf("un struct que miente sobre el exp saltea la comprobación: %v", err)
	}
}

func TestParseUser_AlgNoneRechazado(t *testing.T) {
	iam := s2stest.NewIAM(t)
	tok, err := jwt.NewWithClaims(jwt.SigningMethodNone, s2stest.UserClaims("u-1", "T1")).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2stoken.ParseUser(tok, jwt.MapClaims{}, iam.Keyring); !errors.Is(err, s2stoken.ErrUnauthenticated) {
		t.Fatalf("alg none aceptado: %v", err)
	}
}

func TestSingleHeader(t *testing.T) {
	h := map[string][]string{"Authorization": {"a", "b"}, "X-Tenant-Id": {"T1"}}
	if _, ok := s2stoken.SingleHeader(h, "authorization"); ok {
		t.Fatal("Authorization repetido aceptado")
	}
	if v, ok := s2stoken.SingleHeader(h, s2stoken.HeaderTenantID); !ok || v != "T1" {
		t.Fatalf("X-Tenant-ID = %q,%v", v, ok)
	}
	if v, ok := s2stoken.SingleHeader(h, "X-Ausente"); !ok || v != "" {
		t.Fatalf("ausente = %q,%v", v, ok)
	}
}
