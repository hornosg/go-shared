package s2stoken

import (
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestCheckUserClaims(t *testing.T) {
	cases := map[string]struct {
		claims jwt.MapClaims
		ok     bool
	}{
		"usuario válido":        {jwt.MapClaims{"iss": UserIssuer}, true},
		"token de servicio":     {jwt.MapClaims{"iss": UserIssuer, "token_use": TokenUse}, false},
		"token_use desconocido": {jwt.MapClaims{"iss": UserIssuer, "token_use": "x"}, false},
		"token_use no string":   {jwt.MapClaims{"iss": UserIssuer, "token_use": 1}, false},
		"iss de servicio":       {jwt.MapClaims{"iss": Issuer}, false},
		"sin iss":               {jwt.MapClaims{}, false},
		"iss ajeno":             {jwt.MapClaims{"iss": "evil"}, false},
	}
	for name, tc := range cases {
		err := CheckUserClaims(tc.claims)
		if (err == nil) != tc.ok || (err != nil && StatusCode(err) != 401) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

func TestRedactHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Service-Token", "secreto-svc")
	h.Set("Authorization", "Bearer secreto-user")
	h.Set("X-Tenant-ID", "T1")
	out := http.Header(RedactHeaders(h))
	if out.Get("X-Service-Token") != "[REDACTED]" || out.Get("Authorization") != "[REDACTED]" || out.Get("X-Tenant-ID") != "T1" {
		t.Fatalf("redacción incorrecta: %v", out)
	}
	if h.Get("X-Service-Token") != "secreto-svc" {
		t.Fatal("RedactHeaders modificó el original")
	}
	if got := RedactHeaders(map[string][]string{"x-service-token": {"s"}}); got["x-service-token"][0] != "[REDACTED]" {
		t.Fatal("la redacción debe ignorar mayúsculas")
	}
}
