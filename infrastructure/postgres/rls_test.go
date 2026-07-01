package postgres

import (
	"context"
	"testing"

	_ "github.com/lib/pq"
)

func TestSetRLSContextTx_RejectsMalformedValues(t *testing.T) {
	cases := []struct {
		name string
		rc   RLSContext
	}{
		{"tenant_id con comilla", RLSContext{TenantID: "abc'; DROP TABLE x; --"}},
		{"namespace con espacio y punto y coma", RLSContext{Namespace: "mc; SELECT 1"}},
		{"role con espacio", RLSContext{Role: "system admin"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := SetRLSContextTx(context.Background(), nil, tc.rc)
			if err == nil {
				t.Fatalf("esperaba error de validación para %+v", tc.rc)
			}
		})
	}
}

func TestSetRLSContextTx_AcceptsWellFormedValues(t *testing.T) {
	rc := RLSContext{
		TenantID:  "11111111-1111-1111-1111-111111111111",
		Namespace: "mc",
		Role:      "system_admin",
	}
	if !safeGUCValue.MatchString(rc.TenantID) || !safeGUCValue.MatchString(rc.Namespace) || !safeGUCValue.MatchString(rc.Role) {
		t.Fatal("valores bien formados no deberían fallar la validación de forma")
	}
}

func TestQuoteLiteral_EscapesSingleQuotes(t *testing.T) {
	got := quoteLiteral("o'brien")
	want := "'o''brien'"
	if got != want {
		t.Fatalf("quoteLiteral() = %q, want %q", got, want)
	}
}
