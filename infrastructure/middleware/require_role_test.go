package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func init() { gin.SetMode(gin.TestMode) }

// newCtxWithClaims arma un contexto Gin con jwt_claims preseteados (simula lo que deja
// TenantValidation) para testear RequireRole/RequirePermission en aislamiento.
func runWithClaims(mw gin.HandlerFunc, claims jwt.MapClaims, setRoles bool) int {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if claims != nil {
		c.Set("jwt_claims", claims)
		if setRoles {
			c.Set("roles", stringSliceClaim(claims, "roles"))
		}
	}
	reached := false
	mw(c)
	if !c.IsAborted() {
		reached = true
	}
	if reached {
		return http.StatusOK
	}
	return w.Code
}

func TestRequireRole(t *testing.T) {
	cases := []struct {
		name    string
		claims  jwt.MapClaims
		allowed []string
		want    int
	}{
		{"rol permitido pasa", jwt.MapClaims{"roles": []interface{}{"cashier"}}, []string{"cashier", "supervisor"}, http.StatusOK},
		{"rol no permitido → 403", jwt.MapClaims{"roles": []interface{}{"cashier"}}, []string{"supervisor"}, http.StatusForbidden},
		{"sin roles → 403", jwt.MapClaims{"roles": []interface{}{}}, []string{"supervisor"}, http.StatusForbidden},
		{"claim roles ausente → 403", jwt.MapClaims{}, []string{"supervisor"}, http.StatusForbidden},
		{"sin jwt_claims (fail-closed) → 403", nil, []string{"cashier"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runWithClaims(RequireRole(tc.allowed...), tc.claims, false)
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRequireRole_ReadsRolesContextKey(t *testing.T) {
	// Cuando TenantValidation ya dejó "roles" en contexto, RequireRole lo usa.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Set("roles", []string{"supervisor"})
	RequireRole("supervisor")(c)
	if c.IsAborted() {
		t.Fatalf("esperaba pasar con roles en contexto, abortó con %d", w.Code)
	}
}

func TestRequirePermission(t *testing.T) {
	cases := []struct {
		name    string
		claims  jwt.MapClaims
		allowed []string
		want    int
	}{
		{"permiso exacto pasa", jwt.MapClaims{"perms": []interface{}{"sales:pos:sell"}}, []string{"sales:pos:sell"}, http.StatusOK},
		{"comodín * pasa cualquier permiso", jwt.MapClaims{"perms": []interface{}{"*"}}, []string{"sales:cash_session:open"}, http.StatusOK},
		{"permiso faltante → 403", jwt.MapClaims{"perms": []interface{}{"sales:pos:sell"}}, []string{"sales:cash_session:close"}, http.StatusForbidden},
		{"sin perms → 403", jwt.MapClaims{}, []string{"x"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runWithClaims(RequirePermission(tc.allowed...), tc.claims, false)
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// C3: el comodín "*" NO debe usarse para autorizar approve_review. Este test documenta
// que la protección correcta es RequireRole("supervisor") exacto, donde un admin con
// perms ["*"] pero rol "tenant_admin" queda fuera.
func TestApproveReview_AdminWildcardDoesNotBypassRoleGate(t *testing.T) {
	adminClaims := jwt.MapClaims{"roles": []interface{}{"tenant_admin"}, "perms": []interface{}{"*"}}
	got := runWithClaims(RequireRole("supervisor"), adminClaims, false)
	if got != http.StatusForbidden {
		t.Errorf("un admin con perms=* pero sin rol supervisor NO debe aprobar descuadres; got %d", got)
	}
}
