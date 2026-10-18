package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hornosg/go-shared/infrastructure/s2stoken"
)

// ACC-E09 T3: los verificadores de usuario rechazan el token de servicio y exigen iss=iam-service,
// aunque el token esté firmado por la misma clave de iam.
func TestVerificadoresDeUsuario_RechazanTokenDeServicioEIssAjeno(t *testing.T) {
	gin.SetMode(gin.TestMode)
	exp := time.Now().Add(time.Hour).Unix()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"tenant_id": "T1", "user_id": "u", "namespace": "mc", "roles": []string{"system_admin"}, "exp": exp}
	}
	tv := gin.New()
	tv.GET("/t", TenantValidation(TenantValidationConfig{JWTPublicKeyDir: fixtureKeyringDir(), Namespace: "mc"}), func(c *gin.Context) { c.Status(200) })
	pa := gin.New()
	pa.GET("/p", VerifyPlatformJWT(PlatformAuthConfig{JWTPublicKeyDir: fixtureKeyringDir(), Namespace: "mc"}), func(c *gin.Context) { c.Status(200) })

	cases := map[string]struct {
		mutate func(jwt.MapClaims)
		want   int
	}{
		"usuario válido":    {func(c jwt.MapClaims) { c["iss"] = s2stoken.UserIssuer }, 200},
		"token_use=service": {func(c jwt.MapClaims) { c["iss"] = s2stoken.UserIssuer; c["token_use"] = s2stoken.TokenUse }, 401},
		"token de servicio entero": {func(c jwt.MapClaims) {
			c["iss"] = s2stoken.Issuer
			c["token_use"] = s2stoken.TokenUse
			c["tenant_scope"] = "system"
		}, 401},
		"sin iss":   {func(c jwt.MapClaims) {}, 401},
		"iss ajeno": {func(c jwt.MapClaims) { c["iss"] = "otro" }, 401},
	}
	for name, tc := range cases {
		claims := base()
		tc.mutate(claims)
		tok, err := signFixtureRaw(claims)
		if err != nil {
			t.Fatal(err)
		}
		for path, r := range map[string]*gin.Engine{"/t": tv, "/p": pa} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("X-Tenant-ID", "T1")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Errorf("%s en %s: %d, se espera %d", name, path, w.Code, tc.want)
			}
		}
	}
}
