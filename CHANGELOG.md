# Changelog

## v0.20.0

- ACC-E09 T3a: nuevo paquete `infrastructure/s2stoken` (sin gin ni `net/http`), núcleo del token de
  servicio S2S de ADR-006 (iam-service `docs/adr`). Define los claims (`aud` string, nunca array) y las
  constantes de contrato que importan iam y los receptores: `Issuer` (`iam-service/s2s`), `UserIssuer`
  (`iam-service`), `TokenUse` (`service`), `TokenType` (`s2s+jwt`), `AssertionAudience`
  (`iam-service/s2s/token`), `IAMAudience` (`account-service`), `TenantScopeUser`/`TenantScopeSystem`,
  `TTL` (300 s) y `Leeway` (30 s).
- `s2stoken.Verify(token, Config) (Principal, error)`: RS256 por `kid` contra el keyring de iam, `typ`,
  `iss`, `token_use`, `exp`/`iat` obligatorios con vida ≤ TTL, `aud` igual al receptor, `sub`/`jti`,
  `tenant_scope`, `namespace` y los scopes que exige la ruta. Errores tipados `ErrUnauthenticated` (401)
  y `ErrForbidden` (403, namespace ajeno o scope insuficiente); `StatusCode(err)` los traduce. Sin rama
  HMAC ni parámetro de secreto. Una `Config` sin keyring, `Audience` o `Namespace` rechaza todo.
  Review L4 de T3a: `RequiredScopes` vacío también rechaza todo salvo `AnyScope: true` explícito (por
  defecto se deniega), `Audience` no puede ser el de la aserción de iam y el parser usa decodificación
  estricta.
- `jwtkeyring.RS256Keyfunc(ring)`: la regla RS256-only sin parámetro de secreto. `Keyfunc(secret, ring)`
  queda Deprecated (delega en ella); `ParseDual` la usa internamente. Sin cambio de comportamiento.
- Compatible: ningún verificador existente cambia. El rechazo de `token_use=service` en los verificadores
  de usuario (`TenantValidation`, `VerifyPlatformJWT`) llega en T3.

## v0.19.0

- ACC-E03 T6: corte de HS256. `TenantValidation`, `VerifyPlatformJWT` y `jwtkeyring.Keyfunc/ParseDual`
  aceptan SÓLO RS256 con la pública cuyo `kid` está en el keyring (`JWT_PUBLIC_KEY_DIR`). Un token HS256
  (aun firmado con el secreto de la flota), `alg:none` u otro algoritmo -> 401.
- `JWTSecret` pasa a ser opcional e ignorado en `TenantValidationConfig` y `PlatformAuthConfig`
  (Deprecated; se conserva el campo para no romper la compilación de los consumidores).
  `TenantValidation` ya no hace panic con `JWT_SECRET` vacío.
- **Incompatible en operación:** todo emisor que firme HS256 deja de ser aceptado por la flota.
  El keyring sigue siendo obligatorio (mismo fail-closed que v0.18.0).

## v0.18.0

- ACC-E03 T5b: aceptación dual en la ventana de cutover a firma asimétrica (ADR-003 §f, addendum T5a).
  `TenantValidation` y `VerifyPlatformJWT` verifican HS256 con el secreto legacy y RS256 con la
  pública cuyo `kid` está en el keyring (`JWT_PUBLIC_KEY_DIR`, un `*.pem` por clave pública RSA >=2048;
  el `kid` se deriva del thumbprint RFC 7638, `acc-<12 hex>`, igual que iam-service). `alg:none`,
  HS384/HS512 y cualquier otro algoritmo se rechazan; kid desconocido -> 401.
- Nuevo paquete `infrastructure/jwtkeyring` (sin gin): `Load`, `Resolve`, `KID`, `Keyfunc`,
  `ParseDual`. Lo consumen los verificadores propios de la flota (webdata, catalog) en lugar de copiarlo.
- **Incompatible en operación:** con `GIN_MODE=release` y sin `JWT_PUBLIC_KEY_DIR`, `TenantValidation`
  y `VerifyPlatformJWT` hacen panic al construirse. Un directorio configurado que no carga (vacío,
  PEM inválido, kid duplicado, clave no RSA o <2048 bits) tampoco arranca, en cualquier modo.
  `JWTSecret` sigue siendo obligatorio en `TenantValidation` hasta T6.
- `VerifyPlatformJWT` con `JWTSecret` vacío ya no acepta HS256 firmado con clave vacía.

## v0.17.0

- `TenantValidation` ahora falla durante la construcción si `JWT_SECRET` está vacío. Este cambio es
  intencionalmente incompatible en operación: un servicio sin el secreto configurado ya no arranca,
  en lugar de aceptar tokens HS256 firmados con una clave vacía.
