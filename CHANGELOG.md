# Changelog

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
