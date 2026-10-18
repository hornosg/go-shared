# Changelog

## v0.21.0

- ACC-E09 T3 (ADR-006 de iam-service): cliente emisor, combinador receptor y adaptadores del token de
  servicio S2S. Sin rama HMAC ni parámetro de secreto compartido.
- **Incompatible para tokens de usuario sin `iss`:** `TenantValidation` y `VerifyPlatformJWT` aplican
  `s2stoken.CheckUserClaims`: rechazan con 401 un token con `token_use` (el de servicio, aunque lo firme
  la misma clave de iam) y exigen `iss=iam-service`. Los tokens reales de iam lo llevan desde
  `63a0329` (2026-09-04); los fixtures de test de cada consumidor tienen que agregarlo (T3b).
- `s2stoken`: `CheckUserClaims`, `RedactHeaders` (redacta `Authorization`, `X-Service-Token`,
  `X-Api-Key`, cookies) y las constantes `HeaderServiceToken`/`HeaderTenantID`. Sigue sin gin ni
  `net/http`.
- `s2stoken/receiver` (sin gin ni `net/http`): `Authenticate(cfg, X-Service-Token, Authorization,
  X-Tenant-ID)` aplica `S2S_DENY_SUB` → `Verify` → denegación por `sub` → `tenant_scope` permitido por
  la ruta (C-1: `AllowUser`; `System` = `SystemDenied` por defecto | `SystemGlobal` | `SystemPerTenant`;
  `SystemOnlyScopes` con token `user` → 403) → regla de `X-Tenant-ID` de ADR-006 (token `user`: Bearer
  ausente o inválido 401, Bearer sin `tenant_id` 403 sin importar `RejectMissingTenant`, header ausente
  → se usa el tenant del Bearer, header distinto → 403 + log `s2s_tenant_mismatch`; token `system`: el
  Bearer se ignora). `ParseDenySub`: un valor no parseable rechaza todo token de servicio y mantiene el
  tráfico de usuarios. `VerifyUser` para receptores sin middleware propio.
- `middleware/s2sauth` (gin) y `s2stoken/s2shttp` (`net/http`, para webdata): el combinador decide por la
  presencia de `X-Service-Token`; sin él rige la credencial heredada que se le pase (nil → 401); con él
  y un token inválido → 401 **sin** caer a la heredada. Respuesta genérica sólo con
  `StatusCode` (C-2); logs estructurados con slog, nunca el token; `s2s_auth=token|legacy_key`.
- `s2stoken/client`: `LoadPrivateKey`, `New(Config)`, `Token(ctx, aud, scopes...)` con caché por
  `(aud, scope)` renovado a los `exp − 60 s`, `Invalidate`, timeout (5 s), circuit breaker (5 fallos
  consecutivos, 30 s abierto, medio abierto después; con el circuito abierto devuelve el token cacheado
  aún vigente o `ErrCircuitOpen`), métrica `s2s_token_issue_errors_total{aud,reason}`, `Transport`
  (pone `X-Service-Token` y re-emite una sola vez ante 401) y `ModeFor(destino)` sobre
  `S2S_MODE_<DESTINO>=token|legacy` (ausente → legacy; otro valor → error).
- `s2stoken/s2stest`: fixtures RS256 (clave efímera de iam, keyring, tokens de servicio y de usuario)
  para los tests de la flota.
- Review L4 de T3 (O-1..O-3, N-3): el combinador decide por **presencia** del header (`X-Service-Token`
  vacío o repetido → 401, nunca la heredada); `client.Transport` no adjunta el token a una redirección
  (`req.Response != nil`) y el cliente de emisión no sigue redirecciones (`CheckRedirect` →
  `ErrUseLastResponse`); un 401 del receptor ya no descarta a ciegas el token: `Client.Refresh` es
  single-flight y no re-emite un token más joven que `MinReissueAge` (30 s); el circuito es **por aud**,
  sólo cuentan transporte, 5xx, 429 y respuesta ilegible (no los 4xx permanentes ni la cancelación del
  request, que ahora tampoco cuelga la emisión), y un 4xx de iam aplica `DefaultRetryBackoff` (5 s);
  `SystemPerTenant` valida que `X-Tenant-ID` sea un UUID canónico (36 caracteres) y lo normaliza.
  `Client.Refresh` fuerza la renovación sin vaciar la entrada: con iam caído el token vigente sigue
  sirviendo hasta su `exp`.

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
