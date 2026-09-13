# Changelog

## v0.17.0

- `TenantValidation` ahora falla durante la construcción si `JWT_SECRET` está vacío. Este cambio es
  intencionalmente incompatible en operación: un servicio sin el secreto configurado ya no arranca,
  en lugar de aceptar tokens HS256 firmados con una clave vacía.
