# go-shared

Kernel compartido en Go para una plataforma SaaS multi-tenant de microservicios. Concentra los contratos transversales —observabilidad, persistencia, rate limiting, middleware HTTP y primitivas de dominio— para que cada servicio los consuma como dependencia versionada en lugar de reimplementarlos.

```
module github.com/hornosg/go-shared   ·   Go 1.25   ·   SemVer (último: v0.12.0)
```

Diseñado bajo arquitectura hexagonal: el paquete expone **puertos** y **adapters** listos para inyectar, sin acoplar a los servicios consumidores. Es la base sobre la que corren 12+ microservicios Go del ecosistema [mercado-cercano](https://github.com/mercadocercano).

## Por qué existe

En un ecosistema de microservicios, las decisiones transversales (cómo se loguea, cómo se conecta a Postgres, cómo se valida un tenant, cómo se responde un error) tienden a divergir servicio por servicio. `go-shared` las fija una vez, las versiona con SemVer y las distribuye: un cambio de contrato se propaga de forma controlada vía bump de versión, no por copia-pega.

## Paquetes

### `infrastructure/`

| Paquete | Qué provee |
|---------|------------|
| `env` | Lectura tipada de variables de entorno con defaults: `Get`, `GetInt`, `GetBool`, `GetDuration`. |
| `postgres` | `Connect(Config)` con pool de conexiones y defaults sanos (`WithDefaults`), más `MonitorOptions` para instrumentar saturación del pool. |
| `logging` | `CanonicalLogger` — un evento canónico por request en JSON estructurado (envelope común a toda la flota, ver ADR-001 de los servicios). Incluye `SecurityLogger` para eventos de seguridad. |
| `metrics` | `PrometheusRecorder` (y `NoopRecorder` para tests) — recorder inyectable de métricas RED. |
| `middleware` | Middleware Gin reutilizable: compresión Gzip condicional, validación de tenant con soporte de namespace, y configuración de rate limiting (`RateLimitConfig`, `LimitsProvider`). |
| `ratelimit` | `Limiter` con implementación `RedisLimiter` (sliding window) y `Decision` — rate limiting multinivel por tenant/plan. |
| `response` | Respuestas HTTP consistentes: `ErrorResponse`, `JSON`, `NewError`, `Abort` — contrato de error uniforme entre servicios. |
| `config` · `adapters` · `notifications` | Configuración compartida, adapters de infraestructura y puertos de notificación. |

### `domain/`

Primitivas de dominio compartidas entre servicios: `businesstype` y `category` (taxonomía del catálogo), `port` (interfaces de dominio), `service` (servicios de dominio sin estado). Permite que reglas de negocio transversales —como la clasificación de rubros— vivan en un solo lugar.

### `criteria/`

Patrón Criteria/Specification para construir queries de forma declarativa y testeable, desacoplada del driver de base de datos.

## Uso

```bash
go get github.com/hornosg/go-shared@v0.12.0
```

```go
import (
    "github.com/hornosg/go-shared/infrastructure/env"
    "github.com/hornosg/go-shared/infrastructure/postgres"
    "github.com/hornosg/go-shared/infrastructure/logging"
)

// Variables de entorno tipadas
port := env.GetInt("HTTP_PORT", 8080)

// Pool de Postgres con defaults
db, err := postgres.Connect(postgres.Config{
    DSN: env.Get("DATABASE_URL", ""),
}.WithDefaults())

// Logger canónico (un evento por request)
logger := logging.NewCanonicalLogger("pim-service")
```

## Versionado

SemVer estricto. Los servicios consumidores fijan la versión en su `go.mod` y migran de forma deliberada. Un cambio de contrato se publica como nueva versión y se adopta servicio por servicio.

## Estado

Cobertura de tests: ~55%, concentrada en la lógica con mayor riesgo (parsing de env, rate limiting, response, postgres DSN/pool). Es infraestructura de producción consumida por todo el ecosistema.

---

Parte del ecosistema [mercado-cercano](https://github.com/mercadocercano) · Licencia MIT
