---
adr: ADR-001
status: accepted
scope: fleet
skills:
  implement:
    - dev/hexagonal-go
    - dev/postgres-data-modeling
  verify:
    - dev/code-reviewer
    - dev/postgres-data-modeling
---

# ADR-001: Migraciones versionadas estandarizadas con golang-migrate embebido en go-shared

**Estado**: Aceptado
**Fecha**: 2026-06-19
**Deciders**: @architect
**Alcance**: Flota Go completa del ecosistema mercado-cercano (`iam`, `sales`, `stock`, `tenant`, `customer`, `ledger`, `payment-method`, `webdata`, `pim`, `onboarding`, `notification`). `commerce-ai-service` (Python/Alembic) queda fuera de scope.

**Contexto**: No existe una forma única de aplicar migraciones en la flota Go. Cada servicio resuelve el problema a su manera y eso se volvió un riesgo de producción concreto:

- **Inconsistencia fleet-wide**: hay migradores caseros divergentes (`onboarding-service`, `notification-service` cada uno con su propio runner), servicios que ejecutan SQL por script externo (`./scripts/migrate.sh`, `migrate.sh up`, `make migrate`) y servicios sin runner reproducible. Los caseros **no tienen locking** (dos instancias arrancando en paralelo pueden correr la misma migración dos veces), **no embeben los `.sql`** (dependen de que la carpeta `migrations/` viaje junto al binario en el contenedor) y **no llevan registro de versión confiable**.
- **Numeración inconsistente entre servicios**: conviven `NNN_*` cortos, timestamps `YYYYMMDD*` y colisiones reales de número. `pim-service` es el caso extremo: mezcla `001..045`, `202412180001..`, `20260425000001..` y tres archivos `014_*` distintos. Sin una versión lineal confiable, ningún runner puede decidir con certeza qué falta aplicar.
- **`.down.sql` parcial**: algunos servicios traen down, otros no. No hay forma estándar de revertir.
- **Seeds mezclados con DDL**: hay seeds estructurales (`iam/006_seed_system_data`, `onboarding/002_seed_step_definitions`) en la misma serie que seeds de demo/E2E (`tenant/002_seed_initial_data`, `sales/012_seed_document_sequences_demo`). Aplicar la serie completa en prod **contamina prod con data de demo**.
- **Deploy de `webdata-service` en rojo**: el deploy a producción está bloqueado porque no hay un mecanismo confiable y embebido para llevar la DB de prod al schema esperado. Este es el detonante urgente: `webdata` necesita arrancar en prod aplicando sus migraciones de forma autocontenida, sin depender de scripts manuales fuera del binario.

## Decisión

Adoptamos **[golang-migrate](https://github.com/golang-migrate/migrate)** como motor único de migraciones para toda la flota Go, **embebido in-app** vía `//go:embed migrations/*.sql`, envuelto por un **helper mínimo en `go-shared`** e **invocado desde `main.go` ANTES de levantar el HTTP server**. Si las migraciones fallan, el proceso aborta y el server no arranca (fail-fast).

El motor se elige por encima de cualquier runner casero porque trae lo que los caseros no tienen: **advisory lock nativo de PostgreSQL** (sólo una instancia migra a la vez), tabla `schema_migrations` con control de versión y estado `dirty`, drivers `iofs` (lee de un `embed.FS`) + `postgres`, y soporte de `force` para baselining.

La decisión se materializa en los cinco parámetros siguientes, todos normativos.

### Parámetro 1 — `.down.sql` obligatorio

Toda **migración nueva** debe incluir su par `.down.sql`. No se acepta un `.up.sql` sin down.

Para las **migraciones históricas sin down**, se completa el faltante con este criterio fino:

- **Down real** cuando revertir es trivial y seguro: la up sólo hace DDL aditivo o estructural reversible sin pérdida de datos (`CREATE TABLE` → `DROP TABLE`, `ADD COLUMN` → `DROP COLUMN`, `CREATE INDEX` → `DROP INDEX`).
- **Down explícito que falla** cuando revertir es peligroso o no determinístico. El archivo `.down.sql` existe (la serie queda completa y golang-migrate puede recorrerla) pero su único contenido es abortar con un mensaje claro. Aplica a:
  - migraciones de **datos** (backfills, `UPDATE`/`DELETE` masivos, limpiezas) donde no se puede reconstruir el estado previo — ej. `webdata/006_update_extraction_schemas` (reescribe `extraction_schema` de cada source), `webdata/017_cleanup_duplicate_and_inactive_sources`, `webdata/020_backfill_business_types_*`;
  - `DROP`/`ALTER` destructivos donde el down recrearía la estructura pero **no** los datos.

  Forma del down "no soportado":
  ```sql
  -- Down no soportado: esta migración modifica/elimina datos de forma no reversible.
  -- Revertir requiere restaurar desde backup. Ver ADR-001 (go-shared).
  DO $$ BEGIN
    RAISE EXCEPTION 'irreversible migration: down no soportado (ver ADR-001)';
  END $$;
  ```

Regla práctica: el down nunca queda vacío ni ausente. O revierte de verdad, o falla a propósito explicando por qué.

### Parámetro 2 — Baseline del schema existente vía `migrate force <V>`

Las bases que ya están en producción no se recrean: se **adoptan** declarando su versión actual con `migrate force <V>`, que escribe `V` en `schema_migrations` sin ejecutar SQL. A partir de ahí golang-migrate sólo aplica lo posterior a `V`.

`V` **no se adivina**: es un paso mecánico verificable. Se inventaría qué tablas/columnas/índices existen hoy en la DB de prod y se mapea ese estado a la última migración que los creó. `V` = el número de esa migración. Si el inventario no cuadra exactamente con ninguna migración (estado intermedio aplicado a mano), primero se reconcilia el schema hasta que coincida, y recién entonces se hace el `force`.

Casos de la flota:

- **`webdata` = caso fácil**: tablas con numeración limpia. Se inventaría, se mapea a su `V`, se hace `force <V>` y queda listo para deploy. Es el primero del rollout por ser el desbloqueante.
- **`pim` = caso difícil**: numeración corrupta (cortos + timestamps + colisiones `014_*`). **No** se hace baseline sobre esa numeración. Primero se **renumera** toda la serie a `NNNNNN_*` lineal (parámetro 3), recién después se calcula `V` sobre la serie renumerada y se hace el `force`. Por eso `pim` va **último** entre los que llevan baseline.

### Parámetro 3 — Naming

Formato único, obligatorio para todo archivo nuevo y para todo lo renumerado:

```
NNNNNN_descripcion.up.sql
NNNNNN_descripcion.down.sql
```

- `NNNNNN`: secuencia numérica con padding a 6 dígitos (`000001`, `000002`, …), lineal y sin huecos en lo nuevo.
- `descripcion`: snake_case, en verbo+objeto (`create_orders_table`, `add_status_to_sales`).
- Siempre el par `.up.sql` / `.down.sql`.

Se abandonan los timestamps `YYYYMMDD*` y la numeración corta `NNN_`. La renumeración masiva sólo es obligatoria donde la serie está rota (`pim`); los servicios con `NNN_*` limpio pueden re-paddear a 6 dígitos de forma trivial al adoptar el helper.

### Parámetro 4 — Seeds separados por familia

Se distinguen dos familias de seed con destino distinto:

- **(a) Estructurales / de referencia** — data que el dominio necesita para funcionar (catálogos de referencia, definiciones de pasos, datos de sistema). Ej.: `iam/006_seed_system_data`, `onboarding/002_seed_step_definitions`.
  → Van como **migración versionada normal** en `migrations/`, **idempotentes** (`INSERT ... ON CONFLICT DO NOTHING` / upsert por clave natural). **Corren en prod**.

- **(b) Demo / E2E** — data de ejemplo para desarrollo y pruebas, que **no debe existir en prod**. Ej.: `tenant/002_seed_initial_data`, `sales/012_seed_document_sequences_demo`.
  → Se **sacan de `migrations/`** y se mueven a una carpeta aparte: **`seeds/dev/`** dentro de cada servicio. Esa carpeta **no** la consume el helper en el arranque normal; se aplica sólo en local y en el harness E2E (por script o por una bandera explícita de entorno). **No corre en prod.**

Razón: evitar contaminar prod con data de demo, que es exactamente lo que hoy puede pasar al aplicar la serie completa.

Path elegido: `seeds/dev/` (hermano de `migrations/`, nombre que deja explícito el destino "no-prod"). Alternativa equivalente descartada por menos legible: `testdata/`.

### Parámetro 5 — Statements no transaccionales

golang-migrate corre, por defecto, **una transacción por migración**. Hoy ese default alcanza para toda la flota: se verificó que **no existe ningún statement no transaccional** (cero `CREATE INDEX CONCURRENTLY`, `VACUUM`, `REINDEX`, `ALTER TYPE ... ADD VALUE`). Por lo tanto no se cambia nada del modo de ejecución ahora.

Regla a futuro (deja sentado el cómo, sin acción inmediata): si alguna vez se necesita un statement que no puede correr dentro de una transacción (caso típico: `CREATE INDEX CONCURRENTLY`), ese statement va **solo en su propio archivo de migración**, marcado para correr **fuera de transacción**. No se mezcla DDL transaccional con no transaccional en el mismo archivo.

## El helper en go-shared

Vive en `libs/go-shared/migrate/migrate.go`. Es deliberadamente mínimo: arma el driver `iofs` desde el `embed.FS` del servicio, arma el driver `postgres` desde el `*sql.DB` ya abierto (reusa el pool del servicio, no abre conexión nueva) y aplica `Up()`. Es idempotente y seguro ante arranque concurrente gracias al advisory lock de golang-migrate.

Firma única:

```go
package migrate

import "database/sql"
import "embed"

// RunMigrations aplica todas las migraciones pendientes embebidas en fsys
// contra db, usando el advisory lock de PostgreSQL. Es idempotente: si no hay
// nada pendiente, no hace nada. Devuelve error si alguna migración falla
// (el caller debe abortar el arranque).
//
//   db     — pool ya abierto y verificado por el servicio.
//   fsys   — embed.FS que contiene migrations/*.sql (NNNNNN_*.up.sql / .down.sql).
//   dbName — nombre de la base; sólo para logging/diagnóstico.
func RunMigrations(db *sql.DB, fsys embed.FS, dbName string) error
```

Internamente usa los drivers `github.com/golang-migrate/migrate/v4/source/iofs` y `github.com/golang-migrate/migrate/v4/database/postgres`. El módulo de go-shared es `github.com/hornosg/go-shared`, por lo que el import efectivo del helper es `github.com/hornosg/go-shared/migrate`.

### Ejemplo de uso desde `main.go`

Cada servicio embebe su propia carpeta `migrations/` y llama al helper inmediatamente después de abrir el pool y antes de construir el router / levantar el server. Adaptado del `cmd/api/main.go` de `webdata-service`:

```go
package main

import (
	"context"
	"embed"
	"fmt"
	"os"

	"github.com/hornosg/go-shared/infrastructure/postgres"
	"github.com/hornosg/go-shared/migrate"
	// ... resto de imports del servicio
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func main() {
	// ... lectura de env (dbHost, dbPort, dbUser, dbPass, dbName, etc.)

	db, err := database.NewPostgresDB(dbHost, dbPort, dbUser, dbPass, dbName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database connection failed: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Migraciones ANTES de levantar el server. Fail-fast: si fallan, no arranca.
	if err := migrate.RunMigrations(db, migrationsFS, dbName); err != nil {
		fmt.Fprintf(os.Stderr, "migrations failed: %v\n", err)
		os.Exit(1)
	}

	postgres.StartPoolMonitor(context.Background(), db, postgres.MonitorOptions{
		Service: "webdata-service",
		DBName:  dbName,
	})

	// ... DI wiring, router y srv.ListenAndServe() como hoy
}
```

El `//go:embed migrations/*.sql` exige que la directiva esté en el mismo paquete `main` y que la carpeta `migrations/` sea hermana del archivo que la declara. Esto hace al binario **autocontenido**: las migraciones viajan dentro del ejecutable, sin depender de que la carpeta exista en el contenedor de prod — que es precisamente lo que desbloquea el deploy de `webdata`.

## Plan de rollout

Orden deliberado: primero el desbloqueante, después los de numeración limpia, después el corrupto, y al final los caseros que hay que reemplazar.

1. **`go-shared/migrate`** — escribir y testear el helper. Prerrequisito de todo lo demás.
2. **`webdata-service`** (URGENTE — desbloquea el deploy de prod en rojo): inventariar prod → `migrate force <V>` (caso fácil) → embeber + cablear `RunMigrations` en `cmd/api/main.go` → deploy.
3. **Numeración limpia** (re-paddeo a `NNNNNN_*`, completar `.down.sql`, baseline, cablear helper), en este orden: `iam` → `sales` → `stock` → `tenant` → `customer` → `ledger` → `payment-method`. En esta tanda se separan los seeds demo de `tenant` y `sales` a `seeds/dev/` (parámetro 4).
4. **`pim-service`** (ÚLTIMO con baseline): renumerar toda la serie a `NNNNNN_*` (resolver colisiones `014_*` y timestamps) → recalcular `V` sobre la serie renumerada → `migrate force <V>` → cablear helper.
5. **`onboarding-service` y `notification-service`**: reemplazar el migrador casero por el helper (eliminar el runner propio, embeber, cablear). Separar seeds si corresponde.

`commerce-ai-service` no se toca: es Python con Alembic, fuera de scope.

## Alternativas consideradas

| Opción | Por qué no |
|--------|-----------|
| **Helper casero de migraciones** (el patrón actual de `onboarding`/`notification`) | Los runners caseros ya divergieron entre servicios; **no tienen locking** (riesgo de doble ejecución en arranque concurrente / múltiples réplicas); **no embeben los `.sql`** (frágil en contenedor); no llevan control de versión/`dirty` confiable. golang-migrate trae todo eso de fábrica, incluido el **advisory lock de PostgreSQL** nativo. Mantener N runners caseros es deuda que ya se está pagando. |
| **Seguir con scripts externos** (`migrate.sh` / `make migrate` fuera del binario) | Depende de que el script y la carpeta `migrations/` estén presentes en el entorno de deploy; no es autocontenido; es justo la causa del deploy roto de `webdata`. |
| **Motores alternativos** (`goose`, `atlas`, `tern`) | `goose` es comparable pero golang-migrate tiene la integración `iofs`+`postgres` más directa para el caso `embed.FS` + pool existente y advisory lock; `atlas` agrega un modelo declarativo/herramienta externa que excede lo que necesitamos. Sin ventaja que justifique cambiar de la opción ya elegida. |
| **ORM con auto-migrate** (GORM AutoMigrate o similar) | La flota usa `database/sql` + raw SQL por decisión de arquitectura; auto-migrate esconde el DDL, no versiona y no permite migraciones de datos controladas. Incompatible con el stack. |

## Consecuencias

**Positivas**:
- Una sola forma de migrar en toda la flota Go: mismo motor, mismo naming, mismo helper, mismo punto de invocación.
- Binarios **autocontenidos** (`//go:embed`): el deploy no depende de archivos externos → desbloquea `webdata` en prod.
- **Seguro ante concurrencia**: el advisory lock evita doble ejecución con múltiples réplicas o arranques simultáneos.
- **Fail-fast**: un schema inconsistente impide arrancar el server en vez de servir tráfico sobre una DB a medio migrar.
- Prod deja de correr seeds de demo (parámetro 4); `schema_migrations` da estado de versión auditable por servicio.
- Capacidad de rollback real donde tiene sentido, y rechazo explícito donde no (parámetro 1).

**Negativas / trade-offs (deuda asumida)**:
- **Trabajo de migración one-shot no trivial**: renumerar `pim`, completar `.down.sql` históricos, inventariar y baselinear cada DB de prod, separar seeds. Es esfuerzo manual y verificable, servicio por servicio.
- **Baseline es un punto de cuidado**: un `force <V>` con `V` mal calculado deja la DB en un estado donde se saltean o re-aplican migraciones. Mitigación: `V` se deriva por inventario verificable, no por estimación.
- Nueva dependencia (`golang-migrate/v4` + drivers) en `go-shared`, propagada a todos los consumidores.
- Las migraciones de datos con down "no soportado" no son reversibles por el motor: revertirlas exige restore desde backup (trade-off aceptado: es preferible fallar claro a fingir un rollback que corrompe datos).

**Neutral**:
- El modo de ejecución no cambia hoy (1 tx por migración); el parámetro 5 sólo deja escrita la regla para el primer statement no transaccional que aparezca.
- El pool de conexiones se reusa (el helper recibe el `*sql.DB` del servicio), no abre conexiones nuevas.

## Revisión prevista

Revisar esta decisión si: (a) aparece el primer statement no transaccional en la flota (activa el parámetro 5 y conviene validar el flujo fuera de transacción), (b) el volumen de datos hace que alguna migración de datos in-app sea demasiado lenta para correr en el arranque (habría que mover ese tipo de migración a un job separado), o (c) se incorpora un cuarto servicio con un motor distinto y se evalúa unificar también ahí.
