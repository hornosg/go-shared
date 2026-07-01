package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
)

// Session variable names para las policies RLS (Devy RULE-10). Mantener en sync con las
// migraciones 002_rls.sql de cada servicio.
const (
	TenantVar    = "app.tenant_id"
	NamespaceVar = "app.namespace"
	RoleVar      = "app.role"
)

// safeGUCValue exige un formato acotado (uuid, o alfanumérico/guion/punto para namespace)
// antes de interpolarlo en un SET LOCAL — Postgres no permite bind params en SET, así que
// la validación de forma es la defensa real contra inyección en el nombre de la GUC.
var safeGUCValue = regexp.MustCompile(`^[a-zA-Z0-9_.\-]{0,128}$`)

// RLSContext trae los valores de sesión que fijan el alcance de las policies RLS de una
// transacción. TenantID es obligatorio para servicios single-namespace; Namespace es sólo
// para servicios de plataforma compartidos entre proyectos (ej. notifications). Role
// habilita break-glass (system_admin) — debe salir de un claim JWT ya validado, nunca de
// un header sin verificar.
type RLSContext struct {
	TenantID  string
	Namespace string
	Role      string
}

// SetRLSContextTx fija las variables de sesión RLS con SET LOCAL dentro de una
// transacción ya abierta. SET LOCAL se resetea solo al hacer COMMIT/ROLLBACK — a
// diferencia de SET sobre una conexión pooleada, no requiere un RESET manual ni corre
// riesgo de "pegarse" a la conexión física cuando vuelve al pool (ver E07, sesión L4
// 2026-07-01: CRITICAL-2 del patrón SET+reset manual del scaffold).
func SetRLSContextTx(ctx context.Context, tx *sql.Tx, rc RLSContext) error {
	if !safeGUCValue.MatchString(rc.TenantID) {
		return fmt.Errorf("rls: tenant_id con formato inválido")
	}
	if !safeGUCValue.MatchString(rc.Namespace) {
		return fmt.Errorf("rls: namespace con formato inválido")
	}
	if !safeGUCValue.MatchString(rc.Role) {
		return fmt.Errorf("rls: role con formato inválido")
	}

	if rc.TenantID != "" {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL %s = %s", TenantVar, quoteLiteral(rc.TenantID))); err != nil {
			return fmt.Errorf("rls: set tenant_id: %w", err)
		}
	}
	if rc.Namespace != "" {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL %s = %s", NamespaceVar, quoteLiteral(rc.Namespace))); err != nil {
			return fmt.Errorf("rls: set namespace: %w", err)
		}
	}
	if rc.Role != "" {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL %s = %s", RoleVar, quoteLiteral(rc.Role))); err != nil {
			return fmt.Errorf("rls: set role: %w", err)
		}
	}
	return nil
}

// WithRLSInTransaction abre una transacción, fija el contexto RLS con SET LOCAL, corre fn,
// y hace commit/rollback. Es la forma recomendada de usar este paquete: no deja margen para
// olvidar el reset porque no hay nada que resetear.
func WithRLSInTransaction(ctx context.Context, db *sql.DB, rc RLSContext, fn func(context.Context, *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rls: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := SetRLSContextTx(ctx, tx, rc); err != nil {
		return err
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// quoteLiteral escapa un literal para uso en SET LOCAL (no soporta bind params).
// Complementa, no reemplaza, la validación de formato de safeGUCValue.
func quoteLiteral(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\'')
			continue
		}
		out = append(out, s[i])
	}
	out = append(out, '\'')
	return string(out)
}
