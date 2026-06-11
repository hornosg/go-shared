package criteria

import (
	"fmt"
	"strconv"
	"strings"
)

// SQLCriteriaConverter convierte un objeto Criteria en consultas SQL PostgreSQL
type SQLCriteriaConverter struct{}

// NewSQLCriteriaConverter crea una nueva instancia del conversor
func NewSQLCriteriaConverter() *SQLCriteriaConverter {
	return &SQLCriteriaConverter{}
}

// ToSelectSQL convierte un criteria a una consulta SQL SELECT completa con sus parámetros.
// Retorna error si algún field name es inválido (defensa contra SQL injection).
func (s *SQLCriteriaConverter) ToSelectSQL(baseQuery string, c Criteria) (string, []interface{}, error) {
	if err := c.Validate(); err != nil {
		return "", nil, err
	}

	var parts []string
	var params []interface{}

	parts = append(parts, baseQuery)

	if !c.Filters.IsEmpty() {
		whereClause, whereParams := s.buildWhereClause(c.Filters)
		parts = append(parts, whereClause)
		params = append(params, whereParams...)
	}

	if len(c.Orders) > 0 {
		orderClause := s.buildOrderClause(c.Orders)
		parts = append(parts, orderClause)
	}

	if !c.Pagination.IsEmpty() {
		limitClause := s.buildLimitClause(c.Pagination)
		parts = append(parts, limitClause)
	}

	return strings.Join(parts, " "), params, nil
}

// ToCountSQL convierte un criteria a una consulta SQL COUNT con sus parámetros (sin ORDER BY ni LIMIT).
// Retorna error si algún field name es inválido.
func (s *SQLCriteriaConverter) ToCountSQL(baseCountQuery string, c Criteria) (string, []interface{}, error) {
	if err := c.Validate(); err != nil {
		return "", nil, err
	}

	var parts []string
	var params []interface{}

	parts = append(parts, baseCountQuery)

	if !c.Filters.IsEmpty() {
		whereClause, whereParams := s.buildWhereClause(c.Filters)
		parts = append(parts, whereClause)
		params = append(params, whereParams...)
	}

	return strings.Join(parts, " "), params, nil
}

func (s *SQLCriteriaConverter) buildWhereClause(filters Filters) (string, []interface{}) {
	var conditions []string
	var params []interface{}
	paramIndex := 1

	for _, filter := range filters.Items {
		if filter.Operator == OpIn || filter.Operator == OpNotIn {
			if values, ok := filter.Value.([]interface{}); ok && len(values) > 0 {
				placeholders := make([]string, len(values))
				for i, value := range values {
					placeholders[i] = "$" + strconv.Itoa(paramIndex)
					params = append(params, value)
					paramIndex++
				}
				op := "IN"
				if filter.Operator == OpNotIn {
					op = "NOT IN"
				}
				conditions = append(conditions, fmt.Sprintf("%s %s (%s)", filter.Field, op, strings.Join(placeholders, ", ")))
			}
		} else {
			condition, value := s.processFilterWithIndex(filter, paramIndex)
			conditions = append(conditions, condition)
			if value != nil {
				params = append(params, value)
				paramIndex++
			}
		}
	}

	if len(conditions) > 0 {
		return fmt.Sprintf("WHERE %s", strings.Join(conditions, " AND ")), params
	}
	return "", params
}

func (s *SQLCriteriaConverter) buildOrderClause(orders []Order) string {
	if len(orders) == 0 {
		return ""
	}
	clauses := make([]string, len(orders))
	for i, o := range orders {
		clauses[i] = fmt.Sprintf("%s %s", o.Field, o.Direction)
	}
	return "ORDER BY " + strings.Join(clauses, ", ")
}

func (s *SQLCriteriaConverter) buildLimitClause(p Pagination) string {
	return fmt.Sprintf("LIMIT %d OFFSET %d", p.Limit, p.Offset)
}

func (s *SQLCriteriaConverter) processFilterWithIndex(filter Filter, paramIndex int) (string, interface{}) {
	placeholder := "$" + strconv.Itoa(paramIndex)

	switch filter.Operator {
	case OpEqual, OpNotEqual, OpGreaterThan, OpGreaterThanOrEqual, OpLessThan, OpLessThanOrEqual:
		return fmt.Sprintf("%s %s %s", filter.Field, filter.Operator, placeholder), filter.Value
	case OpLike:
		val := filter.Value
		if str, ok := val.(string); ok && !strings.Contains(str, "%") {
			val = "%" + str + "%"
		}
		return fmt.Sprintf("%s ILIKE %s", filter.Field, placeholder), val
	case OpNotLike:
		val := filter.Value
		if str, ok := val.(string); ok && !strings.Contains(str, "%") {
			val = "%" + str + "%"
		}
		return fmt.Sprintf("%s NOT ILIKE %s", filter.Field, placeholder), val
	case OpIsNull:
		return fmt.Sprintf("%s IS NULL", filter.Field), nil
	case OpIsNotNull:
		return fmt.Sprintf("%s IS NOT NULL", filter.Field), nil
	case OpContains:
		val := filter.Value
		if str, ok := val.(string); ok && !strings.Contains(str, "%") {
			val = "%" + str + "%"
		}
		return fmt.Sprintf("%s ILIKE %s", filter.Field, placeholder), val
	case OpNotContains:
		val := filter.Value
		if str, ok := val.(string); ok && !strings.Contains(str, "%") {
			val = "%" + str + "%"
		}
		return fmt.Sprintf("%s NOT ILIKE %s", filter.Field, placeholder), val
	case OpArrayContains:
		return fmt.Sprintf("%s @> ARRAY[%s]", filter.Field, placeholder), filter.Value
	default:
		return fmt.Sprintf("%s = %s", filter.Field, placeholder), filter.Value
	}
}
