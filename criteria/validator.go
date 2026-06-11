package criteria

import (
	"fmt"
	"regexp"
)

var validFieldNameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.]*$`)

// ValidateFieldName verifica que un nombre de campo sea seguro para interpolar en SQL.
func ValidateFieldName(field string) error {
	if field == "" {
		return fmt.Errorf("field name must not be empty")
	}
	if !validFieldNameRegex.MatchString(field) {
		return fmt.Errorf("invalid field name %q: must match [a-zA-Z_][a-zA-Z0-9_.]*", field)
	}
	return nil
}

// Validate valida que los criterios sean correctos
func (c Criteria) Validate() error {
	for _, filter := range c.Filters.Items {
		if err := ValidateFieldName(filter.Field); err != nil {
			return fmt.Errorf("filter: %w", err)
		}

		requiresValue := []FilterOperator{
			OpEqual, OpNotEqual, OpGreaterThan, OpGreaterThanOrEqual,
			OpLessThan, OpLessThanOrEqual, OpLike, OpNotLike, OpIn, OpNotIn,
			OpContains, OpNotContains, OpArrayContains,
		}

		for _, op := range requiresValue {
			if filter.Operator == op && filter.Value == nil {
				return fmt.Errorf("el operador %s requiere un valor", op)
			}
		}
	}

	for _, order := range c.Orders {
		if err := ValidateFieldName(order.Field); err != nil {
			return fmt.Errorf("order: %w", err)
		}
		if order.Direction != OrderAsc && order.Direction != OrderDesc {
			return fmt.Errorf("dirección de orden inválida: %s", order.Direction)
		}
	}

	if !c.Pagination.IsEmpty() {
		if c.Pagination.Limit <= 0 {
			return fmt.Errorf("el límite debe ser mayor que 0")
		}
		if c.Pagination.Offset < 0 {
			return fmt.Errorf("el offset debe ser mayor o igual a 0")
		}
	}

	return nil
}

// Sanitize filtra criterios para mantener solo campos permitidos.
// Si el campo de orden no está permitido, usa "created_at" DESC por defecto.
func Sanitize(c Criteria, allowedFields []string) Criteria {
	if len(allowedFields) == 0 {
		return c
	}

	allowedMap := make(map[string]bool)
	for _, field := range allowedFields {
		allowedMap[field] = true
	}

	validFilters := NewFilters()
	for _, filter := range c.Filters.Items {
		if allowedMap[filter.Field] {
			validFilters.Add(filter)
		}
	}

	validOrders := make([]Order, 0, len(c.Orders))
	for _, order := range c.Orders {
		if order.Field != "" && allowedMap[order.Field] {
			validOrders = append(validOrders, order)
		}
	}
	if len(validOrders) == 0 && len(c.Orders) > 0 {
		validOrders = []Order{NewOrder("created_at", OrderDesc)}
	}

	return NewCriteria(validFilters, validOrders, c.Pagination)
}
