package criteria

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// CriteriaBuilder facilita la construcción de criterios usando el patrón builder
type CriteriaBuilder struct {
	filters    []Filter
	orders     []Order
	page       int
	pageSize   int
	orderField string
	orderDir   OrderDirection
}

// NewCriteriaBuilder crea un nuevo builder
func NewCriteriaBuilder() *CriteriaBuilder {
	return &CriteriaBuilder{
		filters:    make([]Filter, 0),
		orders:     make([]Order, 0),
		page:       1,
		pageSize:   10,
		orderField: "created_at",
		orderDir:   OrderDesc,
	}
}

// FromURLValues inicializa el builder desde url.Values
// Parsea: page, page_size, sort_by, sort_dir, y filter_<field> para filtros con operador Equal
func (b *CriteriaBuilder) FromURLValues(values url.Values) *CriteriaBuilder {
	if page := values.Get("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			b.page = p
		}
	}

	if pageSize := values.Get("page_size"); pageSize != "" {
		if ps, err := strconv.Atoi(pageSize); err == nil && ps > 0 && ps <= 100 {
			b.pageSize = ps
		}
	}

	if sortBy := values.Get("sort_by"); sortBy != "" {
		b.orderField = sortBy
	}

	if sortDir := values.Get("sort_dir"); sortDir != "" {
		sortDir = strings.ToUpper(sortDir)
		if sortDir == "ASC" {
			b.orderDir = OrderAsc
		} else {
			b.orderDir = OrderDesc
		}
	}

	// Parse filter_<field> params (default operator Equal)
	for key, vals := range values {
		if strings.HasPrefix(key, "filter_") && len(vals) > 0 && vals[0] != "" {
			field := strings.TrimPrefix(key, "filter_")
			b.filters = append(b.filters, NewFilter(field, OpEqual, vals[0]))
		}
	}

	return b
}

// WithFilter agrega un filtro
func (b *CriteriaBuilder) WithFilter(field string, operator FilterOperator, value interface{}) *CriteriaBuilder {
	b.filters = append(b.filters, NewFilter(field, operator, value))
	return b
}

// WithOrder agrega un orden (soporta multi-orden)
func (b *CriteriaBuilder) WithOrder(field string, direction OrderDirection) *CriteriaBuilder {
	b.orders = append(b.orders, NewOrder(field, direction))
	return b
}

// SetPagination establece la paginación (alias para compatibilidad)
func (b *CriteriaBuilder) SetPagination(page, pageSize int) *CriteriaBuilder {
	return b.WithPagination(page, pageSize)
}

// WithPagination establece la paginación
func (b *CriteriaBuilder) WithPagination(page, pageSize int) *CriteriaBuilder {
	if page > 0 {
		b.page = page
	}
	if pageSize > 0 && pageSize <= 100 {
		b.pageSize = pageSize
	}
	return b
}

// AddFilter agrega un filtro genérico (alias para compatibilidad)
func (b *CriteriaBuilder) AddFilter(field string, operator FilterOperator, value interface{}) *CriteriaBuilder {
	return b.WithFilter(field, operator, value)
}

// AddEqualFilter agrega un filtro de igualdad.
// Ignora strings vacíos para no generar condiciones `campo = ''` cuando el
// valor viene de un query param ausente (consistente con AddLikeFilter/AddUUIDFilter).
func (b *CriteriaBuilder) AddEqualFilter(field string, value interface{}) *CriteriaBuilder {
	if str, ok := value.(string); ok && str == "" {
		return b
	}
	return b.WithFilter(field, OpEqual, value)
}

// AddNotEqualFilter agrega un filtro de desigualdad
func (b *CriteriaBuilder) AddNotEqualFilter(field string, value interface{}) *CriteriaBuilder {
	return b.WithFilter(field, OpNotEqual, value)
}

// AddGreaterThanFilter agrega un filtro mayor que
func (b *CriteriaBuilder) AddGreaterThanFilter(field string, value interface{}) *CriteriaBuilder {
	return b.WithFilter(field, OpGreaterThan, value)
}

// AddGreaterThanOrEqualFilter agrega un filtro mayor o igual que
func (b *CriteriaBuilder) AddGreaterThanOrEqualFilter(field string, value interface{}) *CriteriaBuilder {
	return b.WithFilter(field, OpGreaterThanOrEqual, value)
}

// AddLessThanFilter agrega un filtro menor que
func (b *CriteriaBuilder) AddLessThanFilter(field string, value interface{}) *CriteriaBuilder {
	return b.WithFilter(field, OpLessThan, value)
}

// AddLessThanOrEqualFilter agrega un filtro menor o igual que
func (b *CriteriaBuilder) AddLessThanOrEqualFilter(field string, value interface{}) *CriteriaBuilder {
	return b.WithFilter(field, OpLessThanOrEqual, value)
}

// AddArrayContainsFilter agrega un filtro para arrays que contienen un valor
func (b *CriteriaBuilder) AddArrayContainsFilter(field string, value interface{}) *CriteriaBuilder {
	return b.WithFilter(field, OpArrayContains, value)
}

// AddLikeFilter agrega un filtro LIKE (agrega % si no tiene wildcards)
func (b *CriteriaBuilder) AddLikeFilter(field string, value interface{}) *CriteriaBuilder {
	if str, ok := value.(string); ok && str != "" {
		if !strings.Contains(str, "%") {
			value = "%" + str + "%"
		}
		return b.WithFilter(field, OpLike, value)
	}
	return b
}

// AddInFilter agrega un filtro IN para arrays
func (b *CriteriaBuilder) AddInFilter(field string, values []interface{}) *CriteriaBuilder {
	if len(values) > 0 {
		return b.WithFilter(field, OpIn, values)
	}
	return b
}

// AddUUIDFilter agrega un filtro para UUID validando el formato
func (b *CriteriaBuilder) AddUUIDFilter(field string, value interface{}) *CriteriaBuilder {
	if str, ok := value.(string); ok && str != "" {
		if _, err := uuid.Parse(str); err == nil {
			return b.WithFilter(field, OpEqual, str)
		}
	}
	return b
}

// AddBoolFilter agrega un filtro booleano (acepta "true"/"false" string o bool)
func (b *CriteriaBuilder) AddBoolFilter(field string, value interface{}) *CriteriaBuilder {
	if str, ok := value.(string); ok {
		if str == "true" {
			return b.WithFilter(field, OpEqual, true)
		}
		if str == "false" {
			return b.WithFilter(field, OpEqual, false)
		}
	}
	if boolVal, ok := value.(bool); ok {
		return b.WithFilter(field, OpEqual, boolVal)
	}
	return b
}

// SetOrder establece el orden (reemplaza el default, no agrega a multi-orden)
func (b *CriteriaBuilder) SetOrder(field string, direction OrderDirection) *CriteriaBuilder {
	if field != "" {
		b.orderField = field
		b.orderDir = direction
	}
	return b
}

// Build construye el criteria final
func (b *CriteriaBuilder) Build() Criteria {
	filters := NewFilters(b.filters...)

	var orders []Order
	if len(b.orders) > 0 {
		orders = append(orders, b.orders...)
	} else if b.orderField != "" {
		orders = []Order{NewOrder(b.orderField, b.orderDir)}
	} else {
		orders = []Order{NewOrder("created_at", OrderDesc)}
	}

	pagination := NewPagination(b.page, b.pageSize)

	return NewCriteria(filters, orders, pagination)
}
