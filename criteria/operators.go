package criteria

// FilterOperator define los operadores disponibles para filtros
type FilterOperator string

const (
	OpEqual              FilterOperator = "="
	OpNotEqual           FilterOperator = "!="
	OpGreaterThan        FilterOperator = ">"
	OpGreaterThanOrEqual FilterOperator = ">="
	OpLessThan           FilterOperator = "<"
	OpLessThanOrEqual    FilterOperator = "<="
	OpLike               FilterOperator = "LIKE"
	OpNotLike            FilterOperator = "NOT LIKE"
	OpIn                 FilterOperator = "IN"
	OpNotIn              FilterOperator = "NOT IN"
	OpIsNull             FilterOperator = "IS NULL"
	OpIsNotNull          FilterOperator = "IS NOT NULL"
	OpContains           FilterOperator = "CONTAINS"
	OpNotContains        FilterOperator = "NOT CONTAINS"
	OpArrayContains      FilterOperator = "ARRAY_CONTAINS"
)

// OrderDirection define las direcciones de ordenamiento
type OrderDirection string

const (
	OrderAsc  OrderDirection = "ASC"
	OrderDesc OrderDirection = "DESC"
)
