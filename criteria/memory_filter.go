package criteria

import (
	"reflect"
	"sort"
	"strings"
)

// ApplyInMemory aplica un Criteria sobre un slice en memoria.
// Soporta filtros (Equal, NotEqual, Like, In, etc.), ordenamiento multi-campo y paginación.
// Los campos se resuelven por nombre de struct field o json tag.
func ApplyInMemory[T any](items []T, c Criteria) (filtered []T, totalCount int) {
	if len(items) == 0 {
		return items, 0
	}

	// Filtrar
	filtered = make([]T, 0, len(items))
	for _, item := range items {
		if matchesFilter(item, c.Filters) {
			filtered = append(filtered, item)
		}
	}
	totalCount = len(filtered)

	// Ordenar
	if len(c.Orders) > 0 {
		sort.Slice(filtered, func(i, j int) bool {
			return lessByOrders(filtered[i], filtered[j], c.Orders)
		})
	}

	// Paginar
	if !c.Pagination.IsEmpty() && c.Pagination.Limit > 0 {
		offset := c.Pagination.Offset
		if offset >= len(filtered) {
			return []T{}, totalCount
		}
		end := offset + c.Pagination.Limit
		if end > len(filtered) {
			end = len(filtered)
		}
		filtered = filtered[offset:end]
	}

	return filtered, totalCount
}

func matchesFilter[T any](item T, filters Filters) bool {
	for _, f := range filters.Items {
		val, ok := getFieldValue(item, f.Field)
		if !ok {
			continue
		}
		if !applyOperator(f.Operator, val, f.Value) {
			return false
		}
	}
	return true
}

func getFieldValue(v interface{}, fieldName string) (interface{}, bool) {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, false
	}

	// Buscar por json tag primero
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		jsonTag := f.Tag.Get("json")
		if jsonTag != "" {
			name := strings.Split(jsonTag, ",")[0]
			if name == fieldName {
				return rv.Field(i).Interface(), true
			}
		}
		if f.Name == fieldName {
			return rv.Field(i).Interface(), true
		}
	}

	// Buscar por nombre exacto
	for i := 0; i < rt.NumField(); i++ {
		if strings.EqualFold(rt.Field(i).Name, fieldName) {
			return rv.Field(i).Interface(), true
		}
	}
	return nil, false
}

func applyOperator(op FilterOperator, fieldVal, filterVal interface{}) bool {
	switch op {
	case OpEqual:
		return reflect.DeepEqual(fieldVal, filterVal)
	case OpNotEqual:
		return !reflect.DeepEqual(fieldVal, filterVal)
	case OpLike:
		return matchLike(fieldVal, filterVal, false)
	case OpNotLike:
		return !matchLike(fieldVal, filterVal, false)
	case OpIsNull:
		return fieldVal == nil || reflect.ValueOf(fieldVal).IsZero()
	case OpIsNotNull:
		return fieldVal != nil && !reflect.ValueOf(fieldVal).IsZero()
	case OpIn:
		return matchIn(fieldVal, filterVal)
	case OpNotIn:
		return !matchIn(fieldVal, filterVal)
	case OpContains:
		return matchLike(fieldVal, filterVal, true)
	case OpNotContains:
		return !matchLike(fieldVal, filterVal, true)
	case OpGreaterThan, OpGreaterThanOrEqual, OpLessThan, OpLessThanOrEqual:
		return compareNumeric(op, fieldVal, filterVal)
	default:
		return reflect.DeepEqual(fieldVal, filterVal)
	}
}

func matchLike(fieldVal, pattern interface{}, _ bool) bool {
	fs, ok1 := toString(fieldVal)
	ps, ok2 := toString(pattern)
	if !ok1 || !ok2 {
		return false
	}
	// Case-insensitive substring match (ILIKE semantics)
	psClean := strings.Trim(strings.ReplaceAll(ps, "%", ""), " ")
	if psClean == "" {
		return true
	}
	return strings.Contains(strings.ToLower(fs), strings.ToLower(psClean))
}

func matchIn(fieldVal, filterVal interface{}) bool {
	rv := reflect.ValueOf(filterVal)
	if rv.Kind() == reflect.Slice {
		for i := 0; i < rv.Len(); i++ {
			if reflect.DeepEqual(fieldVal, rv.Index(i).Interface()) {
				return true
			}
		}
		return false
	}
	return reflect.DeepEqual(fieldVal, filterVal)
}

func toString(v interface{}) (string, bool) {
	if v == nil {
		return "", false
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.String {
		return rv.String(), true
	}
	return "", false
}

func compareNumeric(op FilterOperator, a, b interface{}) bool {
	af := toFloat(a)
	bf := toFloat(b)
	if af == nil || bf == nil {
		return false
	}
	switch op {
	case OpGreaterThan:
		return *af > *bf
	case OpGreaterThanOrEqual:
		return *af >= *bf
	case OpLessThan:
		return *af < *bf
	case OpLessThanOrEqual:
		return *af <= *bf
	default:
		return false
	}
}

func toFloat(v interface{}) *float64 {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		f := float64(rv.Int())
		return &f
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		f := float64(rv.Uint())
		return &f
	case reflect.Float32, reflect.Float64:
		f := rv.Float()
		return &f
	}
	return nil
}

func lessByOrders[T any](a, b T, orders []Order) bool {
	for _, o := range orders {
		av, okA := getFieldValue(a, o.Field)
		bv, okB := getFieldValue(b, o.Field)
		if !okA || !okB {
			continue
		}
		cmp := compare(av, bv)
		if cmp != 0 {
			if o.Direction == OrderAsc {
				return cmp < 0
			}
			return cmp > 0
		}
	}
	return false
}

func compare(a, b interface{}) int {
	af := toFloat(a)
	bf := toFloat(b)
	if af != nil && bf != nil {
		if *af < *bf {
			return -1
		}
		if *af > *bf {
			return 1
		}
		return 0
	}
	as, oka := toString(a)
	bs, okb := toString(b)
	if oka && okb {
		return strings.Compare(strings.ToLower(as), strings.ToLower(bs))
	}
	if reflect.DeepEqual(a, b) {
		return 0
	}
	return 0
}
