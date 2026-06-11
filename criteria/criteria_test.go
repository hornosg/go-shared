package criteria

import (
	"net/url"
	"testing"
)

func TestPagination_Bounds(t *testing.T) {
	p := NewPagination(0, 200)
	if p.Page != 1 {
		t.Errorf("Page should be clamped to 1, got %d", p.Page)
	}
	if p.PageSize != 100 {
		t.Errorf("PageSize should be clamped to 100, got %d", p.PageSize)
	}
	if p.Offset != 0 {
		t.Errorf("Offset should be 0, got %d", p.Offset)
	}
}

func TestPagination_Defaults(t *testing.T) {
	p := NewPagination(2, 10)
	if p.Page != 2 || p.PageSize != 10 || p.Limit != 10 || p.Offset != 10 {
		t.Errorf("unexpected pagination: %+v", p)
	}
}

func TestFilters_AddCountEmpty(t *testing.T) {
	f := NewFilters()
	if !f.IsEmpty() || f.Count() != 0 {
		t.Error("new filters should be empty")
	}
	f.Add(NewFilter("name", OpEqual, "test"))
	if f.IsEmpty() || f.Count() != 1 {
		t.Error("after add, count should be 1")
	}
}

func TestCriteriaBuilder_FromURLValues(t *testing.T) {
	vals := url.Values{
		"page":      {"2"},
		"page_size": {"20"},
		"sort_by":   {"name"},
		"sort_dir":  {"asc"},
	}
	c := NewCriteriaBuilder().FromURLValues(vals).Build()
	if c.Pagination.Page != 2 || c.Pagination.PageSize != 20 {
		t.Errorf("pagination wrong: %+v", c.Pagination)
	}
	if len(c.Orders) != 1 || c.Orders[0].Field != "name" || c.Orders[0].Direction != OrderAsc {
		t.Errorf("order wrong: %+v", c.Orders)
	}
}

func TestCriteriaBuilder_FilterParams(t *testing.T) {
	vals := url.Values{
		"filter_name":   {"coca"},
		"filter_status": {"active"},
	}
	c := NewCriteriaBuilder().FromURLValues(vals).Build()
	if c.Filters.Count() != 2 {
		t.Errorf("expected 2 filters, got %d", c.Filters.Count())
	}
}

func TestValidate_EmptyFilterField(t *testing.T) {
	c := NewCriteria(NewFilters(NewFilter("", OpEqual, "x")), nil, NewPagination(1, 10))
	if err := c.Validate(); err == nil {
		t.Error("expected error for empty filter field")
	}
}

func TestValidate_ValidCriteria(t *testing.T) {
	c := NewCriteria(NewFilters(NewFilter("name", OpEqual, "x")), []Order{NewOrder("id", OrderAsc)}, NewPagination(1, 10))
	if err := c.Validate(); err != nil {
		t.Errorf("valid criteria should pass: %v", err)
	}
}

func TestSanitize_RemovesDisallowedFilter(t *testing.T) {
	c := NewCriteria(
		NewFilters(NewFilter("password", OpEqual, "secret")),
		nil,
		NewPagination(1, 10),
	)
	s := Sanitize(c, []string{"name", "email"})
	if s.Filters.Count() != 0 {
		t.Error("password filter should be removed")
	}
}

func TestSanitize_OrderDefaultsForDisallowed(t *testing.T) {
	c := NewCriteria(
		NewFilters(),
		[]Order{NewOrder("secret_field", OrderDesc)},
		NewPagination(1, 10),
	)
	s := Sanitize(c, []string{"name"})
	if len(s.Orders) != 1 || s.Orders[0].Field != "created_at" || s.Orders[0].Direction != OrderDesc {
		t.Errorf("order should default to created_at DESC: %+v", s.Orders)
	}
}

func TestSQLConverter_ILIKE(t *testing.T) {
	conv := NewSQLCriteriaConverter()
	c := NewCriteria(
		NewFilters(NewFilter("name", OpLike, "coca")),
		nil,
		NewPagination(1, 10),
	)
	q, params, err := conv.ToSelectSQL("SELECT * FROM products", c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(params) != 1 {
		t.Fatalf("expected 1 param, got %d", len(params))
	}
	if val, ok := params[0].(string); !ok || val != "%coca%" {
		t.Errorf("expected %%coca%%, got %v", params[0])
	}
	if len(q) == 0 || len(params) == 0 {
		t.Error("query and params should not be empty")
	}
}

func TestSQLConverter_IN_Expanded(t *testing.T) {
	conv := NewSQLCriteriaConverter()
	c := NewCriteria(
		NewFilters(NewFilter("status", OpIn, []interface{}{"active", "draft", "archived"})),
		nil,
		NewPagination(1, 10),
	)
	q, params, err := conv.ToCountSQL("SELECT COUNT(*) FROM products", c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(params) != 3 {
		t.Errorf("expected 3 params for IN, got %d", len(params))
	}
	if len(q) == 0 {
		t.Error("query should not be empty")
	}
}

func TestSQLConverter_MultiOrder(t *testing.T) {
	conv := NewSQLCriteriaConverter()
	c := NewCriteria(
		NewFilters(),
		[]Order{NewOrder("name", OrderAsc), NewOrder("created_at", OrderDesc)},
		NewPagination(1, 10),
	)
	q, _, err := conv.ToSelectSQL("SELECT * FROM products", c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(q) == 0 {
		t.Error("query should not be empty")
	}
}

func TestSQLConverter_CountNoOrderLimit(t *testing.T) {
	conv := NewSQLCriteriaConverter()
	c := NewCriteria(
		NewFilters(),
		[]Order{NewOrder("name", OrderAsc)},
		NewPagination(1, 10),
	)
	q, _, err := conv.ToCountSQL("SELECT COUNT(*) FROM products", c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(q) == 0 {
		t.Error("query should not be empty")
	}
}

func TestValidateFieldName_Valid(t *testing.T) {
	validFields := []string{"name", "created_at", "products.name", "_id", "a1"}
	for _, f := range validFields {
		if err := ValidateFieldName(f); err != nil {
			t.Errorf("field %q should be valid: %v", f, err)
		}
	}
}

func TestValidateFieldName_Invalid(t *testing.T) {
	invalidFields := []string{
		"name);DROP TABLE x;--",
		"1field",
		"field name",
		"field-name",
		"$where",
		"",
	}
	for _, f := range invalidFields {
		if err := ValidateFieldName(f); err == nil {
			t.Errorf("field %q should be invalid", f)
		}
	}
}

func TestSQLConverter_RejectsInjection(t *testing.T) {
	conv := NewSQLCriteriaConverter()
	c := NewCriteria(
		NewFilters(NewFilter("name);DROP TABLE x;--", OpEqual, "val")),
		nil,
		NewPagination(1, 10),
	)
	_, _, err := conv.ToSelectSQL("SELECT * FROM products", c)
	if err == nil {
		t.Error("expected error for malicious field name")
	}
}

func TestApplyInMemory_FilterString(t *testing.T) {
	type Product struct {
		Name string `json:"name"`
	}
	items := []Product{
		{Name: "Coca Cola"},
		{Name: "Pepsi"},
		{Name: "Coca Zero"},
	}
	c := NewCriteria(
		NewFilters(NewFilter("name", OpLike, "coca")),
		nil,
		NewPagination(1, 10),
	)
	filtered, total := ApplyInMemory(items, c)
	if total != 2 {
		t.Errorf("expected 2 matches, got %d", total)
	}
	if len(filtered) != 2 {
		t.Errorf("expected 2 filtered items, got %d", len(filtered))
	}
}

func TestApplyInMemory_Pagination(t *testing.T) {
	type Item struct {
		ID int `json:"id"`
	}
	items := make([]Item, 50)
	for i := 0; i < 50; i++ {
		items[i] = Item{ID: i}
	}
	c := NewCriteria(NewFilters(), nil, NewPagination(2, 10))
	filtered, total := ApplyInMemory(items, c)
	if total != 50 {
		t.Errorf("totalCount should be 50, got %d", total)
	}
	if len(filtered) != 10 {
		t.Errorf("page 2 should have 10 items, got %d", len(filtered))
	}
}

func TestApplyInMemory_Sort(t *testing.T) {
	type Item struct {
		Price float64 `json:"price"`
	}
	items := []Item{{Price: 30}, {Price: 10}, {Price: 20}}
	c := NewCriteria(
		NewFilters(),
		[]Order{NewOrder("price", OrderAsc)},
		NewPagination(1, 10),
	)
	filtered, _ := ApplyInMemory(items, c)
	if len(filtered) != 3 {
		t.Fatalf("expected 3 items, got %d", len(filtered))
	}
	if filtered[0].Price != 10 || filtered[1].Price != 20 || filtered[2].Price != 30 {
		t.Errorf("expected sorted by price asc: %+v", filtered)
	}
}

func TestNewListResponse(t *testing.T) {
	items := []*string{}
	p := NewPagination(1, 10)
	resp := NewListResponse(items, 45, p)
	if resp.TotalCount != 45 || resp.TotalPages != 5 || resp.Page != 1 || resp.PageSize != 10 {
		t.Errorf("unexpected ListResponse: %+v", resp)
	}
}
