package businesstype

import (
	"fmt"
	"time"
)

// BusinessTypeAssignment is a value object that captures the resolved business type
// for a product, including the code, human-readable name, and the timestamp of
// resolution. Promoted from webdata-service (E24 / ADR-005 §5).
type BusinessTypeAssignment struct {
	BusinessTypeCode string
	BusinessTypeName string
	CreatedAt        time.Time
}

// NewBusinessTypeAssignment constructs a BusinessTypeAssignment.
// Returns an error if code is empty.
func NewBusinessTypeAssignment(code, name string) (BusinessTypeAssignment, error) {
	if code == "" {
		return BusinessTypeAssignment{}, fmt.Errorf("business type code is required")
	}
	return BusinessTypeAssignment{
		BusinessTypeCode: code,
		BusinessTypeName: name,
		CreatedAt:        time.Now(),
	}, nil
}
