package port

import (
	"context"
	"io"
)

// FileImporter is the generic port for reading a stream and converting it into typed records.
type FileImporter[T any] interface {
	Import(ctx context.Context, reader io.Reader, tenantID string) (*ImportResult[T], error)
}

// ImportResult holds the outcome of a file import operation.
type ImportResult[T any] struct {
	TotalRows         int           `json:"total_rows"`
	SuccessfulImports int           `json:"successful_imports"`
	FailedImports     int           `json:"failed_imports"`
	ImportedItems     []T           `json:"imported_items"`
	Errors            []ImportError `json:"errors"`
}

// ImportError describes a validation or parsing failure for a single row.
type ImportError struct {
	Row    int               `json:"row"`
	Data   map[string]string `json:"data"`
	Errors []string          `json:"errors"`
}

func NewImportResult[T any]() *ImportResult[T] {
	return &ImportResult[T]{
		ImportedItems: make([]T, 0),
		Errors:        make([]ImportError, 0),
	}
}

func (r *ImportResult[T]) AddSuccess(item T) {
	r.SuccessfulImports++
	r.ImportedItems = append(r.ImportedItems, item)
}

func (r *ImportResult[T]) AddError(row int, data map[string]string, errors []string) {
	r.FailedImports++
	r.Errors = append(r.Errors, ImportError{Row: row, Data: data, Errors: errors})
}

func (r *ImportResult[T]) IsSuccess() bool { return r.FailedImports == 0 }
func (r *ImportResult[T]) HasErrors() bool  { return r.FailedImports > 0 }
