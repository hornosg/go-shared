package adapters

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/hornosg/go-shared/domain/port"
)

// RowParser is implemented by concrete importers to convert a CSV row into a typed record.
type RowParser[T any] interface {
	ParseRow(row []string, headers []string, rowData map[string]string, tenantID string) (*T, []string)
}

// CSVFileImporter combines FileImporter and RowParser for single-type importers.
type CSVFileImporter[T any] interface {
	port.FileImporter[T]
	RowParser[T]
}

// BaseCSVFileImporter provides reusable CSV parsing logic.
// Embed it in a concrete importer and implement RowParser[T].
type BaseCSVFileImporter[T any] struct {
	delimiter       rune
	hasHeader       bool
	requiredColumns []string
}

func NewBaseCSVFileImporter[T any](delimiter rune, hasHeader bool, requiredColumns []string) *BaseCSVFileImporter[T] {
	if delimiter == 0 {
		delimiter = ','
	}
	return &BaseCSVFileImporter[T]{
		delimiter:       delimiter,
		hasHeader:       hasHeader,
		requiredColumns: requiredColumns,
	}
}

// Import parses the CSV stream using the provided RowParser.
func (b *BaseCSVFileImporter[T]) Import(ctx context.Context, reader io.Reader, tenantID string, parser RowParser[T]) (*port.ImportResult[T], error) {
	result := port.NewImportResult[T]()

	csvReader := csv.NewReader(reader)
	csvReader.Comma = b.delimiter
	csvReader.TrimLeadingSpace = true

	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("error reading CSV: %w", err)
	}
	if len(records) == 0 {
		return result, nil
	}

	var headers []string
	startRow := 0

	if b.hasHeader {
		headers = records[0]
		startRow = 1
		if err := b.validateRequiredColumns(headers); err != nil {
			return nil, err
		}
	}

	for i := startRow; i < len(records); i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		row := records[i]
		rowNumber := i + 1
		rowData := b.buildRowMap(headers, row)
		item, errs := parser.ParseRow(row, headers, rowData, tenantID)
		if len(errs) > 0 {
			result.AddError(rowNumber, rowData, errs)
		} else if item != nil {
			result.AddSuccess(*item)
		}
	}

	result.TotalRows = len(records) - startRow
	return result, nil
}

func (b *BaseCSVFileImporter[T]) validateRequiredColumns(headers []string) error {
	hm := make(map[string]bool, len(headers))
	for _, h := range headers {
		hm[strings.TrimSpace(strings.ToLower(h))] = true
	}
	var missing []string
	for _, req := range b.requiredColumns {
		if !hm[strings.ToLower(req)] {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required columns missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (b *BaseCSVFileImporter[T]) buildRowMap(headers, row []string) map[string]string {
	data := make(map[string]string, len(row))
	if len(headers) == 0 {
		for i, v := range row {
			data[fmt.Sprintf("column_%d", i)] = strings.TrimSpace(v)
		}
	} else {
		for i, h := range headers {
			v := ""
			if i < len(row) {
				v = strings.TrimSpace(row[i])
			}
			data[strings.TrimSpace(h)] = v
		}
	}
	return data
}
