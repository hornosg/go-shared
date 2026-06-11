package criteria

import "context"

// CriteriaRepository define una interfaz genérica para repositorios que soportan criteria
type CriteriaRepository[T any] interface {
	SearchByCriteria(ctx context.Context, criteria Criteria) ([]*T, error)
	CountByCriteria(ctx context.Context, criteria Criteria) (int, error)
}

// ListRepository define una interfaz para operaciones de listado con criteria
type ListRepository[T any] interface {
	CriteriaRepository[T]
	ListByCriteria(ctx context.Context, criteria Criteria) (*ListResponse[T], error)
}

// BaseListRepository implementación base que puede ser embebida por repositorios concretos
type BaseListRepository[T any] struct {
	criteriaRepo CriteriaRepository[T]
}

// NewBaseListRepository crea una nueva instancia del repositorio base
func NewBaseListRepository[T any](criteriaRepo CriteriaRepository[T]) *BaseListRepository[T] {
	return &BaseListRepository[T]{criteriaRepo: criteriaRepo}
}

// ListByCriteria implementa la lógica común para listado con criteria
func (r *BaseListRepository[T]) ListByCriteria(ctx context.Context, criteria Criteria) (*ListResponse[T], error) {
	items, err := r.criteriaRepo.SearchByCriteria(ctx, criteria)
	if err != nil {
		return nil, err
	}
	total, err := r.criteriaRepo.CountByCriteria(ctx, criteria)
	if err != nil {
		return nil, err
	}
	return NewListResponseFromCriteria(items, total, criteria), nil
}
