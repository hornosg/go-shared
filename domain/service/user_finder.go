package service

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// Errores comunes para la comunicación entre módulos
var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrInvalidUserData   = errors.New("invalid user data")
)

// UserFinderService define una interfaz genérica para buscar usuarios
// Esta interfaz puede ser implementada por cualquier módulo sin crear acoplamiento
type UserFinderService interface {
	FindUserByEmail(ctx context.Context, email string, tenantID *uuid.UUID) (*BasicUserData, error)
	FindUserByID(ctx context.Context, id uuid.UUID) (*BasicUserData, error)
}

// BasicUserData contiene solo la información básica de usuario que pueden necesitar otros módulos
type BasicUserData struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	TenantID     uuid.UUID
	RoleID       uuid.UUID
	Status       string
	Provider     string
	FederatedID  string
}
