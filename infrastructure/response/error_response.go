// Package response provides the shared HTTP response envelopes used across the
// mercado-cercano ecosystem. It centralizes the error shape that every service
// has so far been building ad-hoc as gin.H{"error": ...}, so the contract is
// typed once, documented once (OpenAPI), and reused everywhere.
package response

import "github.com/gin-gonic/gin"

// ErrorResponse is the standard HTTP error envelope of the ecosystem.
// It mirrors the historical gin.H{"error": ...} shape so existing consumers and
// clients keep working unchanged; Details is optional and omitted when empty.
type ErrorResponse struct {
	// Error is the human-readable error message.
	Error string `json:"error"`
	// Details carries optional extra context (root cause, offending field, ...).
	Details string `json:"details,omitempty"`
}

// NewError builds an ErrorResponse with just a message.
func NewError(message string) ErrorResponse {
	return ErrorResponse{Error: message}
}

// NewErrorWithDetails builds an ErrorResponse with a message and extra details.
func NewErrorWithDetails(message, details string) ErrorResponse {
	return ErrorResponse{Error: message, Details: details}
}

// JSON writes an ErrorResponse with the given status. Use in terminal handlers.
func JSON(c *gin.Context, status int, message string) {
	c.JSON(status, NewError(message))
}

// JSONWithDetails writes an ErrorResponse with details. Use in terminal handlers.
func JSONWithDetails(c *gin.Context, status int, message, details string) {
	c.JSON(status, NewErrorWithDetails(message, details))
}

// Abort writes an ErrorResponse and stops the handler chain. Use in middleware.
func Abort(c *gin.Context, status int, message string) {
	c.AbortWithStatusJSON(status, NewError(message))
}
