package criteria

import (
	"net/url"

	"github.com/gin-gonic/gin"
)

// GinHelper proporciona funciones para trabajar con Criteria en controllers Gin
type GinHelper struct{}

// NewGinHelper crea una nueva instancia del helper
func NewGinHelper() *GinHelper {
	return &GinHelper{}
}

// BuildCriteriaFromQuery construye un CriteriaBuilder desde los query parameters de Gin
func (h *GinHelper) BuildCriteriaFromQuery(c *gin.Context) *CriteriaBuilder {
	return NewCriteriaBuilder().FromURLValues(c.Request.URL.Query())
}

// BuildCriteriaFromURLValues construye un CriteriaBuilder desde url.Values
func (h *GinHelper) BuildCriteriaFromURLValues(values url.Values) *CriteriaBuilder {
	return NewCriteriaBuilder().FromURLValues(values)
}

// ValidateAndSanitize valida el criteria y filtra solo los campos permitidos
func (h *GinHelper) ValidateAndSanitize(c Criteria, allowedFields []string) (Criteria, error) {
	if err := c.Validate(); err != nil {
		return Criteria{}, err
	}
	return Sanitize(c, allowedFields), nil
}

// EntityCriteriaHelper proporciona compatibilidad con el patrón anterior (BuildBaseFromContext, ValidateAndSanitizeCriteria)
type EntityCriteriaHelper struct {
	*GinHelper
}

// NewEntityCriteriaHelper crea un nuevo helper para entidades
func NewEntityCriteriaHelper() *EntityCriteriaHelper {
	return &EntityCriteriaHelper{GinHelper: NewGinHelper()}
}

// BuildBaseFromContext crea un builder base desde el contexto de Gin
func (h *EntityCriteriaHelper) BuildBaseFromContext(c *gin.Context) *CriteriaBuilder {
	return h.BuildCriteriaFromQuery(c)
}

// ValidateAndSanitizeCriteria sanitiza criterios (solo whitelist de campos)
func (h *EntityCriteriaHelper) ValidateAndSanitizeCriteria(criteria Criteria, allowedFields []string) Criteria {
	return Sanitize(criteria, allowedFields)
}
