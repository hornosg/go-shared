package middleware

import (
	"github.com/gin-gonic/gin"
)

/*
Ejemplo de cómo aplicar middlewares específicos a ciertas rutas:

```go
func SetupRoutesWithCompression(router *gin.Engine) {
	// 1. Aplicar compresión global que maneja solicitudes/respuestas basadas en los headers
	router.Use(GzipMiddleware())

	// 2. Configurar rutas específicas para distintos tipos de compresión
	apiGroup := router.Group("/api/v1")

	// a) Rutas que siempre intentan comprimir pero verificando soporte del cliente (seguro)
	largeDataGroup := apiGroup.Group("/large-data")
	largeDataGroup.Use(ForceGzipMiddleware()) // Usa opciones por defecto (verifica soporte)

	// b) Rutas para servicios internos donde sabemos que el cliente soporta gzip (cuidado!)
	internalGroup := apiGroup.Group("/internal")
	internalOpts := ForceGzipOptions{CheckClientSupport: false}
	internalGroup.Use(ForceGzipMiddleware(internalOpts))

	// Configurar las rutas
	largeDataGroup.GET("/products", productHandler)
	internalGroup.GET("/metrics", metricsHandler)

	// 3. Rutas que nunca deberían comprimirse (como descargas de archivos)
	downloadGroup := apiGroup.Group("/downloads")
	downloadGroup.GET("/files/:id", fileDownloadHandler)
}
*/

// Skip devuelve true si la ruta debe saltarse para cierta funcionalidad
func ShouldSkipGzip(path string, excludedPaths []string) bool {
	for _, excluded := range excludedPaths {
		if path == excluded {
			return true
		}
	}
	return false
}

// ConditionalMiddleware aplica un middleware solo si una condición se cumple
func ConditionalMiddleware(condition func(*gin.Context) bool, middleware gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if condition(c) {
			middleware(c)
		} else {
			c.Next()
		}
	}
}
