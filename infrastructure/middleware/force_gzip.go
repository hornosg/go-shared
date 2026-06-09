package middleware

import (
	"compress/gzip"
	"strings"

	"github.com/gin-gonic/gin"
)

// ForceGzipOptions contiene opciones para ForceGzipMiddleware
type ForceGzipOptions struct {
	// CheckClientSupport verifica si el cliente soporta gzip antes de comprimir
	CheckClientSupport bool
}

// DefaultForceGzipOptions devuelve opciones por defecto
func DefaultForceGzipOptions() ForceGzipOptions {
	return ForceGzipOptions{
		CheckClientSupport: true, // Por defecto, verificar si el cliente soporta gzip
	}
}

// ForceGzipMiddleware fuerza la compresión gzip en las respuestas
// ADVERTENCIA: Si CheckClientSupport es false, se enviará gzip a todos los clientes
// independientemente de si pueden procesarlo, lo que puede causar errores
func ForceGzipMiddleware(options ...ForceGzipOptions) gin.HandlerFunc {
	var opts ForceGzipOptions
	if len(options) > 0 {
		opts = options[0]
	} else {
		opts = DefaultForceGzipOptions()
	}

	return func(c *gin.Context) {
		// Verificar si el cliente soporta gzip cuando CheckClientSupport está activado
		if opts.CheckClientSupport && !strings.Contains(c.Request.Header.Get("Accept-Encoding"), gzipEncoding) {
			c.Next()
			return
		}

		// Crear un writer gzip
		gz := gzip.NewWriter(c.Writer)
		defer gz.Close()

		// Reemplazar el writer original con el gzip writer
		c.Writer = &gzipWriter{
			ResponseWriter: c.Writer,
			writer:         gz,
		}

		// Establecer el header de content encoding
		c.Header("Content-Encoding", gzipEncoding)
		c.Header("Vary", "Accept-Encoding")

		c.Next()
	}
}

// GzipReader es un middleware que siempre intenta descomprimir el cuerpo de la solicitud si está comprimido con gzip
func GzipReader() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Simplemente pasamos al siguiente middleware sin intentar descomprimir
		c.Next()

		// Código comentado temporalmente para diagnosticar problemas
		/*
			// Verificar Content-Type para evitar descomprimir datos binarios no comprimidos
			contentType := c.Request.Header.Get("Content-Type")
			if strings.Contains(contentType, "application/json") ||
				strings.Contains(contentType, "application/xml") ||
				strings.Contains(contentType, "text/") {

				// Intentar descomprimir
				reader, err := gzip.NewReader(c.Request.Body)
				// Si no es un formato gzip válido, simplemente continuamos con el body original
				if err == nil {
					defer reader.Close()

					data, err := io.ReadAll(reader)
					if err == nil {
						c.Request.Body = io.NopCloser(strings.NewReader(string(data)))
						c.Request.ContentLength = int64(len(data))
						c.Request.Header.Del("Content-Encoding")
						c.Request.Header.Del("Content-Length")
					}
				}
			}
		*/
	}
}
