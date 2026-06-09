package middleware

import (
	"compress/gzip"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	gzipEncoding = "gzip"
)

type gzipWriter struct {
	gin.ResponseWriter
	writer *gzip.Writer
}

// Write implementa la interfaz io.Writer
func (g *gzipWriter) Write(data []byte) (int, error) {
	return g.writer.Write(data)
}

// WriteString implementa la interfaz io.StringWriter
func (g *gzipWriter) WriteString(s string) (int, error) {
	return g.Write([]byte(s))
}

// Close cierra el escritor gzip
func (g *gzipWriter) Close() error {
	return g.writer.Close()
}

// GzipOptions contiene las opciones para el middleware GzipMiddleware
type GzipOptions struct {
	ExcludedPaths []string
}

// DefaultGzipOptions devuelve opciones por defecto para el middleware GzipMiddleware
func DefaultGzipOptions() GzipOptions {
	return GzipOptions{
		ExcludedPaths: []string{},
	}
}

// GzipMiddleware comprime las respuestas usando gzip para clientes que lo soportan
func GzipMiddleware(options ...GzipOptions) gin.HandlerFunc {
	var opts GzipOptions
	if len(options) > 0 {
		opts = options[0]
	} else {
		opts = DefaultGzipOptions()
	}

	return func(c *gin.Context) {
		// Verificar si la ruta debe excluirse
		if ShouldSkipGzip(c.Request.URL.Path, opts.ExcludedPaths) {
			c.Next()
			return
		}

		// Manejar descompresión de solicitudes entrantes con gzip - DESACTIVADO TEMPORALMENTE
		/*
			if c.Request.Header.Get("Content-Encoding") == gzipEncoding {
				reader, err := gzip.NewReader(c.Request.Body)
				if err != nil {
					c.AbortWithStatus(http.StatusBadRequest)
					return
				}
				defer reader.Close()

				// Reemplazar el body original con el body descomprimido
				data, err := io.ReadAll(reader)
				if err != nil {
					c.AbortWithStatus(http.StatusBadRequest)
					return
				}

				c.Request.Body = io.NopCloser(strings.NewReader(string(data)))
				c.Request.ContentLength = int64(len(data))
				c.Request.Header.Del("Content-Encoding")
				c.Request.Header.Del("Content-Length")
			}
		*/

		// Manejar compresión de respuestas salientes con gzip
		if !strings.Contains(c.Request.Header.Get("Accept-Encoding"), gzipEncoding) {
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
