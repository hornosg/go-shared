package config

import (
	"github.com/gin-gonic/gin"

	"github.com/hornosg/go-shared/infrastructure/middleware"
)

// SharedConfig contiene la configuración para el módulo compartido
type SharedConfig struct {
	EnableGzip            bool
	AlwaysTryDecompress   bool
	ForceGzipCompression  bool
	ForceGzipCheckSupport bool     // Verifica si el cliente soporta gzip antes de forzar compresión
	ForceGzipPaths        []string // Rutas donde forzar compresión
	GzipExcludedPaths     []string
}

// DefaultSharedConfig devuelve una configuración por defecto
func DefaultSharedConfig() SharedConfig {
	return SharedConfig{
		EnableGzip:            true,
		AlwaysTryDecompress:   true,
		ForceGzipCompression:  false,
		ForceGzipCheckSupport: true,
		ForceGzipPaths:        []string{"/iam/api/v1/users"},
		GzipExcludedPaths:     []string{"/health", "/metrics", "/api-docs", "/iam/api/v1/auth"},
	}
}

// SetupSharedMiddleware configura los middlewares compartidos
func SetupSharedMiddleware(router *gin.Engine, config SharedConfig) {
	if config.AlwaysTryDecompress {
		router.Use(middleware.GzipReader())
	}

	if config.EnableGzip {
		gzipOpts := middleware.GzipOptions{
			ExcludedPaths: config.GzipExcludedPaths,
		}
		router.Use(middleware.GzipMiddleware(gzipOpts))

		if config.ForceGzipCompression && len(config.ForceGzipPaths) > 0 {
			forceGzipOpts := middleware.ForceGzipOptions{
				CheckClientSupport: config.ForceGzipCheckSupport,
			}
			for _, path := range config.ForceGzipPaths {
				router.Group(path).Use(middleware.ForceGzipMiddleware(forceGzipOpts))
			}
		}
	}
}
