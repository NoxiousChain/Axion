package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CORS adds CORS response headers for allowed origins.
// If allowedOrigins is empty no cross-origin headers are set and browsers will
// block cross-origin requests, which is the secure default.
// Preflight OPTIONS requests for unlisted origins receive 403.
func CORS(allowedOrigins []string) gin.HandlerFunc {
	set := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		set[o] = true
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		allowed := origin != "" && set[origin]

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Authorization, X-Axion-Key, Content-Type")
			c.Header("Access-Control-Max-Age", "86400")
		}

		if c.Request.Method == http.MethodOptions {
			if allowed {
				c.AbortWithStatus(http.StatusNoContent)
			} else {
				c.AbortWithStatus(http.StatusForbidden)
			}
			return
		}

		c.Next()
	}
}
