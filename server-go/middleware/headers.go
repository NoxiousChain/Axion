package middleware

import (
	"github.com/gin-gonic/gin"
)

// SecurityHeaders adds defense-in-depth HTTP response headers to every
// response. Apply globally before route groups (H4).
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent MIME-type sniffing
		c.Header("X-Content-Type-Options", "nosniff")
		// Disallow framing — prevents clickjacking
		c.Header("X-Frame-Options", "DENY")
		// Modern browsers use CSP for XSS; the legacy header causes double-reporting
		c.Header("X-XSS-Protection", "0")
		// Limit referrer information on cross-origin requests
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		// CSP: locked down to same-origin; allow inline styles for SvelteKit,
		// ws/wss for the WebSocket feed, and data: URIs for chart images.
		c.Header("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self' ws: wss:; "+
				"frame-ancestors 'none'")
		// HSTS: only sent over TLS to avoid breaking plain-HTTP dev setups
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}
		c.Next()
	}
}
