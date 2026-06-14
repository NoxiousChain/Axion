package middleware

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/pbkdf2"
)

const (
	CtxRole     = "axion_role"
	CtxActor    = "axion_actor"
	CtxIsHuman  = "axion_is_human"
)

// jwtSecret derives the HS256 signing key from the API key — must match tacnet_sec/server/auth.py.
func jwtSecret(apiKey string) []byte {
	return pbkdf2.Key([]byte(apiKey), []byte("axion-jwt-v1"), 100_000, 32, sha256.New)
}

// Auth validates X-Axion-Key or Bearer JWT; sets role/actor in context.
func Auth(getKey func() string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := getKey()

		// Machine token via header
		if k := c.GetHeader("X-Axion-Key"); k != "" {
			if k == key {
				c.Set(CtxRole, "__machine__")
				c.Set(CtxActor, "__machine__")
				c.Set(CtxIsHuman, false)
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "invalid API key"})
			return
		}

		// Bearer JWT
		authHdr := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHdr, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "authentication required"})
			return
		}
		tokenStr := strings.TrimPrefix(authHdr, "Bearer ")

		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return jwtSecret(key), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "invalid token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "malformed claims"})
			return
		}

		c.Set(CtxRole, claims["role"])
		c.Set(CtxActor, claims["sub"])
		c.Set(CtxIsHuman, true)
		c.Next()
	}
}

// AuthWS is Auth adapted for WebSocket upgrade requests (token in query param).
func AuthWS(getKey func() string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.Query("token")
		key := getKey()
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return jwtSecret(key), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "invalid token"})
			return
		}
		claims := token.Claims.(jwt.MapClaims)
		c.Set(CtxRole, claims["role"])
		c.Set(CtxActor, claims["sub"])
		c.Set(CtxIsHuman, true)
		c.Next()
	}
}

func RequireAdmin() gin.HandlerFunc {
	return requireRole("admin")
}

func RequireOperator() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get(CtxRole)
		switch fmt.Sprint(role) {
		case "operator", "admin", "__machine__":
			c.Next()
		default:
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"detail": "operator or admin required"})
		}
	}
}

func requireRole(required string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get(CtxRole)
		if fmt.Sprint(role) != required {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"detail": required + " role required"})
			return
		}
		c.Next()
	}
}

// JSONLogger emits structured request logs.
func JSONLogger() gin.HandlerFunc { return gin.Logger() }

// BodySizeLimit rejects requests exceeding maxBytes before they hit a handler.
func BodySizeLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxBytes {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge,
				gin.H{"detail": "request body too large"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}
