package middleware

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/pbkdf2"
)

const (
	CtxRole    = "axion_role"
	CtxActor   = "axion_actor"
	CtxIsHuman = "axion_is_human"
)

// machineKeyFailLimiter tracks failed X-Axion-Key attempts per IP (in-memory fallback).
var machineKeyFailLimiter = newIPRateLimiter(20, 5*time.Minute)

// globalMachineKeyFailBackend replaces the in-memory fail limiter with a
// Postgres-backed one when set via SetMachineKeyFailBackend (M4).
var globalMachineKeyFailBackend func(context.Context, string) bool

// globalNodeKeyLookup resolves per-node API keys when set via SetNodeKeyLookup (L2).
var globalNodeKeyLookup func(context.Context, string) string

// NodeKeyLookup maps an API key to a node ID ("" = not found).
type NodeKeyLookup = func(context.Context, string) string

// SetMachineKeyFailBackend replaces the in-memory failed-key rate limiter with a
// persistent backend for multi-instance safety (M4). Call once at startup.
func SetMachineKeyFailBackend(fn func(context.Context, string) bool) {
	globalMachineKeyFailBackend = fn
}

// SetNodeKeyLookup configures the per-node API key resolver (L2).
// Call once at startup after the DB is initialised.
func SetNodeKeyLookup(fn func(context.Context, string) string) {
	globalNodeKeyLookup = fn
}

// jwtSecret derives the HS256 signing key — must match tacnet_sec/server/auth.py.
func jwtSecret(apiKey string) []byte {
	return pbkdf2.Key([]byte(apiKey), []byte("axion-jwt-v1"), 100_000, 32, sha256.New)
}

// SessionChecker returns true when the JWT (identified by issuedAt) is still
// valid for the given username. Nil means "skip check".
type SessionChecker func(ctx context.Context, username string, issuedAt time.Time) bool

// Auth validates X-Axion-Key or Bearer JWT and sets role/actor in the context.
// An optional SessionChecker is used to reject tokens issued before a user's
// last session-revocation event (H3).
func Auth(getKey func() string, checkSession ...SessionChecker) gin.HandlerFunc {
	var checker SessionChecker
	if len(checkSession) > 0 {
		checker = checkSession[0]
	}

	return func(c *gin.Context) {
		key := getKey()

		// Machine token via header (C3: rate-limit failed attempts per IP)
		if k := c.GetHeader("X-Axion-Key"); k != "" {
			if k == key {
				c.Set(CtxRole, "__machine__")
				c.Set(CtxActor, "__machine__")
				c.Set(CtxIsHuman, false)
				c.Next()
				return
			}
			// L2: check per-node API keys before treating as a failure
			if nkl := globalNodeKeyLookup; nkl != nil {
				if nodeID := nkl(c.Request.Context(), k); nodeID != "" {
					c.Set(CtxRole, "__machine__")
					c.Set(CtxActor, nodeID) // auditable node identity, not generic "__machine__"
					c.Set(CtxIsHuman, false)
					c.Next()
					return
				}
			}
			// Failed attempt — M4: use Postgres backend when configured
			if backend := globalMachineKeyFailBackend; backend != nil {
				ctx, cancel := context.WithTimeout(c.Request.Context(), 300*time.Millisecond)
				allowed := backend(ctx, c.ClientIP())
				cancel()
				if !allowed {
					c.AbortWithStatusJSON(http.StatusTooManyRequests,
						gin.H{"detail": "too many invalid key attempts"})
					return
				}
			} else if !machineKeyFailLimiter.allow(c.ClientIP()) {
				c.AbortWithStatusJSON(http.StatusTooManyRequests,
					gin.H{"detail": "too many invalid key attempts"})
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

		claims, ok := parseJWT(key, tokenStr)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "invalid token"})
			return
		}

		// H3: reject tokens issued before the user's last session revocation
		if checker != nil {
			if iatVal, hasIAT := claims["iat"].(float64); hasIAT {
				sub := fmt.Sprint(claims["sub"])
				iat := time.Unix(int64(iatVal), 0)
				if !checker(c.Request.Context(), sub, iat) {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "session revoked"})
					return
				}
			}
		}

		c.Set(CtxRole, claims["role"])
		c.Set(CtxActor, claims["sub"])
		c.Set(CtxIsHuman, true)
		c.Next()
	}
}

// ValidateJWT parses and validates a JWT string without needing a Gin context.
// Used by handlers that receive the token out-of-band (e.g. WebSocket first
// message) to avoid exposing the token in URL query strings (C2).
// Returns role, actor, and whether the token is valid.
func ValidateJWT(key, tokenStr string) (role, actor string, ok bool) {
	claims, valid := parseJWT(key, tokenStr)
	if !valid {
		return "", "", false
	}
	return fmt.Sprint(claims["role"]), fmt.Sprint(claims["sub"]), true
}

// parseJWT validates signature and algorithm, returns claims on success.
func parseJWT(key, tokenStr string) (jwt.MapClaims, bool) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtSecret(key), nil
	})
	if err != nil || !token.Valid {
		return nil, false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, false
	}
	return claims, true
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
