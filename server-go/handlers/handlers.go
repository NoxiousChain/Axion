// Package handlers wires all HTTP + WebSocket handlers for the Axion Go server.
// Each sub-file (auth.go, alerts.go, …) adds methods to the Handler type.
package handlers

import (
	"net/http"
	"sync"
	"time"

	"github.com/axion/server/db"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Handler struct {
	db              *db.DB
	hub             *Hub
	getKey          func() string
	mu              sync.RWMutex
	key             string
	corsOrigins     []string
	certExpiry      *time.Time // M3: TLS cert expiry; nil when not running TLS
	correlateWindow float64    // M6: incident correlation window in seconds (default 300)
}

func New(d *db.DB, initialKey string, hub *Hub, corsOrigins []string) *Handler {
	h := &Handler{
		db:              d,
		hub:             hub,
		key:             initialKey,
		corsOrigins:     corsOrigins,
		correlateWindow: 300,
	}
	h.getKey = func() string {
		h.mu.RLock()
		defer h.mu.RUnlock()
		return h.key
	}
	d.SetAPIKey(initialKey)
	return h
}

// SetCertExpiry records the TLS certificate expiry time so the Ready handler
// can surface an early warning when expiry is imminent (M3).
func (h *Handler) SetCertExpiry(t time.Time) { h.certExpiry = &t }

// SetCorrelateWindow sets the incident-correlation time window in seconds (M6).
func (h *Handler) SetCorrelateWindow(seconds float64) { h.correlateWindow = seconds }

func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "ts": time.Now().Unix()})
}

func (h *Handler) Ready(c *gin.Context) {
	ctx := c.Request.Context()
	if err := h.db.Pool.Ping(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "db unreachable"})
		return
	}

	// M3: surface cert expiry in /api/ready when less than 7 days remain.
	if h.certExpiry != nil {
		daysLeft := int(time.Until(*h.certExpiry).Hours() / 24)
		if daysLeft < 7 {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":           "tls cert expiring",
				"cert_expiry":      h.certExpiry.UTC().Format(time.RFC3339),
				"cert_days_remain": daysLeft,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":           "ready",
			"cert_expiry":      h.certExpiry.UTC().Format(time.RFC3339),
			"cert_days_remain": daysLeft,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

func (h *Handler) Metrics(c *gin.Context) {
	promhttp.Handler().ServeHTTP(c.Writer, c.Request)
}
