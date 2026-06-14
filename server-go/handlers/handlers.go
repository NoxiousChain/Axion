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
	db          *db.DB
	hub         *Hub
	getKey      func() string
	mu          sync.RWMutex
	key         string
	corsOrigins []string
}

func New(d *db.DB, initialKey string, hub *Hub, corsOrigins []string) *Handler {
	h := &Handler{db: d, hub: hub, key: initialKey, corsOrigins: corsOrigins}
	h.getKey = func() string {
		h.mu.RLock()
		defer h.mu.RUnlock()
		return h.key
	}
	d.SetAPIKey(initialKey)
	return h
}

func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "ts": time.Now().Unix()})
}

func (h *Handler) Ready(c *gin.Context) {
	ctx := c.Request.Context()
	if err := h.db.Pool.Ping(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "db unreachable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

func (h *Handler) Metrics(c *gin.Context) {
	promhttp.Handler().ServeHTTP(c.Writer, c.Request)
}
