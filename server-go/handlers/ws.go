package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/axion/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// Hub manages connected WebSocket clients and broadcasts messages.
type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]bool
	send    chan any
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[*websocket.Conn]bool),
		send:    make(chan any, 256),
	}
}

func (hub *Hub) Run() {
	for msg := range hub.send {
		hub.mu.RLock()
		for conn := range hub.clients {
			// Non-blocking write; slow clients are dropped
			conn.WriteJSON(msg) //nolint:errcheck
		}
		hub.mu.RUnlock()
	}
}

func (hub *Hub) Broadcast(msg any) {
	select {
	case hub.send <- msg:
	default: // drop if channel full
	}
}

func (hub *Hub) register(c *websocket.Conn) {
	hub.mu.Lock()
	hub.clients[c] = true
	hub.mu.Unlock()
}

func (hub *Hub) unregister(c *websocket.Conn) {
	hub.mu.Lock()
	delete(hub.clients, c)
	hub.mu.Unlock()
}

// wsUpgrader builds an upgrader that validates the Origin header against the
// configured allowlist. If the allowlist is empty, only same-host connections
// are accepted (safe default for the dashboard served on the same origin).
func (h *Handler) wsUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true // non-browser client (e.g. curl, test harness)
			}
			if len(h.corsOrigins) == 0 {
				// No explicit allowlist: permit same-host only.
				host := origin
				if i := strings.Index(origin, "://"); i >= 0 {
					host = origin[i+3:]
				}
				return host == r.Host
			}
			for _, o := range h.corsOrigins {
				if o == origin {
					return true
				}
			}
			return false
		},
	}
}

// WebSocket — GET /api/ws?token=JWT
func (h *Handler) WebSocket(c *gin.Context) {
	actor, _ := c.Get(middleware.CtxActor)
	ctx := c.Request.Context()

	upgrader := h.wsUpgrader()
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	h.hub.register(conn)
	h.db.Audit(ctx, fmt.Sprint(actor), "ws_connect", "", "")

	// Block until client disconnects (read loop)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}

	h.hub.unregister(conn)
	h.db.Audit(ctx, fmt.Sprint(actor), "ws_disconnect", "", "")
}
