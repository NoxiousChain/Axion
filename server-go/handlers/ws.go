package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

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
			conn.WriteJSON(msg) //nolint:errcheck
		}
		hub.mu.RUnlock()
	}
}

func (hub *Hub) Broadcast(msg any) {
	select {
	case hub.send <- msg:
	default:
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
// configured allowlist. If empty, only same-host connections are accepted.
func (h *Handler) wsUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true // non-browser client
			}
			if len(h.corsOrigins) == 0 {
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

// WebSocket — GET /api/ws
//
// Authentication is performed via the first message rather than a query-string
// token, preventing JWT leakage in server access logs and browser history (C2).
//
// Protocol:
//   client → server: {"type":"auth","token":"<JWT>"}
//   server → client: {"type":"auth_ok"}   — then normal event stream begins
//   server closes with ClosePolicyViolation if auth fails or times out.
func (h *Handler) WebSocket(c *gin.Context) {
	upgrader := h.wsUpgrader()
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}

	// Require auth message within 10 seconds of connect.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	var authMsg struct {
		Type  string `json:"type"`
		Token string `json:"token"`
	}
	if err := conn.ReadJSON(&authMsg); err != nil || authMsg.Type != "auth" || authMsg.Token == "" {
		conn.WriteMessage(websocket.CloseMessage, //nolint:errcheck
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "auth required"))
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	_, actor, ok := middleware.ValidateJWT(h.getKey(), authMsg.Token)
	if !ok {
		conn.WriteMessage(websocket.CloseMessage, //nolint:errcheck
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "invalid token"))
		conn.Close()
		return
	}

	conn.WriteJSON(gin.H{"type": "auth_ok"}) //nolint:errcheck

	h.hub.register(conn)
	ctx := c.Request.Context()
	h.db.Audit(ctx, fmt.Sprint(actor), "ws_connect", "", "") //nolint:errcheck

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}

	h.hub.unregister(conn)
	conn.Close()
	h.db.Audit(ctx, fmt.Sprint(actor), "ws_disconnect", "", "") //nolint:errcheck
}
