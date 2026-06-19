package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/axion/server/db"
	"github.com/axion/server/handlers"
	"github.com/axion/server/middleware"
	"github.com/gin-gonic/gin"
)

func main() {
	apiKey := os.Getenv("AXION_API_KEY")
	if apiKey == "" {
		log.Fatal("AXION_API_KEY environment variable is required")
	}

	// C1: DATABASE_URL is required — no insecure hardcoded fallback.
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	database, err := db.New(dsn)
	if err != nil {
		log.Fatalf("DB connect: %v", err)
	}
	defer database.Close()

	if err := db.Migrate(database); err != nil {
		log.Fatalf("Migration: %v", err)
	}

	adminPw := os.Getenv("AXION_ADMIN_PASSWORD")
	if adminPw == "" {
		b := make([]byte, 16)
		rand.Read(b) //nolint:errcheck
		adminPw = hex.EncodeToString(b)
		log.Printf("AXION_ADMIN_PASSWORD not set — generated admin password: %s", adminPw)
	}
	if err := database.EnsureBootstrapAdmin(context.Background(), "admin", adminPw); err != nil {
		log.Fatalf("Bootstrap admin: %v", err)
	}

	corsOrigins := parseCORSOrigins(os.Getenv("AXION_CORS_ORIGINS"))

	hub := handlers.NewHub()
	go hub.Run()

	h := handlers.New(database, apiKey, hub, corsOrigins)
	getKey := func() string { return apiKey }

	// M4: replace in-memory rate limiters with Postgres-backed ones so state
	// survives restarts and is shared across all instances in HA deployments.
	middleware.SetMachineKeyFailBackend(database.RateLimitFn("machine_key_fail", 20, 5*time.Minute))

	// L2: per-node API key lookup so each edge node can use its own key.
	middleware.SetNodeKeyLookup(database.LookupNodeKey)

	// Periodic cleanup of expired rate_limit rows (prevents unbounded growth).
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			database.CleanupRateLimits(context.Background())
		}
	}()

	// H2: alert ingest rate limit (configurable via AXION_INGEST_RATE_LIMIT).
	ingestLimit := 500
	if v := os.Getenv("AXION_INGEST_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ingestLimit = n
		}
	}

	// M6: incident correlation window (default 300 s, configurable).
	if v := os.Getenv("AXION_CORRELATE_WINDOW_SECONDS"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil && n > 0 {
			h.SetCorrelateWindow(n)
		}
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.JSONLogger())
	r.Use(middleware.BodySizeLimit(1 << 20))
	r.Use(middleware.CORS(corsOrigins))
	r.Use(middleware.SecurityHeaders()) // H4

	// Public
	r.GET("/api/health", h.Health)
	r.GET("/api/ready", h.Ready)
	r.POST("/api/login", middleware.LoginRateLimitDB(database.RateLimitFn("login", 10, time.Minute)), h.Login)
	r.GET("/metrics", h.Metrics)

	// Serve SvelteKit static build (if present)
	r.Static("/app", "./dashboard/build")

	// H3: pass session-validity checker so revoked JWTs are rejected
	authMW := middleware.Auth(getKey, database.IsSessionValid)

	api := r.Group("/api", authMW)
	{
		api.POST("/rotate-key", middleware.RequireAdmin(), h.RotateKey)

		// Users (admin)
		api.GET("/users", middleware.RequireAdmin(), h.ListUsers)
		api.POST("/users", middleware.RequireAdmin(), h.CreateUser)
		api.DELETE("/users/:username", middleware.RequireAdmin(), h.DeleteUser)
		api.POST("/users/:username/totp", middleware.RequireAdmin(), h.EnrolTOTP)
		api.DELETE("/users/:username/totp", middleware.RequireAdmin(), h.DisableTOTP)
		api.POST("/users/:username/unlock", middleware.RequireAdmin(), h.UnlockUser)
		api.POST("/users/:username/revoke-sessions", middleware.RequireAdmin(), h.RevokeUserSessions) // H3

		// Node keys (admin) — L2: per-node API keys
		api.GET("/nodes", middleware.RequireAdmin(), h.ListNodeKeys)
		api.POST("/nodes", middleware.RequireAdmin(), h.CreateNodeKey)
		api.DELETE("/nodes/:node_id", middleware.RequireAdmin(), h.DeleteNodeKey)

		// Audit (admin)
		api.GET("/audit", middleware.RequireAdmin(), h.ListAudit)
		api.GET("/audit/verify", middleware.RequireAdmin(), h.VerifyAudit)

		// Alerts (H2: per-IP ingest rate limit)
		api.POST("/alerts", middleware.RequireOperator(),
			middleware.AlertIngestRateLimit(ingestLimit, time.Minute), h.IngestAlert)
		api.GET("/alerts", h.ListAlerts)
		api.POST("/alerts/:id/ack", middleware.RequireOperator(), h.AckAlert)

		// Stats + incidents (any authenticated)
		api.GET("/stats", h.Stats)
		api.GET("/incidents", h.ListIncidents)
		api.GET("/incidents/:id", h.GetIncident)
		api.POST("/incidents/:id/ack", middleware.RequireOperator(), h.AckIncident)
	}

	// C2: WebSocket auth is performed via first message, not query-string token.
	// No AuthWS middleware here — authentication happens inside the handler.
	r.GET("/api/ws", h.WebSocket)

	addr := os.Getenv("AXION_ADDR")
	if addr == "" {
		addr = ":8000"
	}

	srv := &http.Server{Addr: addr, Handler: r}

	go func() {
		log.Printf("Axion Go server listening on %s", addr)
		certFile := os.Getenv("AXION_TLS_CERT")
		keyFile := os.Getenv("AXION_TLS_KEY")
		if certFile != "" && keyFile != "" {
			// M3: check cert expiry at startup; warn at 30 days, expose in /api/ready at 7 days.
			if expiry, err := parseCertExpiry(certFile); err != nil {
				log.Printf("WARNING: could not parse TLS cert for expiry check: %v", err)
			} else {
				daysLeft := int(time.Until(expiry).Hours() / 24)
				if daysLeft < 0 {
					log.Printf("ERROR: TLS certificate expired %d days ago (%s)", -daysLeft, expiry.Format(time.RFC3339))
				} else if daysLeft < 30 {
					log.Printf("WARNING: TLS certificate expires in %d days (%s)", daysLeft, expiry.Format(time.RFC3339))
				} else {
					log.Printf("TLS certificate valid for %d more days (expires %s)", daysLeft, expiry.Format(time.RFC3339))
				}
				h.SetCertExpiry(expiry)
			}
			if err := srv.ListenAndServeTLS(certFile, keyFile); err != http.ErrServerClosed {
				log.Fatalf("TLS ListenAndServe: %v", err)
			}
		} else {
			if err := srv.ListenAndServe(); err != http.ErrServerClosed {
				log.Fatalf("ListenAndServe: %v", err)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutdown signal received, draining connections…")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	log.Println("Server stopped")
}

func parseCORSOrigins(s string) []string {
	var origins []string
	for _, o := range strings.Split(s, ",") {
		if t := strings.TrimSpace(o); t != "" {
			origins = append(origins, t)
		}
	}
	return origins
}

// parseCertExpiry reads the first PEM certificate block from certFile and
// returns its NotAfter time so the server can warn before it expires (M3).
func parseCertExpiry(certFile string) (time.Time, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block found in %s", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	return cert.NotAfter, nil
}
