package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"os/signal"
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

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://axion:axion@localhost:5432/axion?sslmode=disable"
	}

	database, err := db.New(dsn)
	if err != nil {
		log.Fatalf("DB connect: %v", err)
	}
	defer database.Close()

	if err := db.Migrate(database); err != nil {
		log.Fatalf("Migration: %v", err)
	}

	// Bootstrap admin on first run (no-op if users table already has rows).
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

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.JSONLogger())
	r.Use(middleware.BodySizeLimit(1 << 20))
	r.Use(middleware.CORS(corsOrigins))

	// Public
	r.GET("/api/health", h.Health)
	r.GET("/api/ready", h.Ready)
	r.POST("/api/login", middleware.LoginRateLimit(10, time.Minute), h.Login)
	r.GET("/metrics", h.Metrics)

	// Serve SvelteKit static build (if present)
	r.Static("/app", "./dashboard/build")

	authMW := middleware.Auth(getKey)

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

		// Audit (admin)
		api.GET("/audit", middleware.RequireAdmin(), h.ListAudit)
		api.GET("/audit/verify", middleware.RequireAdmin(), h.VerifyAudit)

		// Alerts
		api.POST("/alerts", middleware.RequireOperator(), h.IngestAlert)
		api.GET("/alerts", h.ListAlerts)
		api.POST("/alerts/:id/ack", middleware.RequireOperator(), h.AckAlert)

		// Stats + incidents (any authenticated)
		api.GET("/stats", h.Stats)
		api.GET("/incidents", h.ListIncidents)
		api.GET("/incidents/:id", h.GetIncident)
		api.POST("/incidents/:id/ack", middleware.RequireOperator(), h.AckIncident)
	}

	// WebSocket (JWT via query param)
	r.GET("/api/ws", middleware.AuthWS(getKey), h.WebSocket)

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

// parseCORSOrigins splits a comma-separated list of allowed origins.
func parseCORSOrigins(s string) []string {
	var origins []string
	for _, o := range strings.Split(s, ",") {
		if t := strings.TrimSpace(o); t != "" {
			origins = append(origins, t)
		}
	}
	return origins
}
