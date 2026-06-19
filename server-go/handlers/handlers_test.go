// Run with: go test ./... (from server-go/)
//
// Uses a test-scoped in-memory PostgreSQL via testcontainers-go, or falls back
// to a real DATABASE_URL when set (CI/CD with a Postgres service container).
package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/axion/server/db"
	"github.com/axion/server/handlers"
	"github.com/axion/server/middleware"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"github.com/golang-jwt/jwt/v5"
)

const testAPIKey = "test-api-key-1234567890"

// ─── Test fixtures ──────────────────────────────────────────────────────────

func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping integration tests (set it to run against a real Postgres)")
	}
	database, err := db.New(dsn)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		// Tear down test data
		database.Pool.Exec(context.Background(), `
			TRUNCATE alerts, incidents, audit_log, users RESTART IDENTITY CASCADE`)
		database.Close()
	})
	return database
}

func newRouter(t *testing.T, database *db.DB) (*gin.Engine, *handlers.Handler) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	hub := handlers.NewHub()
	go hub.Run()
	h := handlers.New(database, testAPIKey, hub, nil)
	getKey := func() string { return testAPIKey }

	r := gin.New()
	r.POST("/api/login", h.Login)
	r.GET("/api/health", h.Health)
	r.GET("/api/ready", h.Ready)

	authMW := middleware.Auth(getKey)
	api := r.Group("/api", authMW)
	api.POST("/alerts", middleware.RequireOperator(), h.IngestAlert)
	api.GET("/alerts", h.ListAlerts)
	api.POST("/alerts/:id/ack", middleware.RequireOperator(), h.AckAlert)
	api.GET("/stats", h.Stats)
	api.GET("/incidents", h.ListIncidents)
	api.GET("/incidents/:id", h.GetIncident)
	api.POST("/incidents/:id/ack", middleware.RequireOperator(), h.AckIncident)
	api.GET("/users", middleware.RequireAdmin(), h.ListUsers)
	api.POST("/users", middleware.RequireAdmin(), h.CreateUser)
	api.DELETE("/users/:username", middleware.RequireAdmin(), h.DeleteUser)
	api.POST("/users/:username/totp", middleware.RequireAdmin(), h.EnrolTOTP)
	api.DELETE("/users/:username/totp", middleware.RequireAdmin(), h.DisableTOTP)
	api.POST("/users/:username/unlock", middleware.RequireAdmin(), h.UnlockUser)
	api.POST("/users/:username/revoke-sessions", middleware.RequireAdmin(), h.RevokeUserSessions)
	api.GET("/audit", middleware.RequireAdmin(), h.ListAudit)
	api.GET("/audit/verify", middleware.RequireAdmin(), h.VerifyAudit)

	return r, h
}

// newRouterWithSessionCheck builds a router that wires in IsSessionValid so
// that JWT tokens issued before a revocation event are rejected (H3).
func newRouterWithSessionCheck(t *testing.T, database *db.DB) (*gin.Engine, *handlers.Handler) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	hub := handlers.NewHub()
	go hub.Run()
	h := handlers.New(database, testAPIKey, hub, nil)
	getKey := func() string { return testAPIKey }
	checker := middleware.SessionChecker(database.IsSessionValid)

	r := gin.New()
	r.POST("/api/login", h.Login)

	authMW := middleware.Auth(getKey, checker)
	api := r.Group("/api", authMW)
	api.GET("/alerts", h.ListAlerts)
	api.GET("/users", middleware.RequireAdmin(), h.ListUsers)
	api.POST("/users", middleware.RequireAdmin(), h.CreateUser)
	api.POST("/users/:username/revoke-sessions", middleware.RequireAdmin(), h.RevokeUserSessions)

	return r, h
}

func machineHeader() http.Header {
	h := http.Header{}
	h.Set("X-Axion-Key", testAPIKey)
	return h
}

func adminJWT(t *testing.T) string {
	t.Helper()
	secret := pbkdf2.Key([]byte(testAPIKey), []byte("axion-jwt-v1"), 100_000, 32, sha256.New)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  "admin",
		"role": "admin",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func bearerHeader(token string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	return h
}

func do(t *testing.T, r *gin.Engine, method, path string, body any, headers http.Header) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ─── Health / Ready ─────────────────────────────────────────────────────────

func TestHealth(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	w := do(t, r, "GET", "/api/health", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("health: want 200, got %d", w.Code)
	}
}

func TestReady(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	w := do(t, r, "GET", "/api/ready", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("ready: want 200, got %d", w.Code)
	}
}

// ─── Authentication ─────────────────────────────────────────────────────────

func TestMachineTokenAcceptsValidKey(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	body := map[string]any{
		"detector": "DDoSDetector", "title": "test", "severity": "low",
	}
	w := do(t, r, "POST", "/api/alerts", body, machineHeader())
	if w.Code != http.StatusCreated {
		t.Fatalf("machine ingest: want 201, got %d — body: %s", w.Code, w.Body)
	}
}

func TestMachineTokenRejectsWrongKey(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	h := http.Header{}
	h.Set("X-Axion-Key", "wrong-key")
	w := do(t, r, "GET", "/api/alerts", nil, h)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: want 401, got %d", w.Code)
	}
}

func TestNoAuthReturns401(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	w := do(t, r, "GET", "/api/alerts", nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: want 401, got %d", w.Code)
	}
}

// ─── Alert CRUD ──────────────────────────────────────────────────────────────

func TestIngestAndListAlert(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	payload := map[string]any{
		"detector": "DDoSDetector",
		"title":    "Flood toward 10.0.0.1",
		"severity": "high",
		"node_id":  "node-001",
		"details":  map[string]any{"pkt_rate": 250.0},
	}
	w := do(t, r, "POST", "/api/alerts", payload, machineHeader())
	if w.Code != http.StatusCreated {
		t.Fatalf("ingest: want 201, got %d — %s", w.Code, w.Body)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	alertID := resp["alert_id"]
	if alertID == nil {
		t.Fatal("response missing alert_id")
	}

	w2 := do(t, r, "GET", "/api/alerts", nil, machineHeader())
	if w2.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", w2.Code)
	}
	var list []map[string]any
	json.NewDecoder(w2.Body).Decode(&list)
	if len(list) == 0 {
		t.Fatal("expected at least one alert in list")
	}
	if list[0]["detector"] != "DDoSDetector" {
		t.Errorf("detector mismatch: got %v", list[0]["detector"])
	}
}

func TestAlertFilterBySeverity(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	for _, sev := range []string{"low", "high", "critical"} {
		do(t, r, "POST", "/api/alerts",
			map[string]any{"detector": "test", "title": "t", "severity": sev},
			machineHeader())
	}

	w := do(t, r, "GET", "/api/alerts?severity=high", nil, machineHeader())
	var list []map[string]any
	json.NewDecoder(w.Body).Decode(&list)
	for _, a := range list {
		if a["severity"] != "high" {
			t.Errorf("filter returned wrong severity: %v", a["severity"])
		}
	}
}

func TestAckAlert(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	w := do(t, r, "POST", "/api/alerts",
		map[string]any{"detector": "test", "title": "t", "severity": "medium"},
		machineHeader())
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	id := int(resp["alert_id"].(float64))

	wAck := do(t, r, "POST", fmt.Sprintf("/api/alerts/%d/ack", id),
		map[string]any{"by": "analyst", "note": "checked"},
		machineHeader())
	if wAck.Code != http.StatusOK {
		t.Fatalf("ack: want 200, got %d", wAck.Code)
	}
}

func TestAckAlertNotFound(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	w := do(t, r, "POST", "/api/alerts/99999/ack", map[string]any{}, machineHeader())
	if w.Code != http.StatusNotFound {
		t.Fatalf("ack missing: want 404, got %d", w.Code)
	}
}

// ─── Incidents ───────────────────────────────────────────────────────────────

func TestAlertIngestCreatesIncident(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	w := do(t, r, "POST", "/api/alerts",
		map[string]any{
			"detector": "DDoSDetector", "title": "flood", "severity": "high",
			"node_id": "edge-01",
			"details": map[string]any{"dst_ip": "10.0.0.1"},
		},
		machineHeader())
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["incident_id"] == nil {
		t.Error("expected incident_id in response")
	}

	w2 := do(t, r, "GET", "/api/incidents", nil, machineHeader())
	var incidents []map[string]any
	json.NewDecoder(w2.Body).Decode(&incidents)
	if len(incidents) == 0 {
		t.Fatal("expected at least one incident")
	}
}

func TestRelatedAlertsGroupIntoSameIncident(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	ts := float64(time.Now().Unix())
	details := map[string]any{"dst_ip": "10.5.5.5"}

	var incID1, incID2 float64
	for i, dest := range []float64{ts, ts + 60} {
		_ = i
		w := do(t, r, "POST", "/api/alerts",
			map[string]any{
				"detector": "DDoSDetector", "title": "flood", "severity": "high",
				"ts": dest, "details": details,
			},
			machineHeader())
		var resp map[string]any
		json.NewDecoder(w.Body).Decode(&resp)
		if i == 0 {
			incID1 = resp["incident_id"].(float64)
		} else {
			incID2 = resp["incident_id"].(float64)
		}
	}
	if incID1 != incID2 {
		t.Errorf("related alerts should share incident: %v != %v", incID1, incID2)
	}
}

// ─── RBAC ─────────────────────────────────────────────────────────────────

func TestAnalystCannotIngest(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	secret := pbkdf2.Key([]byte(testAPIKey), []byte("axion-jwt-v1"), 100_000, 32, sha256.New)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "alice", "role": "analyst",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, _ := tok.SignedString(secret)

	w := do(t, r, "POST", "/api/alerts",
		map[string]any{"detector": "x", "title": "t", "severity": "low"},
		bearerHeader(signed))
	if w.Code != http.StatusForbidden {
		t.Fatalf("analyst ingest: want 403, got %d", w.Code)
	}
}

func TestAnalystCanListAlerts(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	secret := pbkdf2.Key([]byte(testAPIKey), []byte("axion-jwt-v1"), 100_000, 32, sha256.New)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "alice", "role": "analyst",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, _ := tok.SignedString(secret)

	w := do(t, r, "GET", "/api/alerts", nil, bearerHeader(signed))
	if w.Code != http.StatusOK {
		t.Fatalf("analyst list: want 200, got %d", w.Code)
	}
}

func TestNonAdminCannotListUsers(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	w := do(t, r, "GET", "/api/users", nil, machineHeader())
	if w.Code != http.StatusForbidden {
		t.Fatalf("machine list users: want 403, got %d", w.Code)
	}
}

// ─── User management ─────────────────────────────────────────────────────────

func TestCreateAndDeleteUser(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	jwt := adminJWT(t)

	w := do(t, r, "POST", "/api/users",
		map[string]any{"username": "testuser", "password": "P@ssword123", "role": "analyst"},
		bearerHeader(jwt))
	if w.Code != http.StatusCreated {
		t.Fatalf("create user: want 201, got %d — %s", w.Code, w.Body)
	}

	w2 := do(t, r, "GET", "/api/users", nil, bearerHeader(jwt))
	var users []map[string]any
	json.NewDecoder(w2.Body).Decode(&users)
	found := false
	for _, u := range users {
		if u["username"] == "testuser" {
			found = true
		}
	}
	if !found {
		t.Error("created user not in list")
	}

	w3 := do(t, r, "DELETE", "/api/users/testuser", nil, bearerHeader(jwt))
	if w3.Code != http.StatusOK {
		t.Fatalf("delete user: want 200, got %d", w3.Code)
	}
}

func TestCreateUserValidation(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	j := adminJWT(t)

	// Password too short
	w := do(t, r, "POST", "/api/users",
		map[string]any{"username": "x", "password": "short", "role": "analyst"},
		bearerHeader(j))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("short password: want 422, got %d", w.Code)
	}
}

// ─── Stats ───────────────────────────────────────────────────────────────────

func TestStats(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	do(t, r, "POST", "/api/alerts",
		map[string]any{"detector": "DDoSDetector", "title": "t", "severity": "critical"},
		machineHeader())

	w := do(t, r, "GET", "/api/stats", nil, machineHeader())
	if w.Code != http.StatusOK {
		t.Fatalf("stats: want 200, got %d", w.Code)
	}
	var s map[string]any
	json.NewDecoder(w.Body).Decode(&s)
	if s["total_alerts"] == nil {
		t.Error("stats missing total_alerts")
	}
	if s["by_severity"] == nil {
		t.Error("stats missing by_severity")
	}
}

func TestStatsWindowFilter(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	// Two alerts: one "old" (2 hours ago via explicit ts), one current.
	oldTs := float64(time.Now().Add(-2 * time.Hour).UnixMicro()) / 1e6
	do(t, r, "POST", "/api/alerts",
		map[string]any{"detector": "OldDetector", "title": "old", "severity": "low", "ts": oldTs},
		machineHeader())
	do(t, r, "POST", "/api/alerts",
		map[string]any{"detector": "NewDetector", "title": "new", "severity": "high"},
		machineHeader())

	// window_minutes=60 should only see the recent alert.
	w := do(t, r, "GET", "/api/stats?window_minutes=60", nil, machineHeader())
	if w.Code != http.StatusOK {
		t.Fatalf("stats window: want 200, got %d", w.Code)
	}
	var s map[string]any
	json.NewDecoder(w.Body).Decode(&s)
	if int(s["total_alerts"].(float64)) != 1 {
		t.Errorf("window filter: want 1 alert in window, got %v", s["total_alerts"])
	}
	byDet := s["by_detector"].(map[string]any)
	if _, ok := byDet["OldDetector"]; ok {
		t.Error("window filter: OldDetector should not appear in windowed stats")
	}
	// by_node and timeline must be present (even if empty).
	if s["by_node"] == nil {
		t.Error("stats missing by_node")
	}
	if s["timeline"] == nil {
		t.Error("stats missing timeline")
	}
}

// ─── Audit log ───────────────────────────────────────────────────────────────

func TestAuditVerifyPass(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	j := adminJWT(t)

	// Generate some audit rows by ingesting an alert
	do(t, r, "POST", "/api/alerts",
		map[string]any{"detector": "test", "title": "t", "severity": "low"},
		machineHeader())

	w := do(t, r, "GET", "/api/audit/verify", nil, bearerHeader(j))
	if w.Code != http.StatusOK {
		t.Fatalf("audit verify: want 200, got %d", w.Code)
	}
	var result map[string]any
	json.NewDecoder(w.Body).Decode(&result)
	if result["integrity"] != "PASS" {
		t.Errorf("expected integrity PASS, got %v — tampered: %v", result["integrity"], result["tampered_ids"])
	}
}

func TestAuditRequiresAdmin(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	w := do(t, r, "GET", "/api/audit", nil, machineHeader())
	if w.Code != http.StatusForbidden {
		t.Fatalf("audit as machine: want 403, got %d", w.Code)
	}
}

// ─── Input validation ─────────────────────────────────────────────────────────

func TestIngestRejectsUnknownSeverity(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	w := do(t, r, "POST", "/api/alerts",
		map[string]any{"detector": "x", "title": "t", "severity": "extreme"},
		machineHeader())
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad severity: want 422, got %d", w.Code)
	}
}

func TestIngestRejectsMissingTitle(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	w := do(t, r, "POST", "/api/alerts",
		map[string]any{"detector": "x", "severity": "low"},
		machineHeader())
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing title: want 422, got %d", w.Code)
	}
}

// ─── Bug-fix regression: DisableTOTP / UnlockUser 404 ───────────────────────

func TestDisableTOTPNotFound(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	j := adminJWT(t)

	w := do(t, r, "DELETE", "/api/users/ghost/totp", nil, bearerHeader(j))
	if w.Code != http.StatusNotFound {
		t.Fatalf("disable totp nonexistent: want 404, got %d — %s", w.Code, w.Body)
	}
}

func TestUnlockUserNotFound(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	j := adminJWT(t)

	w := do(t, r, "POST", "/api/users/ghost/unlock", nil, bearerHeader(j))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unlock nonexistent: want 404, got %d — %s", w.Code, w.Body)
	}
}

func TestDeleteUserNotFound(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	j := adminJWT(t)

	w := do(t, r, "DELETE", "/api/users/ghost", nil, bearerHeader(j))
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete nonexistent: want 404, got %d — %s", w.Code, w.Body)
	}
}

// ─── Bug-fix regression: AckIncident 404 ────────────────────────────────────

func TestAckIncidentNotFound(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	w := do(t, r, "POST", "/api/incidents/99999/ack", map[string]any{}, machineHeader())
	if w.Code != http.StatusNotFound {
		t.Fatalf("ack missing incident: want 404, got %d — %s", w.Code, w.Body)
	}
}

// ─── Bug-fix regression: ListAlerts q and hide_acked filters ────────────────

func TestListAlertsSearchQuery(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	do(t, r, "POST", "/api/alerts",
		map[string]any{"detector": "DDoSDetector", "title": "Flood toward 192.168.1.1", "severity": "high"},
		machineHeader())
	do(t, r, "POST", "/api/alerts",
		map[string]any{"detector": "MalwareDetector", "title": "Unrelated event", "severity": "low"},
		machineHeader())

	w := do(t, r, "GET", "/api/alerts?q=Flood", nil, machineHeader())
	if w.Code != http.StatusOK {
		t.Fatalf("list with q: want 200, got %d", w.Code)
	}
	var list []map[string]any
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("q filter: expected 1 result, got %d", len(list))
	}
	if list[0]["title"] != "Flood toward 192.168.1.1" {
		t.Errorf("q filter returned wrong alert: %v", list[0]["title"])
	}
}

func TestListAlertsHideAcked(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	// Ingest two alerts
	var id1 float64
	w := do(t, r, "POST", "/api/alerts",
		map[string]any{"detector": "test", "title": "ack-me", "severity": "low"},
		machineHeader())
	json.NewDecoder(w.Body).Decode(&map[string]any{})
	var resp map[string]any
	json.NewDecoder(
		do(t, r, "POST", "/api/alerts",
			map[string]any{"detector": "test", "title": "ack-me", "severity": "low"},
			machineHeader()).Body,
	).Decode(&resp)
	id1 = resp["alert_id"].(float64)

	do(t, r, "POST", "/api/alerts",
		map[string]any{"detector": "test", "title": "keep-me", "severity": "high"},
		machineHeader())

	// Ack the first
	do(t, r, "POST", fmt.Sprintf("/api/alerts/%d/ack", int(id1)),
		map[string]any{}, machineHeader())

	// Without filter: both visible
	w2 := do(t, r, "GET", "/api/alerts", nil, machineHeader())
	var all []map[string]any
	json.NewDecoder(w2.Body).Decode(&all)
	if len(all) < 2 {
		t.Fatalf("expected ≥2 alerts without filter, got %d", len(all))
	}

	// With hide_acked=true: only unacked
	w3 := do(t, r, "GET", "/api/alerts?hide_acked=true", nil, machineHeader())
	var unacked []map[string]any
	json.NewDecoder(w3.Body).Decode(&unacked)
	for _, a := range unacked {
		if a["acked"] == true {
			t.Errorf("hide_acked=true returned an acked alert: %v", a)
		}
	}
}

// ─── Bug-fix regression: entity_type inferred from details field ─────────────

func TestEntityTypeSetFromDetailsField(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	// Alert with dst_ip in details — entity_type should be "dst_ip", not "ip"
	w := do(t, r, "POST", "/api/alerts",
		map[string]any{
			"detector": "DDoSDetector", "title": "flood", "severity": "high",
			"details": map[string]any{"dst_ip": "10.0.0.1"},
		},
		machineHeader())
	if w.Code != http.StatusCreated {
		t.Fatalf("ingest: %d — %s", w.Code, w.Body)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	incID := int(resp["incident_id"].(float64))

	w2 := do(t, r, "GET", fmt.Sprintf("/api/incidents/%d", incID), nil, machineHeader())
	var inc map[string]any
	json.NewDecoder(w2.Body).Decode(&inc)
	incident := inc["incident"].(map[string]any)
	if incident["entity_type"] == "ip" {
		t.Errorf("entity_type should not be hardcoded 'ip'; got %v", incident["entity_type"])
	}
	if incident["entity_type"] != "dst_ip" {
		t.Errorf("entity_type: want 'dst_ip', got %v", incident["entity_type"])
	}
	if incident["entity_value"] != "10.0.0.1" {
		t.Errorf("entity_value: want '10.0.0.1', got %v", incident["entity_value"])
	}
}

func TestEntityTypeFallsBackToNodeID(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	// No entity in details — should fall back to node_id
	w := do(t, r, "POST", "/api/alerts",
		map[string]any{
			"detector": "InsiderDetector", "title": "off-hours", "severity": "medium",
			"node_id": "edge-node-07",
		},
		machineHeader())
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	incID := int(resp["incident_id"].(float64))

	w2 := do(t, r, "GET", fmt.Sprintf("/api/incidents/%d", incID), nil, machineHeader())
	var inc map[string]any
	json.NewDecoder(w2.Body).Decode(&inc)
	incident := inc["incident"].(map[string]any)
	if incident["entity_type"] != "node_id" {
		t.Errorf("entity_type fallback: want 'node_id', got %v", incident["entity_type"])
	}
}

// ─── Session revocation (H3) ─────────────────────────────────────────────────

// buildJWT creates a JWT signed with testAPIKey for the given username/role.
func buildJWT(t *testing.T, sub, role string, exp time.Time) string {
	t.Helper()
	secret := pbkdf2.Key([]byte(testAPIKey), []byte("axion-jwt-v1"), 100_000, 32, sha256.New)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  sub,
		"role": role,
		"exp":  exp.Unix(),
		"iat":  time.Now().Unix(),
	})
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return s
}

func TestRevokeSessionsNotFound(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)
	j := adminJWT(t)

	w := do(t, r, "POST", "/api/users/ghost/revoke-sessions", nil, bearerHeader(j))
	if w.Code != http.StatusNotFound {
		t.Fatalf("revoke nonexistent user: want 404, got %d — %s", w.Code, w.Body)
	}
}

func TestRevokeSessionsInvalidatesOldJWT(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouterWithSessionCheck(t, database)
	adminTok := adminJWT(t)

	// Create a regular user
	do(t, r, "POST", "/api/users",
		map[string]any{"username": "revokeuser", "password": "P@ssword123", "role": "analyst"},
		bearerHeader(adminTok))

	// Issue a JWT for revokeuser (iat = now)
	oldTok := buildJWT(t, "revokeuser", "analyst", time.Now().Add(time.Hour))

	// Old token works before revocation
	w1 := do(t, r, "GET", "/api/alerts", nil, bearerHeader(oldTok))
	if w1.Code != http.StatusOK {
		t.Fatalf("before revoke: want 200, got %d", w1.Code)
	}

	// Revoke all sessions for revokeuser
	wRev := do(t, r, "POST", "/api/users/revokeuser/revoke-sessions", nil, bearerHeader(adminTok))
	if wRev.Code != http.StatusOK {
		t.Fatalf("revoke sessions: want 200, got %d — %s", wRev.Code, wRev.Body)
	}

	// Old token must now be rejected
	w2 := do(t, r, "GET", "/api/alerts", nil, bearerHeader(oldTok))
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("after revoke: want 401 for old token, got %d", w2.Code)
	}
}

func TestRevokeSessionsNewJWTStillWorks(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouterWithSessionCheck(t, database)
	adminTok := adminJWT(t)

	do(t, r, "POST", "/api/users",
		map[string]any{"username": "revokeuser2", "password": "P@ssword123", "role": "analyst"},
		bearerHeader(adminTok))

	// Revoke first
	do(t, r, "POST", "/api/users/revokeuser2/revoke-sessions", nil, bearerHeader(adminTok))

	// Issue a brand-new JWT (iat is after the revocation)
	newTok := buildJWT(t, "revokeuser2", "analyst", time.Now().Add(time.Hour))

	// New token must be accepted
	w := do(t, r, "GET", "/api/alerts", nil, bearerHeader(newTok))
	if w.Code != http.StatusOK {
		t.Fatalf("new token after revoke: want 200, got %d", w.Code)
	}
}

func TestRevokeSessionsRequiresAdmin(t *testing.T) {
	database := newTestDB(t)
	r, _ := newRouter(t, database)

	// Operator-level machine token must not be allowed to revoke sessions
	w := do(t, r, "POST", "/api/users/anyone/revoke-sessions", nil, machineHeader())
	if w.Code != http.StatusForbidden {
		t.Fatalf("machine revoke: want 403, got %d", w.Code)
	}
}

// ─── Alert ingest rate limit (H2) ────────────────────────────────────────────

func TestAlertIngestRateLimitEndpoint(t *testing.T) {
	database := newTestDB(t)
	gin.SetMode(gin.TestMode)
	hub := handlers.NewHub()
	go hub.Run()
	h := handlers.New(database, testAPIKey, hub, nil)
	getKey := func() string { return testAPIKey }

	// Very tight limit: 3 requests per minute
	r := gin.New()
	authMW := middleware.Auth(getKey)
	api := r.Group("/api", authMW)
	api.POST("/alerts",
		middleware.AlertIngestRateLimit(3, time.Minute),
		middleware.RequireOperator(),
		h.IngestAlert)

	payload := map[string]any{
		"detector": "test", "title": "t", "severity": "low",
	}
	for i := 0; i < 3; i++ {
		w := do(t, r, "POST", "/api/alerts", payload, machineHeader())
		if w.Code != http.StatusCreated {
			t.Fatalf("attempt %d: want 201, got %d", i+1, w.Code)
		}
	}
	// Fourth attempt must be rate-limited
	w := do(t, r, "POST", "/api/alerts", payload, machineHeader())
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over ingest limit: want 429, got %d", w.Code)
	}
}

// ─── Security headers integration (H4) ───────────────────────────────────────

func TestSecurityHeadersIntegration(t *testing.T) {
	database := newTestDB(t)
	gin.SetMode(gin.TestMode)
	hub := handlers.NewHub()
	go hub.Run()
	h := handlers.New(database, testAPIKey, hub, nil)

	r := gin.New()
	r.Use(middleware.SecurityHeaders())
	r.GET("/api/health", h.Health)

	w := do(t, r, "GET", "/api/health", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("health: want 200, got %d", w.Code)
	}
	for hdr, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "0",
	} {
		if got := w.Header().Get(hdr); got != want {
			t.Errorf("%s: want %q, got %q", hdr, want, got)
		}
	}
	if csp := w.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy header missing from health endpoint")
	}
}
