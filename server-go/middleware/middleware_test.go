package middleware_test

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/axion/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/pbkdf2"
)

const testKey = "test-api-key-middleware-unit"

func init() { gin.SetMode(gin.TestMode) }

// jwtFor generates a signed HS256 JWT for a given role and sub.
func jwtFor(t *testing.T, key, sub, role string, exp time.Time) string {
	t.Helper()
	secret := pbkdf2.Key([]byte(key), []byte("axion-jwt-v1"), 100_000, 32, sha256.New)
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

// routerWith builds a minimal Gin router wrapping the supplied middlewares.
func routerWith(middlewares ...gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	for _, mw := range middlewares {
		r.Use(mw)
	}
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.POST("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func doReq(r *gin.Engine, method, path string, headers http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ─── SecurityHeaders (H4) ────────────────────────────────────────────────────

func TestSecurityHeaders_XContentTypeOptions(t *testing.T) {
	r := routerWith(middleware.SecurityHeaders())
	w := doReq(r, "GET", "/ping", nil)
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options: want nosniff, got %q", got)
	}
}

func TestSecurityHeaders_XFrameOptions(t *testing.T) {
	r := routerWith(middleware.SecurityHeaders())
	w := doReq(r, "GET", "/ping", nil)
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options: want DENY, got %q", got)
	}
}

func TestSecurityHeaders_CSPPresent(t *testing.T) {
	r := routerWith(middleware.SecurityHeaders())
	w := doReq(r, "GET", "/ping", nil)
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing")
	}
	for _, directive := range []string{"default-src", "script-src", "frame-ancestors"} {
		if !contains(csp, directive) {
			t.Errorf("CSP missing directive %q: %s", directive, csp)
		}
	}
}

func TestSecurityHeaders_ReferrerPolicy(t *testing.T) {
	r := routerWith(middleware.SecurityHeaders())
	w := doReq(r, "GET", "/ping", nil)
	if got := w.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy: want strict-origin-when-cross-origin, got %q", got)
	}
}

func TestSecurityHeaders_HSTSAbsentOnHTTP(t *testing.T) {
	r := routerWith(middleware.SecurityHeaders())
	// Plain HTTP request (no TLS, no X-Forwarded-Proto: https) → no HSTS
	w := doReq(r, "GET", "/ping", nil)
	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS must not be sent on plain HTTP; got %q", got)
	}
}

func TestSecurityHeaders_HSTSSentWithForwardedProto(t *testing.T) {
	r := routerWith(middleware.SecurityHeaders())
	h := http.Header{}
	h.Set("X-Forwarded-Proto", "https")
	w := doReq(r, "GET", "/ping", h)
	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("HSTS must be sent when X-Forwarded-Proto: https")
	}
	if !contains(hsts, "max-age=") {
		t.Errorf("HSTS value looks wrong: %q", hsts)
	}
}

func TestSecurityHeaders_XSSProtectionZero(t *testing.T) {
	r := routerWith(middleware.SecurityHeaders())
	w := doReq(r, "GET", "/ping", nil)
	if got := w.Header().Get("X-XSS-Protection"); got != "0" {
		t.Errorf("X-XSS-Protection: want 0, got %q", got)
	}
}

// ─── LoginRateLimit ──────────────────────────────────────────────────────────

func TestLoginRateLimit_AllowsUnderLimit(t *testing.T) {
	r := routerWith(middleware.LoginRateLimit(5, time.Minute))
	for i := 0; i < 5; i++ {
		w := doReq(r, "POST", "/ping", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d: want 200, got %d", i+1, w.Code)
		}
	}
}

func TestLoginRateLimit_BlocksAtLimit(t *testing.T) {
	r := routerWith(middleware.LoginRateLimit(3, time.Minute))
	for i := 0; i < 3; i++ {
		doReq(r, "POST", "/ping", nil)
	}
	// Fourth request must be blocked
	w := doReq(r, "POST", "/ping", nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over limit: want 429, got %d", w.Code)
	}
}

// ─── AlertIngestRateLimit (H2) ───────────────────────────────────────────────

func TestAlertIngestRateLimit_AllowsUnderLimit(t *testing.T) {
	r := routerWith(middleware.AlertIngestRateLimit(10, time.Minute))
	for i := 0; i < 10; i++ {
		w := doReq(r, "POST", "/ping", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d: want 200, got %d", i+1, w.Code)
		}
	}
}

func TestAlertIngestRateLimit_BlocksAtLimit(t *testing.T) {
	r := routerWith(middleware.AlertIngestRateLimit(5, time.Minute))
	for i := 0; i < 5; i++ {
		doReq(r, "POST", "/ping", nil)
	}
	w := doReq(r, "POST", "/ping", nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over ingest limit: want 429, got %d", w.Code)
	}
}

func TestAlertIngestRateLimit_ResponseBody(t *testing.T) {
	r := routerWith(middleware.AlertIngestRateLimit(1, time.Minute))
	doReq(r, "POST", "/ping", nil)
	w := doReq(r, "POST", "/ping", nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", w.Code)
	}
	body := w.Body.String()
	if !contains(body, "rate limit") && !contains(body, "too many") {
		t.Errorf("expected rate-limit message in body, got: %s", body)
	}
}

// ─── Auth middleware — machine key fail limiter (C3) ─────────────────────────

func TestAuth_ValidMachineKey(t *testing.T) {
	r := routerWith(middleware.Auth(func() string { return testKey }))
	h := http.Header{}
	h.Set("X-Axion-Key", testKey)
	w := doReq(r, "GET", "/ping", h)
	if w.Code != http.StatusOK {
		t.Fatalf("valid machine key: want 200, got %d", w.Code)
	}
}

func TestAuth_InvalidMachineKey_Returns401(t *testing.T) {
	r := routerWith(middleware.Auth(func() string { return testKey }))
	h := http.Header{}
	h.Set("X-Axion-Key", "wrong-key")
	w := doReq(r, "GET", "/ping", h)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: want 401, got %d", w.Code)
	}
}

func TestAuth_ValidBearerJWT(t *testing.T) {
	r := routerWith(middleware.Auth(func() string { return testKey }))
	tok := jwtFor(t, testKey, "alice", "analyst", time.Now().Add(time.Hour))
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	w := doReq(r, "GET", "/ping", h)
	if w.Code != http.StatusOK {
		t.Fatalf("valid JWT: want 200, got %d", w.Code)
	}
}

func TestAuth_ExpiredJWT_Returns401(t *testing.T) {
	r := routerWith(middleware.Auth(func() string { return testKey }))
	tok := jwtFor(t, testKey, "alice", "analyst", time.Now().Add(-time.Minute))
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	w := doReq(r, "GET", "/ping", h)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired JWT: want 401, got %d", w.Code)
	}
}

func TestAuth_WrongSigningKey_Returns401(t *testing.T) {
	r := routerWith(middleware.Auth(func() string { return testKey }))
	tok := jwtFor(t, "completely-different-key", "eve", "admin", time.Now().Add(time.Hour))
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	w := doReq(r, "GET", "/ping", h)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong sign key: want 401, got %d", w.Code)
	}
}

func TestAuth_NoCredentials_Returns401(t *testing.T) {
	r := routerWith(middleware.Auth(func() string { return testKey }))
	w := doReq(r, "GET", "/ping", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no creds: want 401, got %d", w.Code)
	}
}

// ─── ValidateJWT (C2) — used for out-of-band WS token validation ─────────────

func TestValidateJWT_ValidToken(t *testing.T) {
	tok := jwtFor(t, testKey, "bob", "operator", time.Now().Add(time.Hour))
	role, actor, ok := middleware.ValidateJWT(testKey, tok)
	if !ok {
		t.Fatal("ValidateJWT: want ok=true")
	}
	if role != "operator" {
		t.Errorf("role: want operator, got %q", role)
	}
	if actor != "bob" {
		t.Errorf("actor: want bob, got %q", actor)
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	tok := jwtFor(t, testKey, "bob", "operator", time.Now().Add(-time.Minute))
	_, _, ok := middleware.ValidateJWT(testKey, tok)
	if ok {
		t.Error("ValidateJWT: want ok=false for expired token")
	}
}

func TestValidateJWT_WrongKey(t *testing.T) {
	tok := jwtFor(t, "other-key", "bob", "operator", time.Now().Add(time.Hour))
	_, _, ok := middleware.ValidateJWT(testKey, tok)
	if ok {
		t.Error("ValidateJWT: want ok=false for token signed with wrong key")
	}
}

func TestValidateJWT_Garbage(t *testing.T) {
	_, _, ok := middleware.ValidateJWT(testKey, "not.a.jwt")
	if ok {
		t.Error("ValidateJWT: want ok=false for garbage input")
	}
}

func TestValidateJWT_Empty(t *testing.T) {
	_, _, ok := middleware.ValidateJWT(testKey, "")
	if ok {
		t.Error("ValidateJWT: want ok=false for empty string")
	}
}

// ─── RequireAdmin / RequireOperator ──────────────────────────────────────────

func TestRequireAdmin_BlocksAnalyst(t *testing.T) {
	r := routerWith(
		middleware.Auth(func() string { return testKey }),
		middleware.RequireAdmin(),
	)
	tok := jwtFor(t, testKey, "alice", "analyst", time.Now().Add(time.Hour))
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	w := doReq(r, "GET", "/ping", h)
	if w.Code != http.StatusForbidden {
		t.Fatalf("analyst to admin route: want 403, got %d", w.Code)
	}
}

func TestRequireAdmin_AllowsAdmin(t *testing.T) {
	r := routerWith(
		middleware.Auth(func() string { return testKey }),
		middleware.RequireAdmin(),
	)
	tok := jwtFor(t, testKey, "sysadmin", "admin", time.Now().Add(time.Hour))
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	w := doReq(r, "GET", "/ping", h)
	if w.Code != http.StatusOK {
		t.Fatalf("admin to admin route: want 200, got %d", w.Code)
	}
}

func TestRequireOperator_AllowsMachine(t *testing.T) {
	r := routerWith(
		middleware.Auth(func() string { return testKey }),
		middleware.RequireOperator(),
	)
	h := http.Header{}
	h.Set("X-Axion-Key", testKey)
	w := doReq(r, "GET", "/ping", h)
	if w.Code != http.StatusOK {
		t.Fatalf("machine to operator route: want 200, got %d", w.Code)
	}
}

func TestRequireOperator_BlocksAnalyst(t *testing.T) {
	r := routerWith(
		middleware.Auth(func() string { return testKey }),
		middleware.RequireOperator(),
	)
	tok := jwtFor(t, testKey, "alice", "analyst", time.Now().Add(time.Hour))
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	w := doReq(r, "GET", "/ping", h)
	if w.Code != http.StatusForbidden {
		t.Fatalf("analyst to operator route: want 403, got %d", w.Code)
	}
}

// ─── BodySizeLimit ────────────────────────────────────────────────────────────

func TestBodySizeLimit_AllowsSmallBody(t *testing.T) {
	r := gin.New()
	r.Use(middleware.BodySizeLimit(1024))
	r.POST("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest("POST", "/ping", nil)
	req.ContentLength = 512
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("small body: want 200, got %d", w.Code)
	}
}

func TestBodySizeLimit_RejectsLargeBody(t *testing.T) {
	r := gin.New()
	r.Use(middleware.BodySizeLimit(1024))
	r.POST("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest("POST", "/ping", nil)
	req.ContentLength = 2048 // over limit
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body: want 413, got %d", w.Code)
	}
}

// ─── helper ──────────────────────────────────────────────────────────────────

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
