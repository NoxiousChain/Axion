package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/axion/server/middleware"
	"github.com/axion/server/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/pbkdf2"
)

func jwtSecret(key string) []byte {
	return pbkdf2.Key([]byte(key), []byte("axion-jwt-v1"), 100_000, 32, sha256.New)
}

// Login — POST /api/login
func (h *Handler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	// Validate API key
	if req.APIKey != h.getKey() {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "invalid API key"})
		return
	}

	ctx := c.Request.Context()

	var (
		pwHash           string
		role             models.Role
		totpSecret       *string
		failedCount      int
		lockedUntil      *time.Time
	)
	err := h.db.Pool.QueryRow(ctx,
		`SELECT password_hash, role, totp_secret, failed_login_count, locked_until
		 FROM users WHERE username = $1`, req.Username,
	).Scan(&pwHash, &role, &totpSecret, &failedCount, &lockedUntil)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "invalid credentials"})
		return
	}

	// Account lockout check
	if lockedUntil != nil && time.Now().Before(*lockedUntil) {
		h.db.Audit(ctx, req.Username, "login_blocked", req.Username, "account locked")
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "account locked"})
		return
	}

	// Password check (PBKDF2-SHA256)
	if !checkPassword(req.Password, pwHash) {
		failedCount++
		if failedCount >= 5 {
			until := time.Now().Add(30 * time.Minute)
			h.db.Pool.Exec(ctx,
				`UPDATE users SET failed_login_count = $1, locked_until = $2 WHERE username = $3`,
				failedCount, until, req.Username,
			)
			h.db.Audit(ctx, req.Username, "login_blocked", req.Username, "5 failed attempts")
		} else {
			h.db.Pool.Exec(ctx,
				`UPDATE users SET failed_login_count = $1 WHERE username = $2`,
				failedCount, req.Username,
			)
		}
		h.db.Audit(ctx, req.Username, "login_failed", req.Username, "bad password")
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "invalid credentials"})
		return
	}

	// TOTP check
	if totpSecret != nil {
		if req.OTP == nil || *req.OTP == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"detail": "OTP required"})
			return
		}
		if !totp.Validate(*req.OTP, *totpSecret) {
			h.db.Audit(ctx, req.Username, "login_failed", req.Username, "bad OTP")
			c.JSON(http.StatusUnauthorized, gin.H{"detail": "invalid OTP"})
			return
		}
	}

	// Reset failure counters
	h.db.Pool.Exec(ctx,
		`UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE username = $1`,
		req.Username,
	)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  req.Username,
		"role": string(role),
		"exp":  time.Now().Add(8 * time.Hour).Unix(),
	})
	signed, err := token.SignedString(jwtSecret(h.getKey()))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "token signing failed"})
		return
	}

	h.db.Audit(ctx, req.Username, "login_success", req.Username, "")
	c.JSON(http.StatusOK, gin.H{"access_token": signed, "token_type": "bearer"})
}

// RotateKey — POST /api/rotate-key  (admin only)
func (h *Handler) RotateKey(c *gin.Context) {
	var req models.RotateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}
	actor, _ := c.Get(middleware.CtxActor)

	h.mu.Lock()
	h.key = req.NewKey
	h.db.SetAPIKey(req.NewKey)
	h.mu.Unlock()

	h.db.Audit(c.Request.Context(), fmt.Sprint(actor), "key_rotated", "", "")
	c.JSON(http.StatusOK, gin.H{"detail": "key rotated"})
}

// ─── User management ─────────────────────────────────────────────────────────

func (h *Handler) ListUsers(c *gin.Context) {
	rows, err := h.db.Pool.Query(c.Request.Context(),
		`SELECT username, role, created_at FROM users ORDER BY username`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	defer rows.Close()

	var users []gin.H
	for rows.Next() {
		var uname string
		var role models.Role
		var createdAt time.Time
		if err := rows.Scan(&uname, &role, &createdAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
			return
		}
		users = append(users, gin.H{"username": uname, "role": role, "created_at": createdAt})
	}
	c.JSON(http.StatusOK, users)
}

func (h *Handler) CreateUser(c *gin.Context) {
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}
	actor, _ := c.Get(middleware.CtxActor)
	ctx := c.Request.Context()

	hash, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "password hashing failed"})
		return
	}

	if _, err := h.db.Pool.Exec(ctx,
		`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)`,
		req.Username, hash, req.Role,
	); err != nil {
		c.JSON(http.StatusConflict, gin.H{"detail": "username already exists"})
		return
	}

	h.db.Audit(ctx, fmt.Sprint(actor), "user_created", req.Username, string(req.Role))
	c.JSON(http.StatusCreated, gin.H{"username": req.Username, "role": req.Role})
}

func (h *Handler) DeleteUser(c *gin.Context) {
	username := c.Param("username")
	actor, _ := c.Get(middleware.CtxActor)
	ctx := c.Request.Context()

	ct, err := h.db.Pool.Exec(ctx, `DELETE FROM users WHERE username = $1`, username)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"detail": "user not found"})
		return
	}

	h.db.Audit(ctx, fmt.Sprint(actor), "user_deleted", username, "")
	c.JSON(http.StatusOK, gin.H{"detail": "deleted"})
}

// EnrolTOTP — POST /api/users/:username/totp
func (h *Handler) EnrolTOTP(c *gin.Context) {
	username := c.Param("username")
	actor, _ := c.Get(middleware.CtxActor)
	ctx := c.Request.Context()

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Axion",
		AccountName: username,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	ct, err := h.db.Pool.Exec(ctx,
		`UPDATE users SET totp_secret = $1 WHERE username = $2`,
		key.Secret(), username,
	)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"detail": "user not found"})
		return
	}

	h.db.Audit(ctx, fmt.Sprint(actor), "totp_enabled", username, "")
	c.JSON(http.StatusOK, gin.H{
		"totp_secret":      key.Secret(),
		"provisioning_uri": key.URL(),
	})
}

func (h *Handler) DisableTOTP(c *gin.Context) {
	username := c.Param("username")
	actor, _ := c.Get(middleware.CtxActor)
	ctx := c.Request.Context()

	ct, err := h.db.Pool.Exec(ctx, `UPDATE users SET totp_secret = NULL WHERE username = $1`, username)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"detail": "user not found"})
		return
	}
	h.db.Audit(ctx, fmt.Sprint(actor), "totp_disabled", username, "")
	c.JSON(http.StatusOK, gin.H{"detail": "TOTP disabled"})
}

func (h *Handler) UnlockUser(c *gin.Context) {
	username := c.Param("username")
	actor, _ := c.Get(middleware.CtxActor)
	ctx := c.Request.Context()

	ct, err := h.db.Pool.Exec(ctx,
		`UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE username = $1`,
		username,
	)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"detail": "user not found"})
		return
	}
	h.db.Audit(ctx, fmt.Sprint(actor), "account_unlocked", username, "")
	c.JSON(http.StatusOK, gin.H{"detail": "unlocked"})
}

// ─── Password helpers ─────────────────────────────────────────────────────────

// hashPassword matches tacnet_sec/server/auth.py: PBKDF2-SHA256, 200 000 iters,
// 32-byte random salt, stored as "salt_hex:dk_hex".
func hashPassword(pw string) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2.Key([]byte(pw), salt, 200_000, 32, sha256.New)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(dk), nil
}

func checkPassword(pw, stored string) bool {
	parts := strings.SplitN(stored, ":", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	dk := pbkdf2.Key([]byte(pw), salt, 200_000, 32, sha256.New)
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(dk)), []byte(parts[1])) == 1
}

