package models

import (
	"encoding/json"
	"time"
)

type Role string

const (
	RoleAnalyst  Role = "analyst"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
	RoleMachine  Role = "__machine__"
)

type User struct {
	Username         string     `json:"username"`
	PasswordHash     string     `json:"-"`
	Role             Role       `json:"role"`
	TOTPSecret       *string    `json:"-"`
	FailedLoginCount int        `json:"-"`
	LockedUntil      *time.Time `json:"-"`
	CreatedAt        time.Time  `json:"created_at"`
}

type Alert struct {
	ID         int64           `json:"id"`
	Ts         float64         `json:"ts"`
	Detector   string          `json:"detector"`
	Severity   string          `json:"severity"`
	Title      string          `json:"title"`
	Details    json.RawMessage `json:"details"`
	NodeID     string          `json:"node_id"`
	Location   string          `json:"location"`
	Acked      bool            `json:"acked"`
	AckedBy    *string         `json:"acked_by,omitempty"`
	AckedAt    *float64        `json:"acked_at,omitempty"`
	IncidentID *int64          `json:"incident_id,omitempty"`
}

type Incident struct {
	ID          int64   `json:"id"`
	Ts          float64 `json:"ts"`
	EntityType  string  `json:"entity_type"`
	EntityValue string  `json:"entity_value"`
	Status      string  `json:"status"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Acked       bool    `json:"acked"`
	AlertCount  int     `json:"alert_count"`
}

type AuditEntry struct {
	ID     int64   `json:"id"`
	Ts     float64 `json:"ts"`
	Actor  string  `json:"actor"`
	Action string  `json:"action"`
	Target string  `json:"target"`
	Detail string  `json:"detail"`
	HMAC   string  `json:"hmac"`
}

// ─── Request / response schemas ────────────────────────────────────────────

type LoginRequest struct {
	Username string  `json:"username" binding:"required,max=64"`
	Password string  `json:"password" binding:"required,max=256"`
	APIKey   string  `json:"api_key"  binding:"required"`
	OTP      *string `json:"otp"`
}

type AlertPayload struct {
	Detector string          `json:"detector"  binding:"required,max=64"`
	Title    string          `json:"title"     binding:"required,max=256"`
	Severity string          `json:"severity"  binding:"required,oneof=low medium high critical"`
	NodeID   string          `json:"node_id"   binding:"max=64"`
	Location string          `json:"location"  binding:"max=128"`
	Ts       float64         `json:"ts"`
	Details  json.RawMessage `json:"details"`
}

type AckBody struct {
	By   string `json:"by"   binding:"max=128"`
	Note string `json:"note" binding:"max=512"`
}

type CreateUserRequest struct {
	Username string `json:"username" binding:"required,min=2,max=64,alphanum"`
	Password string `json:"password" binding:"required,min=8"`
	Role     Role   `json:"role"     binding:"required,oneof=analyst operator admin"`
}

type RotateKeyRequest struct {
	NewKey string `json:"new_key" binding:"required,min=16,max=512"`
}
