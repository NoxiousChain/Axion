package db

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/pbkdf2"
)

type DB struct {
	Pool   *pgxpool.Pool
	apiKey string
}

func New(dsn string) (*DB, error) {
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("db ping: %w", err)
	}
	return &DB{Pool: pool}, nil
}

func (d *DB) SetAPIKey(key string) { d.apiKey = key }

func (d *DB) Close() { d.Pool.Close() }

// Migrate runs the idempotent schema migration (also callable at startup).
func Migrate(d *DB) error {
	_, err := d.Pool.Exec(context.Background(), schema)
	return err
}

// EnsureBootstrapAdmin creates an admin user when the users table is empty.
// It is a no-op if any user already exists.
func (d *DB) EnsureBootstrapAdmin(ctx context.Context, username, password string) error {
	var count int
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if count > 0 {
		return nil
	}
	hash, err := bootstrapHashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = d.Pool.Exec(ctx,
		`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin')
		 ON CONFLICT (username) DO NOTHING`,
		username, hash,
	)
	return err
}

// bootstrapHashPassword produces a PBKDF2-SHA256 hash in salt_hex:dk_hex format,
// matching handlers.hashPassword and the Python server's auth.py.
func bootstrapHashPassword(pw string) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2.Key([]byte(pw), salt, 200_000, 32, sha256.New)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(dk), nil
}

// AuditHMAC computes HMAC-SHA256 matching the Python server's audit log format.
func (d *DB) AuditHMAC(ts float64, actor, action, target, detail string) string {
	keyMaterial := sha256.Sum256([]byte("axion-audit-v1:" + d.apiKey))
	msg := fmt.Sprintf("%f|%s|%s|%s|%s", ts, actor, action, target, detail)
	mac := hmac.New(sha256.New, keyMaterial[:])
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// Audit writes a single audit row.
func (d *DB) Audit(ctx context.Context, actor, action, target, detail string) error {
	ts := float64(time.Now().UnixMicro()) / 1e6
	h := d.AuditHMAC(ts, actor, action, target, detail)
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO audit_log (ts, actor, action, target, detail, row_hmac)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		ts, actor, action, target, detail, h,
	)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
	username           TEXT PRIMARY KEY,
	password_hash      TEXT NOT NULL,
	role               TEXT NOT NULL DEFAULT 'analyst',
	totp_secret        TEXT,
	failed_login_count INTEGER NOT NULL DEFAULT 0,
	locked_until       TIMESTAMPTZ,
	created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
	id          BIGSERIAL PRIMARY KEY,
	ts          DOUBLE PRECISION NOT NULL,
	detector    TEXT NOT NULL,
	severity    TEXT NOT NULL,
	title       TEXT NOT NULL,
	details     JSONB,
	node_id     TEXT NOT NULL DEFAULT '',
	location    TEXT NOT NULL DEFAULT '',
	acked       BOOLEAN NOT NULL DEFAULT FALSE,
	acked_by    TEXT,
	acked_at    DOUBLE PRECISION,
	incident_id BIGINT
);

CREATE INDEX IF NOT EXISTS alerts_ts_idx        ON alerts (ts DESC);
CREATE INDEX IF NOT EXISTS alerts_severity_idx  ON alerts (severity);
CREATE INDEX IF NOT EXISTS alerts_detector_idx  ON alerts (detector);
CREATE INDEX IF NOT EXISTS alerts_incident_idx  ON alerts (incident_id);

CREATE TABLE IF NOT EXISTS incidents (
	id           BIGSERIAL PRIMARY KEY,
	ts           DOUBLE PRECISION NOT NULL,
	entity_type  TEXT NOT NULL,
	entity_value TEXT NOT NULL,
	status       TEXT NOT NULL DEFAULT 'open',
	severity     TEXT NOT NULL DEFAULT 'medium',
	title        TEXT NOT NULL,
	acked        BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS incidents_ts_idx ON incidents (ts DESC);

CREATE TABLE IF NOT EXISTS audit_log (
	id       BIGSERIAL PRIMARY KEY,
	ts       DOUBLE PRECISION NOT NULL,
	actor    TEXT NOT NULL,
	action   TEXT NOT NULL,
	target   TEXT NOT NULL DEFAULT '',
	detail   TEXT NOT NULL DEFAULT '',
	row_hmac TEXT NOT NULL
);

-- Prevent modification or deletion of audit rows
CREATE OR REPLACE RULE audit_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE OR REPLACE RULE audit_no_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;
`
