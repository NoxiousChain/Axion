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

// NodeKey represents a per-node API key entry (L2).
type NodeKey struct {
	NodeID    string    `json:"node_id"`
	CreatedAt time.Time `json:"created_at"`
}

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

// IsSessionValid returns true when the token (identified by its issuedAt
// timestamp) was issued after the user's last session-revocation event.
// Returns true on DB error to avoid blocking legitimate access during outages.
func (d *DB) IsSessionValid(ctx context.Context, username string, issuedAt time.Time) bool {
	var invalidatedAt *time.Time
	err := d.Pool.QueryRow(ctx,
		`SELECT sessions_invalidated_at FROM users WHERE username = $1`, username,
	).Scan(&invalidatedAt)
	if err != nil {
		return true
	}
	if invalidatedAt == nil {
		return true
	}
	return issuedAt.After(*invalidatedAt)
}

// AllowRateLimit checks and records a rate-limit attempt in Postgres.
// Prunes expired entries then returns true if count is under limit (M4).
// Fails open on DB error to avoid blocking legitimate requests.
func (d *DB) AllowRateLimit(ctx context.Context, limiter, ip string, limit int, window time.Duration) bool {
	ws := fmt.Sprintf("%d seconds", int(window.Seconds()))
	d.Pool.Exec(ctx, //nolint:errcheck
		`DELETE FROM rate_limits WHERE limiter=$1 AND ip=$2 AND ts < NOW()-$3::interval`,
		limiter, ip, ws)
	var count int
	if err := d.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM rate_limits WHERE limiter=$1 AND ip=$2`,
		limiter, ip).Scan(&count); err != nil {
		return true
	}
	if count >= limit {
		return false
	}
	d.Pool.Exec(ctx, `INSERT INTO rate_limits (limiter, ip) VALUES ($1, $2)`, limiter, ip) //nolint:errcheck
	return true
}

// RateLimitFn returns a closure suitable for use as a persistent rate-limit
// backend in middleware. State survives restarts and is shared across instances (M4).
func (d *DB) RateLimitFn(limiter string, limit int, window time.Duration) func(context.Context, string) bool {
	return func(ctx context.Context, ip string) bool {
		return d.AllowRateLimit(ctx, limiter, ip, limit, window)
	}
}

// CleanupRateLimits deletes all expired rate_limit rows. Call periodically to
// prevent unbounded table growth (e.g. every 10 minutes via a goroutine).
func (d *DB) CleanupRateLimits(ctx context.Context) {
	d.Pool.Exec(ctx, `DELETE FROM rate_limits WHERE ts < NOW() - INTERVAL '1 hour'`) //nolint:errcheck
}

// CreateNodeKey creates or regenerates an API key for the named edge node (L2).
// Returns the new plaintext key; only returned once — store it securely.
func (d *DB) CreateNodeKey(ctx context.Context, nodeID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	key := hex.EncodeToString(b)
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO node_keys (node_id, api_key) VALUES ($1, $2)
		 ON CONFLICT (node_id) DO UPDATE SET api_key = EXCLUDED.api_key`,
		nodeID, key)
	if err != nil {
		return "", fmt.Errorf("create node key: %w", err)
	}
	return key, nil
}

// ListNodeKeys returns all registered node keys (without the key value).
func (d *DB) ListNodeKeys(ctx context.Context) ([]NodeKey, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT node_id, created_at FROM node_keys ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []NodeKey
	for rows.Next() {
		var k NodeKey
		if err := rows.Scan(&k.NodeID, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// DeleteNodeKey removes a node's API key, immediately revoking its access (L2).
func (d *DB) DeleteNodeKey(ctx context.Context, nodeID string) error {
	ct, err := d.Pool.Exec(ctx, `DELETE FROM node_keys WHERE node_id = $1`, nodeID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("node not found")
	}
	return nil
}

// LookupNodeKey resolves an API key to its node_id. Returns "" if not found (L2).
func (d *DB) LookupNodeKey(ctx context.Context, apiKey string) string {
	var nodeID string
	if err := d.Pool.QueryRow(ctx,
		`SELECT node_id FROM node_keys WHERE api_key = $1`, apiKey).Scan(&nodeID); err != nil {
		return ""
	}
	return nodeID
}

// RevokeUserSessions sets sessions_invalidated_at = NOW() for a user,
// making all previously issued JWTs invalid on the next auth check.
func (d *DB) RevokeUserSessions(ctx context.Context, username string) error {
	ct, err := d.Pool.Exec(ctx,
		`UPDATE users SET sessions_invalidated_at = NOW() WHERE username = $1`, username)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
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
	username                TEXT PRIMARY KEY,
	password_hash           TEXT NOT NULL,
	role                    TEXT NOT NULL DEFAULT 'analyst',
	totp_secret             TEXT,
	failed_login_count      INTEGER NOT NULL DEFAULT 0,
	locked_until            TIMESTAMPTZ,
	sessions_invalidated_at TIMESTAMPTZ,
	created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS sessions_invalidated_at TIMESTAMPTZ;

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

CREATE OR REPLACE FUNCTION audit_log_prevent_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	RAISE EXCEPTION 'audit_log rows are immutable (action: %)', TG_OP;
END;
$$;

DROP RULE IF EXISTS audit_no_update ON audit_log;
DROP RULE IF EXISTS audit_no_delete ON audit_log;

CREATE OR REPLACE TRIGGER trg_audit_no_update
	BEFORE UPDATE ON audit_log
	FOR EACH ROW EXECUTE FUNCTION audit_log_prevent_change();

CREATE OR REPLACE TRIGGER trg_audit_no_delete
	BEFORE DELETE ON audit_log
	FOR EACH ROW EXECUTE FUNCTION audit_log_prevent_change();

-- Per-node API keys: each edge node gets its own key so a compromise
-- of one node does not expose all nodes (L2).
CREATE TABLE IF NOT EXISTS node_keys (
	node_id    TEXT PRIMARY KEY,
	api_key    TEXT NOT NULL UNIQUE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS node_keys_api_key_idx ON node_keys (api_key);

-- Persistent rate-limit store: survives restarts and is shared across
-- multiple server instances, closing the M4 gap in the in-memory limiter.
CREATE TABLE IF NOT EXISTS rate_limits (
	limiter TEXT NOT NULL,
	ip      TEXT NOT NULL,
	ts      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS rate_limits_lookup ON rate_limits (limiter, ip, ts);
`
