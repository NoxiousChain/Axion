-- Axion PostgreSQL schema — production server
-- Mirrors the SQLite schema used by the Python server (tacnet_sec/server/api.py)
-- but with proper PG types, JSONB, constraints, and replication-ready structure.
--
-- Run: psql $DATABASE_URL -f migrations/001_initial.sql

BEGIN;

CREATE TABLE IF NOT EXISTS users (
    username                TEXT PRIMARY KEY,
    password_hash           TEXT        NOT NULL,
    role                    TEXT        NOT NULL DEFAULT 'analyst'
                                CHECK (role IN ('analyst','operator','admin')),
    totp_secret             TEXT,
    failed_login_count      INTEGER     NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    sessions_invalidated_at TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Idempotent: add column if upgrading from a schema that predates H3.
ALTER TABLE users ADD COLUMN IF NOT EXISTS sessions_invalidated_at TIMESTAMPTZ;

-- Bootstrap admin (password must be changed on first login)
INSERT INTO users (username, password_hash, role)
VALUES ('admin', 'CHANGE_ME_ON_FIRST_RUN', 'admin')
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS alerts (
    id          BIGSERIAL        PRIMARY KEY,
    ts          DOUBLE PRECISION NOT NULL,
    detector    TEXT             NOT NULL,
    severity    TEXT             NOT NULL
                    CHECK (severity IN ('low','medium','high','critical')),
    title       TEXT             NOT NULL,
    details     JSONB,
    node_id     TEXT             NOT NULL DEFAULT '',
    location    TEXT             NOT NULL DEFAULT '',
    acked       BOOLEAN          NOT NULL DEFAULT FALSE,
    acked_by    TEXT,
    acked_at    DOUBLE PRECISION,
    incident_id BIGINT
);

CREATE INDEX IF NOT EXISTS alerts_ts_idx        ON alerts (ts DESC);
CREATE INDEX IF NOT EXISTS alerts_severity_idx  ON alerts (severity);
CREATE INDEX IF NOT EXISTS alerts_detector_idx  ON alerts (detector);
CREATE INDEX IF NOT EXISTS alerts_node_id_idx   ON alerts (node_id);
CREATE INDEX IF NOT EXISTS alerts_incident_idx  ON alerts (incident_id)
    WHERE incident_id IS NOT NULL;

-- GIN index enables fast JSONB detail searches (e.g. alerts where details @> '{"src_ip":"…"}')
CREATE INDEX IF NOT EXISTS alerts_details_gin   ON alerts USING gin (details);

CREATE TABLE IF NOT EXISTS incidents (
    id           BIGSERIAL        PRIMARY KEY,
    ts           DOUBLE PRECISION NOT NULL,
    entity_type  TEXT             NOT NULL,
    entity_value TEXT             NOT NULL,
    status       TEXT             NOT NULL DEFAULT 'open'
                     CHECK (status IN ('open','closed')),
    severity     TEXT             NOT NULL DEFAULT 'medium'
                     CHECK (severity IN ('low','medium','high','critical')),
    title        TEXT             NOT NULL,
    acked        BOOLEAN          NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS incidents_ts_idx           ON incidents (ts DESC);
CREATE INDEX IF NOT EXISTS incidents_entity_idx       ON incidents (entity_value, status);
CREATE INDEX IF NOT EXISTS incidents_open_entity_idx  ON incidents (entity_value)
    WHERE status = 'open';

CREATE TABLE IF NOT EXISTS audit_log (
    id       BIGSERIAL        PRIMARY KEY,
    ts       DOUBLE PRECISION NOT NULL,
    actor    TEXT             NOT NULL,
    action   TEXT             NOT NULL,
    target   TEXT             NOT NULL DEFAULT '',
    detail   TEXT             NOT NULL DEFAULT '',
    row_hmac TEXT             NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_ts_idx     ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS audit_actor_idx  ON audit_log (actor);
CREATE INDEX IF NOT EXISTS audit_action_idx ON audit_log (action);

-- Prevent modification or deletion of audit rows (immutable ledger).
-- Triggers raise a hard exception on any attempt; they fire even when called
-- by the table owner, unlike RULE which is silently bypassed by superusers.
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

-- Retention helper view: alerts older than 90 days
CREATE OR REPLACE VIEW alerts_to_archive AS
    SELECT * FROM alerts
    WHERE to_timestamp(ts) < NOW() - INTERVAL '90 days';

-- Per-node API keys: each edge node gets its own key so a compromise of one
-- node does not expose the shared master key or any other node (L2).
CREATE TABLE IF NOT EXISTS node_keys (
    node_id    TEXT PRIMARY KEY,
    api_key    TEXT        NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS node_keys_api_key_idx ON node_keys (api_key);

-- Persistent rate-limit store: survives restarts and is shared across server
-- instances, closing the M4 gap in the previous in-memory sliding-window limiter.
CREATE TABLE IF NOT EXISTS rate_limits (
    limiter TEXT NOT NULL,
    ip      TEXT NOT NULL,
    ts      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS rate_limits_lookup ON rate_limits (limiter, ip, ts);

COMMIT;
