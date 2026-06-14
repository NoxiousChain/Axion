-- Axion PostgreSQL schema — production server
-- Mirrors the SQLite schema used by the Python server (tacnet_sec/server/api.py)
-- but with proper PG types, JSONB, constraints, and replication-ready structure.
--
-- Run: psql $DATABASE_URL -f migrations/001_initial.sql

BEGIN;

CREATE TABLE IF NOT EXISTS users (
    username           TEXT PRIMARY KEY,
    password_hash      TEXT        NOT NULL,
    role               TEXT        NOT NULL DEFAULT 'analyst'
                           CHECK (role IN ('analyst','operator','admin')),
    totp_secret        TEXT,
    failed_login_count INTEGER     NOT NULL DEFAULT 0,
    locked_until       TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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

-- Prevent modification or deletion of audit rows (immutable ledger)
CREATE OR REPLACE RULE audit_no_update
    AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE OR REPLACE RULE audit_no_delete
    AS ON DELETE TO audit_log DO INSTEAD NOTHING;

-- Retention helper view: alerts older than 90 days
CREATE OR REPLACE VIEW alerts_to_archive AS
    SELECT * FROM alerts
    WHERE to_timestamp(ts) < NOW() - INTERVAL '90 days';

COMMIT;
