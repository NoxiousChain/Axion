package db_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/axion/server/db"
)

func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	database, err := db.New(dsn)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		database.Pool.Exec(context.Background(),
			`TRUNCATE audit_log, alerts, incidents, users RESTART IDENTITY CASCADE`)
		database.Close()
	})
	return database
}

func TestMigrateIsIdempotent(t *testing.T) {
	d := openTestDB(t)
	// Running migration twice must not error
	if err := db.Migrate(d); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestAuditHMACIsDeterministic(t *testing.T) {
	d := openTestDB(t)
	d.SetAPIKey("test-key")

	h1 := d.AuditHMAC(1700000000.0, "alice", "login_success", "", "")
	h2 := d.AuditHMAC(1700000000.0, "alice", "login_success", "", "")
	if h1 != h2 {
		t.Errorf("HMAC not deterministic: %s != %s", h1, h2)
	}
}

func TestAuditHMACChangesWithKey(t *testing.T) {
	d := openTestDB(t)
	d.SetAPIKey("key-A")
	h1 := d.AuditHMAC(1700000000.0, "alice", "login_success", "", "")

	d.SetAPIKey("key-B")
	h2 := d.AuditHMAC(1700000000.0, "alice", "login_success", "", "")

	if h1 == h2 {
		t.Error("different keys must produce different HMACs")
	}
}

func TestAuditHMACChangesWithField(t *testing.T) {
	d := openTestDB(t)
	d.SetAPIKey("test-key")

	h1 := d.AuditHMAC(1700000000.0, "alice", "login_success", "", "")
	h2 := d.AuditHMAC(1700000000.0, "alice", "login_failed", "", "")
	if h1 == h2 {
		t.Error("different actions must produce different HMACs")
	}
}

func TestAuditWriteAndRead(t *testing.T) {
	d := openTestDB(t)
	d.SetAPIKey("test-key")
	ctx := context.Background()

	if err := d.Audit(ctx, "admin", "login_success", "admin", ""); err != nil {
		t.Fatalf("audit write: %v", err)
	}

	var count int
	d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_log WHERE actor = 'admin'`).Scan(&count)
	if count == 0 {
		t.Error("audit row not written")
	}
}

func TestAuditRowsAreImmutable(t *testing.T) {
	d := openTestDB(t)
	d.SetAPIKey("test-key")
	ctx := context.Background()

	// Use an explicit transaction so the RowExclusiveLock held by the INSERT
	// blocks concurrent TRUNCATEs (from parallel package test cleanups) for the
	// duration of the INSERT → UPDATE → SELECT sequence.
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	ts := float64(time.Now().UnixMicro()) / 1e6
	hmac := d.AuditHMAC(ts, "alice", "login_success", "", "")
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_log (ts, actor, action, target, detail, row_hmac)
		 VALUES ($1, 'alice', 'login_success', '', '', $2)`, ts, hmac); err != nil {
		t.Fatalf("audit write: %v", err)
	}

	// SAVEPOINT before the UPDATE: the BEFORE UPDATE trigger raises an exception
	// which puts the transaction into PostgreSQL's 'E' (error) state; rolling back
	// to the savepoint restores it to a usable state without releasing the table lock.
	if _, err := tx.Exec(ctx, `SAVEPOINT before_update`); err != nil {
		t.Fatalf("savepoint: %v", err)
	}

	ct, updErr := tx.Exec(ctx, `UPDATE audit_log SET actor = 'hacked' WHERE actor = 'alice'`)
	if updErr != nil {
		t.Logf("update returned error (expected): %v", updErr)
	}
	if ct.RowsAffected() > 0 {
		t.Error("audit rows should be immutable — UPDATE should have no effect")
	}

	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT before_update`); err != nil {
		t.Fatalf("rollback to savepoint: %v", err)
	}

	var actor string
	if err := tx.QueryRow(ctx,
		`SELECT actor FROM audit_log WHERE actor = 'alice' LIMIT 1`,
	).Scan(&actor); err != nil {
		t.Fatalf("SELECT after UPDATE: %v", err)
	}
	if actor != "alice" {
		t.Errorf("actor modified despite immutability rule: got %q", actor)
	}
}

func TestPingHealthy(t *testing.T) {
	d := openTestDB(t)
	if err := d.Pool.Ping(context.Background()); err != nil {
		t.Errorf("ping failed: %v", err)
	}
}
