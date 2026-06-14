package db_test

import (
	"context"
	"os"
	"strings"
	"testing"

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

	d.Audit(ctx, "alice", "login_success", "", "")

	// PG rule blocks update — UPDATE returns 0 rows affected, no error
	ct, err := d.Pool.Exec(ctx,
		`UPDATE audit_log SET actor = 'hacked' WHERE actor = 'alice'`)
	if err != nil {
		t.Logf("update returned error (expected): %v", err)
	}
	if ct.RowsAffected() > 0 {
		t.Error("audit rows should be immutable — UPDATE should have no effect")
	}

	var actor string
	d.Pool.QueryRow(ctx, `SELECT actor FROM audit_log WHERE actor = 'alice' LIMIT 1`).Scan(&actor)
	if !strings.Contains(actor, "alice") {
		t.Error("actor was modified despite immutability rule")
	}
}

func TestPingHealthy(t *testing.T) {
	d := openTestDB(t)
	if err := d.Pool.Ping(context.Background()); err != nil {
		t.Errorf("ping failed: %v", err)
	}
}
