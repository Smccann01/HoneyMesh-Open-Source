package enforcementengine

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"honeymesh/internal/banownership"
	_ "modernc.org/sqlite"
)

func TestGrantProvenanceAndDecisionJournal(t *testing.T) {
	e, kernel, db := testEngine(t)
	now := time.Now()
	owner := banownership.Owner{Kind: banownership.Exchange, ID: "signal-123"}
	grant := Grant{IP: "192.0.2.7", Owner: owner, ExpiresAt: now.Add(time.Minute), Reason: "service_probe", PolicyVersion: "rc4-policy-1", EvidenceRefs: []string{"event:abc123"}}
	if _, err := e.Put(grant, now); err != nil {
		t.Fatal(err)
	}
	got, err := e.Grants(grant.IP, now)
	if err != nil || len(got) != 1 || got[0].PolicyVersion != grant.PolicyVersion || len(got[0].EvidenceRefs) != 1 || got[0].EvidenceRefs[0] != grant.EvidenceRefs[0] {
		t.Fatalf("grant provenance lost: %+v %v", got, err)
	}
	var before, after, nextExpiry int64
	var ownerJSON, versionsJSON, operation, result, status string
	if err := db.QueryRow(`SELECT previous_active,next_active,next_expires_ns,owner_ids_json,policy_versions_json,operation,result,reconcile_status FROM enforcement_decision_audit ORDER BY id DESC LIMIT 1`).Scan(&before, &after, &nextExpiry, &ownerJSON, &versionsJSON, &operation, &result, &status); err != nil {
		t.Fatal(err)
	}
	var ids []string
	if err := json.Unmarshal([]byte(ownerJSON), &ids); err != nil {
		t.Fatal(err)
	}
	if before != 0 || after != 1 || nextExpiry != grant.ExpiresAt.UnixNano() || len(ids) != 1 || ids[0] != "exchange/signal-123" || versionsJSON != `["rc4-policy-1"]` || operation != "apply" || result != "success" || status != "converged" || !kernel.active[grant.IP] {
		t.Fatalf("apply journal invalid: %d %d %d %q %q %q %q %q", before, after, nextExpiry, ownerJSON, versionsJSON, operation, result, status)
	}
	if _, err := e.Remove(grant.IP, owner, now); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT previous_active,next_active,next_expires_ns,operation,result,reconcile_status FROM enforcement_decision_audit ORDER BY id DESC LIMIT 1`).Scan(&before, &after, &nextExpiry, &operation, &result, &status); err != nil {
		t.Fatal(err)
	}
	if before != 1 || after != 0 || nextExpiry != 0 || operation != "remove" || result != "success" || status != "converged" || kernel.active[grant.IP] {
		t.Fatalf("remove journal invalid: %d %d %d %q %q %q", before, after, nextExpiry, operation, result, status)
	}
	grant.EvidenceRefs = []string{"raw/url?secret=1"}
	if _, err := e.Put(grant, now); err == nil {
		t.Fatal("unrestricted evidence reference accepted")
	}
}

func TestLegacyImportPreservesExpiryAndIsOneTime(t *testing.T) {
	e, kernel, db := testEngine(t)
	now := time.Now().Truncate(time.Second)
	if _, err := db.Exec(`CREATE TABLE bans (ip TEXT PRIMARY KEY, expires INTEGER)`); err != nil {
		t.Fatal(err)
	}
	end := now.Add(5 * time.Hour)
	for _, row := range []struct {
		ip  string
		exp int64
	}{{"192.0.2.8", end.Unix()}, {"2001:db8::8", end.Unix()}, {"192.0.2.9", now.Add(-time.Second).Unix()}} {
		if _, err := db.Exec(`INSERT INTO bans (ip,expires) VALUES (?,?)`, row.ip, row.exp); err != nil {
			t.Fatal(err)
		}
	}
	count, err := e.ImportLegacyBans(now)
	if err != nil || count != 2 {
		t.Fatalf("legacy import: count=%d err=%v", count, err)
	}
	if len(kernel.active) != 0 {
		t.Fatal("import touched kernel before cutover reconciliation")
	}
	for _, ip := range []string{"192.0.2.8", "2001:db8::8"} {
		grants, err := e.Grants(ip, now)
		if err != nil || len(grants) != 1 || !grants[0].ExpiresAt.Equal(end) || grants[0].Owner.Kind != banownership.Local || grants[0].PolicyVersion != "rc4-legacy-import-v1" {
			t.Fatalf("legacy grant mismatch %s: %+v %v", ip, grants, err)
		}
	}
	count, err = e.ImportLegacyBans(now)
	if err != nil || count != 0 {
		t.Fatalf("legacy import was not idempotent: count=%d err=%v", count, err)
	}
	if err := e.ReconcileAll(now); err != nil || len(kernel.active) != 2 {
		t.Fatalf("cutover reconcile: active=%v err=%v", kernel.active, err)
	}
}

func TestLegacyImportRejectsRollbackWritesAfterCutover(t *testing.T) {
	for name, change := range map[string]func(*testing.T, *sql.DB, time.Time){
		"new ban": func(t *testing.T, db *sql.DB, end time.Time) {
			if _, err := db.Exec(`INSERT INTO bans (ip,expires) VALUES (?,?)`, "192.0.2.19", end.Unix()); err != nil {
				t.Fatal(err)
			}
		},
		"extended ban": func(t *testing.T, db *sql.DB, end time.Time) {
			if _, err := db.Exec(`UPDATE bans SET expires=? WHERE ip=?`, end.Add(time.Hour).Unix(), "192.0.2.18"); err != nil {
				t.Fatal(err)
			}
		},
		"removed ban": func(t *testing.T, db *sql.DB, _ time.Time) {
			if _, err := db.Exec(`DELETE FROM bans WHERE ip=?`, "192.0.2.18"); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e, _, db := testEngine(t)
			now := time.Now().Truncate(time.Second)
			end := now.Add(5 * time.Hour)
			if _, err := db.Exec(`CREATE TABLE bans (ip TEXT PRIMARY KEY, expires INTEGER)`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO bans (ip,expires) VALUES (?,?)`, "192.0.2.18", end.Unix()); err != nil {
				t.Fatal(err)
			}
			if _, err := e.ImportLegacyBans(now); err != nil {
				t.Fatal(err)
			}
			change(t, db, end)
			if _, err := e.ImportLegacyBans(now); err == nil {
				t.Fatal("RC4 accepted changed legacy bans after cutover marker")
			}
		})
	}
}

func TestSchemaUpgradeAddsProvenanceColumns(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE enforcement_grants (ip TEXT NOT NULL,owner_kind TEXT NOT NULL,owner_id TEXT NOT NULL,expires_at_ns INTEGER NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(ip,owner_kind,owner_id));
		CREATE TABLE enforcement_ip_state (ip TEXT PRIMARY KEY,kernel_applied INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '');`)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &fakeKernel{active: make(map[string]bool)}
	e, err := New(db, kernel)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := e.Put(Grant{IP: "192.0.2.12", Owner: banownership.Owner{Kind: banownership.Local, ID: "trap-80"}, ExpiresAt: now.Add(time.Minute), Reason: "probe", PolicyVersion: "rc4-policy-1"}, now); err != nil {
		t.Fatal(err)
	}
}
