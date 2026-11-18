package adaptivetruststore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"honeymesh/internal/adaptivetrust"
	_ "modernc.org/sqlite"
)

func openStore(t *testing.T, path string) (*Store, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	store, err := New(db)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	return store, db
}

func testGrant(now time.Time) adaptivetrust.Grant {
	return adaptivetrust.Grant{ID: "grant-1", TenantID: "tenant-a", SubjectID: "web-a", ResourceID: "orders-api",
		Actions: []string{"orders.read"}, ApprovedBy: "operator-1", IssuedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour), PolicyVersion: "pilot-1"}
}

func testRequest() adaptivetrust.Request {
	return adaptivetrust.Request{TenantID: "tenant-a", SubjectID: "web-a", ResourceID: "orders-api",
		Action: "orders.read", SessionID: "session-1"}
}

func TestGrantIsScopedDurableAndInsertOnly(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "hat.db")
	store, db := openStore(t, path)
	grant := testGrant(now)
	if err := store.PutGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	if err := store.PutGrant(ctx, grant); err != nil {
		t.Fatalf("identical retry failed: %v", err)
	}
	changed := grant
	changed.Actions = []string{"orders.read", "admin.write"}
	if err := store.PutGrant(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("grant ID widened without new approval: %v", err)
	}
	request := testRequest()
	if got, err := store.ActiveGrant(ctx, request, "pilot-1", now); err != nil || got == nil || got.ID != grant.ID {
		t.Fatalf("active grant: %+v %v", got, err)
	}
	request.Action = "admin.write"
	if got, err := store.ActiveGrant(ctx, request, "pilot-1", now); err != nil || got != nil {
		t.Fatalf("unapproved action found grant: %+v %v", got, err)
	}
	request = testRequest()
	request.TenantID = "tenant-b"
	if got, err := store.ActiveGrant(ctx, request, "pilot-1", now); err != nil || got != nil {
		t.Fatalf("cross-tenant grant returned: %+v %v", got, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, db = openStore(t, path)
	defer db.Close()
	request = testRequest()
	if got, err := store.ActiveGrant(ctx, request, "pilot-1", now); err != nil || got == nil {
		t.Fatalf("grant not recovered after restart: %+v %v", got, err)
	}
	if err := store.RevokeGrant(ctx, grant.ID, "operator-2", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, err := store.ActiveGrant(ctx, request, "pilot-1", now.Add(2*time.Minute)); err != nil || got != nil {
		t.Fatalf("revoked grant remained active: %+v %v", got, err)
	}
}

func TestQuarantinePersistsUntilIndependentRelease(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "hat.db")
	store, db := openStore(t, path)
	hold := adaptivetrust.Hold{ID: "hold-1", TenantID: "tenant-a", SubjectID: "web-a", ResourceID: "orders-api",
		Action: "orders.read", PlacedBy: "operator-1", PlacedAt: now}
	if err := store.PlaceHold(ctx, hold); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, db = openStore(t, path)
	defer db.Close()
	got, err := store.ActiveHold(ctx, testRequest())
	if err != nil || got == nil || got.ID != hold.ID {
		t.Fatalf("quarantine disappeared after restart: %+v %v", got, err)
	}
	if err := store.ReleaseHold(ctx, hold.ID, ReleaseApproval{By: "operator-1", VerifierID: "posture-checker",
		VerificationID: "verification-1", At: now.Add(time.Minute)}); err == nil {
		t.Fatal("hold placer released own quarantine")
	}
	if err := store.ReleaseHold(ctx, hold.ID, ReleaseApproval{By: "operator-2", At: now.Add(time.Minute)}); err == nil {
		t.Fatal("quarantine released without independent verification")
	}
	if err := store.ReleaseHold(ctx, hold.ID, ReleaseApproval{By: "operator-2", VerifierID: "posture-checker",
		VerificationID: "verification-1", At: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if got, err := store.ActiveHold(ctx, testRequest()); err != nil || got != nil {
		t.Fatalf("released hold still active: %+v %v", got, err)
	}
}

func TestCorruptGrantCannotBecomeAnAllow(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	store, db := openStore(t, filepath.Join(t.TempDir(), "hat.db"))
	defer db.Close()
	if err := store.PutGrant(ctx, testGrant(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE hat_grants SET payload_json='broken' WHERE id='grant-1'`); err != nil {
		t.Fatal(err)
	}
	if got, err := store.ActiveGrant(ctx, testRequest(), "pilot-1", now); err == nil || got != nil {
		t.Fatalf("corrupt grant treated as usable: %+v %v", got, err)
	}
}

func TestDecisionHistoryIsBoundedAndScoped(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	store, db := openStore(t, filepath.Join(t.TempDir(), "hat.db"))
	defer db.Close()
	request := testRequest()
	for _, reason := range []string{"posture_unverified", "explicit_grant_verified"} {
		decision := adaptivetrust.Decision{SchemaVersion: adaptivetrust.SchemaVersion,
			State: adaptivetrust.Provisional, Effect: adaptivetrust.Verify, Reason: reason,
			PolicyVersion: "pilot-1", EvaluatedAt: now}
		if err := store.AppendDecision(ctx, request, decision); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.RecentDecisions(ctx, request, 1)
	if err != nil || len(got) != 1 || got[0].Reason != "explicit_grant_verified" {
		t.Fatalf("bounded history: %+v %v", got, err)
	}
	other := request
	other.TenantID = "tenant-b"
	if got, err := store.RecentDecisions(ctx, other, 10); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant history: %+v %v", got, err)
	}
	if _, err := store.RecentDecisions(ctx, request, 101); err == nil {
		t.Fatal("unbounded history query accepted")
	}
}

func TestPreviewUsesOnlyDurableLocalAuthority(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	store, db := openStore(t, filepath.Join(t.TempDir(), "hat.db"))
	defer db.Close()
	input := adaptivetrust.Input{SchemaVersion: adaptivetrust.SchemaVersion,
		Request: testRequest(), Identity: &adaptivetrust.Identity{SubjectID: "web-a", SessionID: "session-1",
			VerifierID: "pilot-ca", Verified: true, ExpiresAt: now.Add(time.Minute)},
		Posture: &adaptivetrust.Posture{ID: "posture-1", SubjectID: "web-a", VerifierID: "posture-checker",
			Verified: true, ObservedAt: now, ExpiresAt: now.Add(time.Minute)},
		Policy: adaptivetrust.Policy{Version: "pilot-1", RequirePosture: true, MaxLease: 30 * time.Second}}
	forged := testGrant(now)
	input.Grant = &forged
	if got, err := store.Preview(ctx, input, now); err != nil || got.PermitsAt(now) {
		t.Fatalf("caller-supplied grant bypassed storage: %+v %v", got, err)
	}
	if err := store.PutGrant(ctx, forged); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Preview(ctx, input, now); err != nil || !got.PermitsAt(now) {
		t.Fatalf("approved read not previewed: %+v %v", got, err)
	}
	hold := adaptivetrust.Hold{ID: "hold-1", TenantID: "tenant-a", SubjectID: "web-a", ResourceID: "orders-api",
		Action: "orders.read", PlacedBy: "operator-1", PlacedAt: now}
	if err := store.PlaceHold(ctx, hold); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Preview(ctx, input, now); err != nil || got.State != adaptivetrust.Quarantined || got.PermitsAt(now) {
		t.Fatalf("caller omitted durable hold: %+v %v", got, err)
	}
}

func TestPreviewFailsClosedOnAuditOrStateError(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	store, db := openStore(t, filepath.Join(t.TempDir(), "hat.db"))
	defer db.Close()
	if err := store.PutGrant(ctx, testGrant(now)); err != nil {
		t.Fatal(err)
	}
	input := adaptivetrust.Input{SchemaVersion: adaptivetrust.SchemaVersion,
		Request: testRequest(), Identity: &adaptivetrust.Identity{SubjectID: "web-a", SessionID: "session-1",
			VerifierID: "pilot-ca", Verified: true, ExpiresAt: now.Add(time.Minute)},
		Posture: &adaptivetrust.Posture{ID: "posture-1", SubjectID: "web-a", VerifierID: "posture-checker",
			Verified: true, ObservedAt: now, ExpiresAt: now.Add(time.Minute)},
		Policy: adaptivetrust.Policy{Version: "pilot-1", RequirePosture: true, MaxLease: 30 * time.Second}}
	if _, err := db.Exec(`DROP TABLE hat_decisions`); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Preview(ctx, input, now); err == nil || got.PermitsAt(now) || got.Reason != "audit_unavailable" {
		t.Fatalf("audit failure permitted access: %+v %v", got, err)
	}
	if _, err := db.Exec(`DROP TABLE hat_grants`); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Preview(ctx, input, now); err == nil || got.PermitsAt(now) || got.Reason != "state_unavailable" {
		t.Fatalf("state failure permitted access: %+v %v", got, err)
	}
}
