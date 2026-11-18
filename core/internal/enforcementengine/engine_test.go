package enforcementengine

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"honeymesh/internal/banownership"
	_ "modernc.org/sqlite"
)

type fakeKernel struct {
	active     map[string]bool
	failApply  bool
	failRemove bool
}

func TestGrantLimitIsBoundedPerSource(t *testing.T) {
	e, kernel, _ := testEngine(t)
	now := time.Now()
	ip := "192.0.2.19"
	for i := 0; i < kindLimit(banownership.Exchange); i++ {
		owner := banownership.Owner{Kind: banownership.Exchange, ID: fmt.Sprintf("signal-%d", i)}
		if _, err := e.Put(Grant{IP: ip, Owner: owner, ExpiresAt: now.Add(time.Minute), Reason: "test", PolicyVersion: "rc4-test-1"}, now); err != nil {
			t.Fatalf("grant %d: %v", i, err)
		}
	}
	if _, err := e.Put(Grant{IP: ip, Owner: banownership.Owner{Kind: banownership.Exchange, ID: "overflow"}, ExpiresAt: now.Add(time.Minute), Reason: "test", PolicyVersion: "rc4-test-1"}, now); err == nil {
		t.Fatal("65th active owner accepted")
	}
	if _, err := e.Put(Grant{IP: ip, Owner: banownership.Owner{Kind: banownership.Local, ID: "local-trap"}, ExpiresAt: now.Add(time.Minute), Reason: "direct detection", PolicyVersion: "rc4-test-1"}, now); err != nil {
		t.Fatalf("shared-signal limit blocked direct local protection: %v", err)
	}
	if _, err := e.Put(Grant{IP: ip, Owner: banownership.Owner{Kind: banownership.Exchange, ID: "signal-0"}, ExpiresAt: now.Add(2 * time.Minute), Reason: "updated", PolicyVersion: "rc4-test-1"}, now); err != nil {
		t.Fatalf("existing owner could not refresh at limit: %v", err)
	}
	grants, err := e.Grants(ip, now)
	if err != nil || len(grants) != kindLimit(banownership.Exchange)+1 || !kernel.active[ip] {
		t.Fatalf("grant limit affected active block: len=%d active=%v err=%v", len(grants), kernel.active[ip], err)
	}
}

func (k *fakeKernel) Apply(ip string) error {
	if k.failApply {
		return errors.New("apply failed")
	}
	k.active[ip] = true
	return nil
}

func (k *fakeKernel) Remove(ip string) error {
	if k.failRemove {
		return errors.New("remove failed")
	}
	delete(k.active, ip)
	return nil
}

func testEngine(t *testing.T) (*Engine, *fakeKernel, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	kernel := &fakeKernel{active: make(map[string]bool)}
	engine, err := New(db, kernel)
	if err != nil {
		t.Fatal(err)
	}
	return engine, kernel, db
}

func TestTestModeRetainsGrantWithoutClaimingKernelBlock(t *testing.T) {
	_, kernel, db := testEngine(t)
	e, err := NewWithEnforcement(db, kernel, false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ip := "192.0.2.44"
	grant := Grant{IP: ip, Owner: banownership.Owner{Kind: banownership.Local, ID: "manual"}, ExpiresAt: now.Add(time.Hour), Reason: "manual", PolicyVersion: "rc4-test-1"}
	if _, err := e.Put(grant, now); err != nil || kernel.active[ip] {
		t.Fatalf("TEST applied a pending grant: active=%v err=%v", kernel.active[ip], err)
	}
	entries, err := e.Snapshot(now)
	if err != nil || len(entries) != 1 || entries[0].KernelApplied || entries[0].Owners != 1 {
		t.Fatalf("TEST snapshot confused grant with block: %+v err=%v", entries, err)
	}
	if err := e.SetEnabled(true, now.Add(time.Second)); err != nil || !kernel.active[ip] {
		t.Fatalf("ENFORCE did not restore grant: active=%v err=%v", kernel.active[ip], err)
	}
	if err := e.SetEnabled(false, now.Add(2*time.Second)); err != nil || kernel.active[ip] {
		t.Fatalf("TEST did not remove effective rule: active=%v err=%v", kernel.active[ip], err)
	}
	restarted, err := NewWithEnforcement(db, kernel, false)
	if err != nil || restarted.ReconcileAll(now.Add(3*time.Second)) != nil || kernel.active[ip] {
		t.Fatalf("restart reapplied TEST grant: active=%v err=%v", kernel.active[ip], err)
	}
	if err := restarted.SetEnabled(true, now.Add(4*time.Second)); err != nil || !kernel.active[ip] {
		t.Fatalf("post-restart ENFORCE did not restore grant: active=%v err=%v", kernel.active[ip], err)
	}
}

func TestFailedEnableKeepsTestModeAndPendingGrant(t *testing.T) {
	_, kernel, db := testEngine(t)
	e, err := NewWithEnforcement(db, kernel, false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ip := "192.0.2.45"
	grant := Grant{IP: ip, Owner: banownership.Owner{Kind: banownership.Local, ID: "manual"}, ExpiresAt: now.Add(time.Hour), Reason: "manual", PolicyVersion: "rc4-test-1"}
	if _, err := e.Put(grant, now); err != nil {
		t.Fatal(err)
	}
	kernel.failApply = true
	if err := e.SetEnabled(true, now.Add(time.Second)); err == nil {
		t.Fatal("failed kernel apply acknowledged as ENFORCE")
	}
	entries, err := e.Snapshot(now.Add(time.Second))
	if err != nil || len(entries) != 1 || entries[0].KernelApplied || entries[0].Owners != 1 {
		t.Fatalf("failed transition lost pending grant: %+v err=%v", entries, err)
	}
	if _, err := e.Put(Grant{IP: "192.0.2.46", Owner: grant.Owner, ExpiresAt: now.Add(time.Hour), Reason: "manual", PolicyVersion: "rc4-test-1"}, now.Add(2*time.Second)); err != nil {
		t.Fatalf("engine stayed enabled after failed transition: %v", err)
	}
}

func TestIndependentGrantsPreserveKernelUntilFinalOwner(t *testing.T) {
	e, kernel, _ := testEngine(t)
	now := time.Now()
	ip := "192.0.2.8"
	owners := []banownership.Owner{
		{Kind: banownership.Local, ID: "trap-80"},
		{Kind: banownership.App, ID: "app-a:event-1"},
		{Kind: banownership.Exchange, ID: "signal-a"},
		{Kind: banownership.Exchange, ID: "signal-b"},
	}
	for i, owner := range owners {
		decision, err := e.Put(Grant{IP: ip, Owner: owner, ExpiresAt: now.Add(time.Duration(i+1) * time.Minute), Reason: "controlled test", PolicyVersion: "rc4-test-1"}, now)
		if err != nil || decision.Owners != i+1 || !kernel.active[ip] {
			t.Fatalf("grant %d: decision=%+v err=%v kernel=%v", i, decision, err, kernel.active)
		}
	}
	for i, owner := range owners {
		decision, err := e.Remove(ip, owner, now)
		if err != nil || decision.Owners != len(owners)-i-1 || kernel.active[ip] != (i < len(owners)-1) {
			t.Fatalf("remove %d: decision=%+v err=%v kernel=%v", i, decision, err, kernel.active)
		}
	}
}

func TestKernelFailureKeepsDesiredStateForRetry(t *testing.T) {
	e, kernel, db := testEngine(t)
	now := time.Now()
	owner := banownership.Owner{Kind: banownership.App, ID: "app-a:event-1"}
	kernel.failApply = true
	if _, err := e.Put(Grant{IP: "::ffff:192.0.2.8", Owner: owner, ExpiresAt: now.Add(time.Minute), Reason: "app evidence", PolicyVersion: "rc4-test-1"}, now); err == nil {
		t.Fatal("kernel failure hidden")
	}
	grants, err := e.Grants("192.0.2.8", now)
	if err != nil || len(grants) != 1 || grants[0].IP != "192.0.2.8" {
		t.Fatalf("desired grant lost: grants=%v err=%v", grants, err)
	}
	var kernelApplied int
	var lastError string
	if err := db.QueryRow(`SELECT kernel_applied,last_error FROM enforcement_ip_state WHERE ip=?`, "192.0.2.8").Scan(&kernelApplied, &lastError); err != nil || kernelApplied != 0 || lastError == "" {
		t.Fatalf("failed apply not recorded: applied=%d error=%q db=%v", kernelApplied, lastError, err)
	}
	var result, reconcileStatus, operation string
	if err := db.QueryRow(`SELECT result,reconcile_status,operation FROM enforcement_decision_audit ORDER BY id DESC LIMIT 1`).Scan(&result, &reconcileStatus, &operation); err != nil || result != "error" || reconcileStatus != "retry" || operation != "apply" {
		t.Fatalf("failed apply audit missing: %q %q %q err=%v", result, reconcileStatus, operation, err)
	}
	kernel.failApply = false
	restarted, err := New(db, kernel)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ReconcileAll(now); err != nil || !kernel.active["192.0.2.8"] {
		t.Fatalf("restart did not apply desired grant: %v active=%v", err, kernel.active)
	}
	kernel.failRemove = true
	if _, err := restarted.Remove("192.0.2.8", owner, now); err == nil {
		t.Fatal("failed removal acknowledged")
	}
	if !kernel.active["192.0.2.8"] {
		t.Fatal("fake kernel unexpectedly released")
	}
	if err := db.QueryRow(`SELECT kernel_applied,last_error FROM enforcement_ip_state WHERE ip=?`, "192.0.2.8").Scan(&kernelApplied, &lastError); err != nil || kernelApplied != 1 || lastError == "" {
		t.Fatalf("failed removal not recorded: applied=%d error=%q db=%v", kernelApplied, lastError, err)
	}
	if err := db.QueryRow(`SELECT result,reconcile_status,operation FROM enforcement_decision_audit ORDER BY id DESC LIMIT 1`).Scan(&result, &reconcileStatus, &operation); err != nil || result != "error" || reconcileStatus != "retry" || operation != "remove" {
		t.Fatalf("failed removal audit missing: %q %q %q err=%v", result, reconcileStatus, operation, err)
	}
	snapshot, err := restarted.Snapshot(now)
	if err != nil || len(snapshot) != 1 || snapshot[0].Owners != 0 || !snapshot[0].KernelApplied || snapshot[0].LastError == "" {
		t.Fatalf("failed removal missing from operator view: snapshot=%+v err=%v", snapshot, err)
	}
	kernel.failRemove = false
	if err := restarted.ReconcileAll(now); err != nil || kernel.active["192.0.2.8"] {
		t.Fatalf("failed removal was not retried: %v active=%v", err, kernel.active)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM enforcement_ip_state WHERE ip=?`, "192.0.2.8").Scan(&count); err != nil || count != 0 {
		t.Fatalf("released state was not pruned: count=%d err=%v", count, err)
	}
}

func TestExpiryOnlyRemovesExpiredOwner(t *testing.T) {
	e, kernel, _ := testEngine(t)
	now := time.Now()
	ip := "2001:db8::8"
	short := banownership.Owner{Kind: banownership.Local, ID: "short"}
	long := banownership.Owner{Kind: banownership.Mesh, ID: "peer-b"}
	for _, grant := range []Grant{
		{IP: ip, Owner: short, ExpiresAt: now.Add(30 * time.Second), Reason: "short", PolicyVersion: "rc4-test-1"},
		{IP: ip, Owner: long, ExpiresAt: now.Add(2 * time.Minute), Reason: "long", PolicyVersion: "rc4-test-1"},
	} {
		if _, err := e.Put(grant, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Sweep(now.Add(time.Minute)); err != nil || !kernel.active[ip] {
		t.Fatalf("sweep removed surviving owner: %v active=%v", err, kernel.active)
	}
	grants, err := e.Grants(ip, now.Add(time.Minute))
	if err != nil || len(grants) != 1 || grants[0].Owner != long {
		t.Fatalf("wrong remaining grants: %v %v", grants, err)
	}
	if err := e.Sweep(now.Add(3 * time.Minute)); err != nil || kernel.active[ip] {
		t.Fatalf("final expiry failed: %v active=%v", err, kernel.active)
	}
}

func TestScopedOverrideSurvivesFeedRefreshAndExpires(t *testing.T) {
	e, kernel, db := testEngine(t)
	now := time.Now()
	ip := "2001:db8::20"
	local := banownership.Owner{Kind: banownership.Local, ID: "trap-80"}
	remote := banownership.Owner{Kind: banownership.Exchange, ID: "signal-20"}
	grant := func(owner banownership.Owner, ttl time.Duration) Grant {
		return Grant{IP: ip, Owner: owner, ExpiresAt: now.Add(ttl), Reason: "controlled test", PolicyVersion: "rc4-test-1"}
	}
	if _, err := e.Put(grant(local, 10*time.Minute), now); err != nil || !kernel.active[ip] {
		t.Fatalf("local grant failed: %v", err)
	}
	decision, err := e.SetOverride(ip, "operator-1", "incorrect lab block", time.Minute, now)
	if err != nil || decision.Active || decision.Owners != 1 || kernel.active[ip] {
		t.Fatalf("override failed: decision=%+v err=%v active=%v", decision, err, kernel.active[ip])
	}
	if _, err := e.Put(grant(remote, 5*time.Minute), now.Add(10*time.Second)); err != nil || kernel.active[ip] {
		t.Fatalf("feed refresh bypassed override: %v active=%v", err, kernel.active[ip])
	}
	snapshot, err := e.Snapshot(now.Add(10 * time.Second))
	if err != nil || len(snapshot) != 1 || snapshot[0].Owners != 2 || snapshot[0].KernelApplied || snapshot[0].OverrideExpiresAt.IsZero() {
		t.Fatalf("override operator view is misleading: snapshot=%+v err=%v", snapshot, err)
	}
	restarted, err := New(db, kernel)
	if err != nil || restarted.ReconcileAll(now.Add(20*time.Second)) != nil || kernel.active[ip] {
		t.Fatalf("restart bypassed override: %v active=%v", err, kernel.active[ip])
	}
	if err := restarted.Sweep(now.Add(61 * time.Second)); err != nil || !kernel.active[ip] {
		t.Fatalf("override expiry did not restore grants: %v active=%v", err, kernel.active[ip])
	}
	snapshot, err = restarted.Snapshot(now.Add(61 * time.Second))
	if err != nil || len(snapshot) != 1 || !snapshot[0].KernelApplied || !snapshot[0].OverrideExpiresAt.IsZero() {
		t.Fatalf("restored operator view is misleading: snapshot=%+v err=%v", snapshot, err)
	}
	grants, err := restarted.Grants(ip, now.Add(61*time.Second))
	if err != nil || len(grants) != 2 {
		t.Fatalf("override destroyed independent grants: %v %v", grants, err)
	}
	var overrideActive int
	if err := db.QueryRow(`SELECT override_active FROM enforcement_decision_audit WHERE ip=? AND override_active=1 LIMIT 1`, ip).Scan(&overrideActive); err != nil || overrideActive != 1 {
		t.Fatalf("override decision not audited: active=%d err=%v", overrideActive, err)
	}
	var auditCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM enforcement_override_audit WHERE ip=? AND actor='operator-1' AND action='set'`, ip).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("override actor not retained: count=%d err=%v", auditCount, err)
	}
}

func TestOverrideRemovalFailureIsRetried(t *testing.T) {
	e, kernel, _ := testEngine(t)
	now := time.Now()
	ip := "192.0.2.27"
	owner := banownership.Owner{Kind: banownership.App, ID: "app-a:event-27"}
	if _, err := e.Put(Grant{IP: ip, Owner: owner, ExpiresAt: now.Add(5 * time.Minute), Reason: "test", PolicyVersion: "rc4-test-1"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SetOverride(ip, "operator-1", "short", 29*time.Second, now); err == nil {
		t.Fatal("out-of-policy override accepted")
	}
	kernel.failRemove = true
	if _, err := e.SetOverride(ip, "operator-1", "incorrect block", time.Minute, now); err == nil || !kernel.active[ip] {
		t.Fatalf("failed kernel removal acknowledged: %v active=%v", err, kernel.active[ip])
	}
	kernel.failRemove = false
	if err := e.ReconcileAll(now.Add(time.Second)); err != nil || kernel.active[ip] {
		t.Fatalf("override removal not retried: %v active=%v", err, kernel.active[ip])
	}
	if _, err := e.ClearOverride(ip, "", now.Add(2*time.Second)); err == nil {
		t.Fatal("anonymous override release accepted")
	}
	if decision, err := e.ClearOverride(ip, "operator-2", now.Add(2*time.Second)); err != nil || !decision.Active || !kernel.active[ip] {
		t.Fatalf("clear did not restore grant: decision=%+v err=%v active=%v", decision, err, kernel.active[ip])
	}
}
