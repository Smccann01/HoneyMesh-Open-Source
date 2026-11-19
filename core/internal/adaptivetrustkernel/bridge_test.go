package adaptivetrustkernel

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"honeymesh/internal/adaptivetrust"
	"honeymesh/internal/adaptivetruststore"
	"honeymesh/internal/banownership"
	"honeymesh/internal/enforcementengine"
	_ "modernc.org/sqlite"
)

type testKernel struct {
	active map[string]bool
	fail   bool
}

func (k *testKernel) Apply(ip string) error {
	if k.fail {
		return errors.New("kernel map write failed")
	}
	k.active[ip] = true
	return nil
}
func (k *testKernel) Remove(ip string) error { delete(k.active, ip); return nil }

func testBridge(t *testing.T, enabled bool) (*adaptivetruststore.Store, *enforcementengine.Engine, *testKernel) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	store, err := adaptivetruststore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &testKernel{active: map[string]bool{}}
	engine, err := enforcementengine.NewWithEnforcement(db, kernel, enabled)
	if err != nil {
		t.Fatal(err)
	}
	return store, engine, kernel
}

func testScope(now time.Time) (adaptivetrust.Request, SourceBinding, adaptivetrust.Policy) {
	request := adaptivetrust.Request{TenantID: "tenant-a", SubjectID: "web-a",
		ResourceID: NetworkResource, Action: QuarantineAction, SessionID: "network-session-1"}
	binding := SourceBinding{TenantID: "tenant-a", SubjectID: "web-a", IP: "192.0.2.11",
		VerifierID: "ip-verifier", EvidenceID: "binding-1", ApprovedBy: "operator-2",
		Verified: true, Exclusive: true, ExpiresAt: now.Add(time.Minute)}
	policy := adaptivetrust.Policy{Version: "hat-pilot-1", MaxLease: 30 * time.Second}
	return request, binding, policy
}

func placeTestHold(t *testing.T, store *adaptivetruststore.Store, request adaptivetrust.Request, now time.Time) {
	t.Helper()
	if err := store.PlaceHold(context.Background(), adaptivetrust.Hold{ID: "hold-1",
		TenantID: request.TenantID, SubjectID: request.SubjectID, ResourceID: request.ResourceID,
		Action: request.Action, PlacedBy: "operator-1", PlacedAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
}

func TestDedicatedNetworkHoldReachesUEEAndReportsActualMode(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, enabled := range []bool{false, true} {
		store, engine, kernel := testBridge(t, enabled)
		request, binding, policy := testScope(now)
		placeTestHold(t, store, request, now)
		result, err := ApplyQuarantine(context.Background(), store, engine, request, binding, policy, now)
		if err != nil || result.KernelApplied != enabled || kernel.active[binding.IP] != enabled ||
			result.LeaseUntil.After(now.Add(maxKernelLease)) {
			t.Fatalf("enabled=%v result=%+v kernel=%v err=%v", enabled, result, kernel.active, err)
		}
		view, grants, err := engine.Inspect(binding.IP, now)
		if err != nil || len(grants) != 1 || view.KernelApplied != enabled || grants[0].Owner.ID != result.OwnerID {
			t.Fatalf("UEE owner not scoped: view=%+v grants=%+v err=%v", view, grants, err)
		}
	}
}

func TestApplicationOrUnverifiedScopeCannotBlockIP(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	store, engine, kernel := testBridge(t, true)
	request, binding, policy := testScope(now)
	placeTestHold(t, store, request, now)
	cases := []struct {
		name string
		edit func(*adaptivetrust.Request, *SourceBinding)
	}{
		{"application route", func(r *adaptivetrust.Request, _ *SourceBinding) { r.ResourceID, r.Action = "orders-api", "orders.read" }},
		{"shared IP", func(_ *adaptivetrust.Request, b *SourceBinding) { b.Exclusive = false }},
		{"unverified IP", func(_ *adaptivetrust.Request, b *SourceBinding) { b.Verified = false }},
		{"wrong subject", func(_ *adaptivetrust.Request, b *SourceBinding) { b.SubjectID = "other" }},
		{"same approver", func(_ *adaptivetrust.Request, b *SourceBinding) { b.ApprovedBy = "operator-1" }},
		{"expired binding", func(_ *adaptivetrust.Request, b *SourceBinding) { b.ExpiresAt = now }},
		{"stale long-lived binding", func(_ *adaptivetrust.Request, b *SourceBinding) { b.ExpiresAt = now.Add(time.Hour) }},
		{"multicast IP", func(_ *adaptivetrust.Request, b *SourceBinding) { b.IP = "224.0.0.1" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, b := request, binding
			tc.edit(&r, &b)
			if result, err := ApplyQuarantine(context.Background(), store, engine, r, b, policy, now); err == nil {
				t.Fatalf("unsafe scope accepted: %+v", result)
			}
			if len(kernel.active) != 0 {
				t.Fatalf("unsafe scope changed kernel: %v", kernel.active)
			}
		})
	}
}

func TestNoHoldAndKernelFailureDoNotClaimProtection(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	store, engine, kernel := testBridge(t, true)
	request, binding, policy := testScope(now)
	if result, err := ApplyQuarantine(context.Background(), store, engine, request, binding, policy, now); err == nil || result.KernelApplied {
		t.Fatalf("missing hold accepted: %+v %v", result, err)
	}
	placeTestHold(t, store, request, now)
	kernel.fail = true
	if result, err := ApplyQuarantine(context.Background(), store, engine, request, binding, policy, now); err == nil || result.KernelApplied || kernel.active[binding.IP] {
		t.Fatalf("failed kernel apply reported protection: %+v %v", result, err)
	}
}

func TestLeaseExpiresWithoutRemovingIndependentOwner(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	store, engine, kernel := testBridge(t, true)
	request, binding, policy := testScope(now)
	placeTestHold(t, store, request, now)
	if _, err := ApplyQuarantine(context.Background(), store, engine, request, binding, policy, now); err != nil {
		t.Fatal(err)
	}
	independent := enforcementengine.Grant{IP: binding.IP,
		Owner:     banownership.Owner{Kind: banownership.Local, ID: "independent-detection"},
		ExpiresAt: now.Add(time.Minute), Reason: "independent local detection", PolicyVersion: "local-1"}
	if _, err := engine.Put(independent, now); err != nil {
		t.Fatal(err)
	}
	if err := engine.Sweep(now.Add(maxKernelLease + time.Second)); err != nil {
		t.Fatal(err)
	}
	view, grants, err := engine.Inspect(binding.IP, now.Add(maxKernelLease+time.Second))
	if err != nil || !view.KernelApplied || !kernel.active[binding.IP] || len(grants) != 1 || grants[0].Owner.ID != independent.Owner.ID {
		t.Fatalf("expired HAT owner affected independent owner: %+v %+v %v", view, grants, err)
	}
	if err := engine.Sweep(now.Add(time.Minute + time.Second)); err != nil {
		t.Fatal(err)
	}
	if kernel.active[binding.IP] {
		t.Fatal("expired final owner still blocks source")
	}
}
