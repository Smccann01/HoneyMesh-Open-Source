package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"honeymesh/internal/banownership"
	"honeymesh/internal/enforcementengine"
)

type runtimeFakeKernel struct {
	active     map[string]bool
	applies    int
	removes    int
	failRemove bool
}

func (k *runtimeFakeKernel) Apply(ip string) error {
	k.active[ip] = true
	k.applies++
	return nil
}
func (k *runtimeFakeKernel) Remove(ip string) error {
	if k.failRemove {
		return errors.New("kernel remove failed")
	}
	delete(k.active, ip)
	k.removes++
	return nil
}

func TestLiveUEEAppExchangeAndLocalOwnership(t *testing.T) {
	database := testNodeEdgeDB(t)
	kernel := &runtimeFakeKernel{active: make(map[string]bool)}
	engine, err := enforcementengine.NewWithEnforcement(database, kernel, true)
	if err != nil {
		t.Fatal(err)
	}
	previous := liveUEE
	liveUEE = engine
	t.Cleanup(func() { liveUEE = previous })
	manager, err := newExchangeRuleManager(database, func(string) error { t.Fatal("legacy Exchange apply called"); return nil }, func(string) error { t.Fatal("legacy Exchange remove called"); return nil })
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ip := "8.8.8.8"
	if _, err := ueeLocalGrant(ip, "MANUAL", "operator", now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	app := testNodeEdgeController(database, true, now)
	event := testNodeEdgeEvent("app_event_12345")
	event.AppID = "app_alpha_01"
	if status, err := app.onEvent(context.Background(), event); err != nil || status != "blocked" {
		t.Fatalf("app: %s %v", status, err)
	}
	if err := manager.applyRecord(exchangeRecord("signal_alpha_01", ip), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	grants, err := engine.Grants(ip, now)
	if err != nil || len(grants) != 3 || !kernel.active[ip] {
		t.Fatalf("overlap: grants=%+v active=%v err=%v", grants, kernel.active[ip], err)
	}
	if err := manager.retract(retraction("signal_alpha_01", ip)); err != nil {
		t.Fatal(err)
	}
	grants, err = engine.Grants(ip, time.Now())
	if err != nil || len(grants) != 2 || !kernel.active[ip] {
		t.Fatalf("retraction removed another owner: grants=%+v active=%v err=%v", grants, kernel.active[ip], err)
	}
	if _, err := engine.Remove(ip, banownership.Owner{Kind: banownership.Local, ID: "manual"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !kernel.active[ip] {
		t.Fatal("local release removed app rule")
	}
	if _, err := engine.Remove(ip, appGrantOwner(event.AppID, event.EventID), time.Now()); err != nil {
		t.Fatal(err)
	}
	if kernel.active[ip] || kernel.removes != 1 {
		t.Fatalf("final owner not removed: active=%v removes=%d", kernel.active[ip], kernel.removes)
	}
}

func TestLiveUEEFailedRemovalIsRetried(t *testing.T) {
	database := testNodeEdgeDB(t)
	kernel := &runtimeFakeKernel{active: make(map[string]bool)}
	engine, err := enforcementengine.NewWithEnforcement(database, kernel, true)
	if err != nil {
		t.Fatal(err)
	}
	previous := liveUEE
	liveUEE = engine
	t.Cleanup(func() { liveUEE = previous })
	ip := "8.8.4.4"
	if _, err := ueeLocalGrant(ip, "MANUAL", "test", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	kernel.failRemove = true
	if _, err := engine.Remove(ip, localOwner("MANUAL"), time.Now()); err == nil || !kernel.active[ip] {
		t.Fatalf("failed remove lost state: active=%v err=%v", kernel.active[ip], err)
	}
	kernel.failRemove = false
	if err := engine.RetryFailed(time.Now()); err != nil || kernel.active[ip] {
		t.Fatalf("retry failed: active=%v err=%v", kernel.active[ip], err)
	}
}

func TestLiveUEEModeChangeKeepsLocalAndClearsRemoteAppGrants(t *testing.T) {
	testPaidHostLicense(t)
	database := testNodeEdgeDB(t)
	kernel := &runtimeFakeKernel{active: make(map[string]bool)}
	engine, err := enforcementengine.NewWithEnforcement(database, kernel, true)
	if err != nil {
		t.Fatal(err)
	}
	previousEngine, previousRules := liveUEE, liveExchangeRules
	liveUEE = engine
	manager, err := newExchangeRuleManager(database, func(string) error { t.Fatal("legacy apply"); return nil }, func(string) error { t.Fatal("legacy remove"); return nil })
	if err != nil {
		t.Fatal(err)
	}
	liveExchangeRules = manager
	previousMode := Mode()
	ModeMu.Lock()
	GlobalMode = ModeEnforce
	ModeMu.Unlock()
	t.Cleanup(func() {
		liveUEE, liveExchangeRules = previousEngine, previousRules
		ModeMu.Lock()
		GlobalMode = previousMode
		ModeMu.Unlock()
	})
	ip := "8.8.8.8"
	if _, err := ueeLocalGrant(ip, "MANUAL", "operator", time.Now().Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := ueeAppGrant(ip, "app_alpha_01", "event_alpha_01", "app event", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := manager.applyRecord(exchangeRecord("signal_alpha_01", ip), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := SetMode(ModeTest); err != nil {
		t.Fatal(err)
	}
	if kernel.active[ip] {
		t.Fatal("TEST retained kernel rule")
	}
	grants, err := engine.Grants(ip, time.Now())
	if err != nil || len(grants) != 1 || grants[0].Owner.Kind != banownership.Local {
		t.Fatalf("TEST grant lifecycle: %+v %v", grants, err)
	}
	if err := SetMode(ModeEnforce); err != nil {
		t.Fatal(err)
	}
	if !kernel.active[ip] {
		t.Fatal("ENFORCE did not restore local rule")
	}
}

func TestLiveUEEAppExpiryAuditKeepsOtherOwner(t *testing.T) {
	database := testNodeEdgeDB(t)
	kernel := &runtimeFakeKernel{active: make(map[string]bool)}
	engine, err := enforcementengine.NewWithEnforcement(database, kernel, true)
	if err != nil {
		t.Fatal(err)
	}
	previous := liveUEE
	liveUEE = engine
	t.Cleanup(func() { liveUEE = previous })
	now := time.Now()
	ip := "8.8.8.8"
	if _, err := ueeLocalGrant(ip, "MANUAL", "operator", now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	app := testNodeEdgeController(database, true, now)
	event := testNodeEdgeEvent("app_expiry_12345")
	event.AppID = "app_alpha_01"
	if status, err := app.onEvent(context.Background(), event); err != nil || status != "blocked" {
		t.Fatalf("app: %s %v", status, err)
	}
	later := now.Add(61 * time.Second)
	if err := engine.Sweep(later); err != nil {
		t.Fatal(err)
	}
	if err := reconcileNodeEdgeAuditExpiry(later); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := database.QueryRow(`SELECT status FROM node_edge_events WHERE event_id=?`, event.EventID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "expired" || !kernel.active[ip] {
		t.Fatalf("app expiry affected local owner: status=%q active=%v", status, kernel.active[ip])
	}
}
