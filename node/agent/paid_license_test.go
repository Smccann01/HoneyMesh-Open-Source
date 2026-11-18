package main

import (
	"testing"
	"time"

	"honeymesh/internal/license"
)

func testPaidHostLicense(t *testing.T) {
	t.Helper()
	tier, valid, expiry, nodes := license.Tier(), license.Valid(), license.ExpiresAt(), license.MaxNodes()
	license.SetStateForTesting(license.TierPro, true, time.Now().Add(time.Hour), 1)
	t.Cleanup(func() { license.SetStateForTesting(tier, valid, expiry, nodes) })
}

func TestFreeHostCanEnterLocalEnforcement(t *testing.T) {
	tier, valid, expiry, nodes := license.Tier(), license.Valid(), license.ExpiresAt(), license.MaxNodes()
	previousMode := Mode()
	license.SetStateForTesting(license.TierFree, true, time.Now().Add(time.Hour), 0)
	t.Cleanup(func() {
		license.SetStateForTesting(tier, valid, expiry, nodes)
		ModeMu.Lock()
		GlobalMode = previousMode
		ModeMu.Unlock()
	})
	ModeMu.Lock()
	GlobalMode = ModeTest
	ModeMu.Unlock()
	for _, mode := range []ModeType{ModeEnforce, ModeLockdown} {
		if err := SetMode(mode); err != nil || Mode() != mode {
			t.Fatalf("free host could not enter %s: mode=%s err=%v", mode, Mode(), err)
		}
	}
	if err := SetMode(ModeTest); err != nil {
		t.Fatal(err)
	}
	if shouldEnforce("8.8.8.8", 443) {
		t.Fatal("TEST mode allowed enforcement")
	}
	ModeMu.Lock()
	GlobalMode = ModeEnforce // A stale persisted mode must not authorize a new decision.
	ModeMu.Unlock()
	if !shouldEnforce("8.8.8.8", 443) {
		t.Fatal("free host did not allow explicit local enforcement")
	}
}

func TestEntitlementLossKeepsLocalMode(t *testing.T) {
	testPaidHostLicense(t)
	previousMode := Mode()
	t.Cleanup(func() {
		ModeMu.Lock()
		GlobalMode = previousMode
		ModeMu.Unlock()
	})
	if err := SetMode(ModeEnforce); err != nil {
		t.Fatal(err)
	}
	license.SetStateForTesting(license.TierFree, true, time.Now().Add(time.Hour), 0)
	cleanupBans()
	if Mode() != ModeEnforce {
		t.Fatalf("entitlement loss changed local mode to %s", Mode())
	}
}
