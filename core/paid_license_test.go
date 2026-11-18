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

func TestCommunityHostEnforcementRequiresExplicitMode(t *testing.T) {
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
	if shouldEnforce("8.8.8.8", 443) {
		t.Fatal("TEST mode must not enforce")
	}
	if err := SetMode(ModeEnforce); err != nil || !shouldEnforce("8.8.8.8", 443) {
		t.Fatalf("explicit ENFORCE transition failed: mode=%s err=%v", Mode(), err)
	}
	if err := SetMode(ModeTest); err != nil || shouldEnforce("8.8.8.8", 443) {
		t.Fatalf("return to TEST failed: mode=%s err=%v", Mode(), err)
	}
	if err := SetMode(ModeLockdown); err != nil || Mode() != ModeLockdown {
		t.Fatalf("explicit LOCKDOWN transition failed: mode=%s err=%v", Mode(), err)
	}
}

func TestEntitlementLossDoesNotDisableLocalMode(t *testing.T) {
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
		t.Fatalf("legacy entitlement changed local mode to %s", Mode())
	}
}
