package main

import (
	"errors"
	"testing"
	"time"
)

func TestStoredCommunityBanReappliesWhenEnforceResumes(t *testing.T) {
	now := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	bans := map[string]time.Time{
		"192.0.2.10": now.Add(5 * time.Minute),
		"192.0.2.11": now.Add(-time.Minute),
	}
	kernel := make(map[string]bool)
	apply := func(ip string) error { kernel[ip] = true; return nil }
	remove := func(ip string) error { delete(kernel, ip); return nil }
	if err := reconcileLegacyBanSnapshot(bans, ModeTest, ModeEnforce, now, apply, remove); err != nil {
		t.Fatal(err)
	}
	if !kernel["192.0.2.10"] || kernel["192.0.2.11"] {
		t.Fatalf("incorrect restored state: %v", kernel)
	}
	if err := reconcileLegacyBanSnapshot(bans, ModeEnforce, ModeTest, now, apply, remove); err != nil {
		t.Fatal(err)
	}
	if len(kernel) != 0 || len(bans) != 2 {
		t.Fatalf("TEST must unapply without forgetting grants: kernel=%v bans=%v", kernel, bans)
	}
}

func TestFailedModeReconciliationRollsBackKernelWrites(t *testing.T) {
	now := time.Now()
	bans := map[string]time.Time{
		"192.0.2.10": now.Add(time.Hour),
		"192.0.2.11": now.Add(time.Hour),
	}
	kernel := make(map[string]bool)
	apply := func(ip string) error {
		if ip == "192.0.2.11" {
			return errors.New("kernel apply failed")
		}
		kernel[ip] = true
		return nil
	}
	remove := func(ip string) error { delete(kernel, ip); return nil }
	if err := reconcileLegacyBanSnapshot(bans, ModeTest, ModeEnforce, now, apply, remove); err == nil {
		t.Fatal("expected a checked kernel error")
	}
	if len(kernel) != 0 {
		t.Fatalf("partial enforcement left behind: %v", kernel)
	}
}
