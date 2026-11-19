package main

import (
	"testing"
	"time"
)

func TestAutomaticBanDurationBoundsAndDefault(t *testing.T) {
	got, err := automaticBanDuration(nil)
	if err != nil || got != 15*time.Minute {
		t.Fatalf("default automatic TTL=%s err=%v", got, err)
	}
	for _, tc := range []struct {
		seconds int
		valid   bool
	}{
		{-1, false}, {0, false}, {29, false},
		{30, true}, {120, true}, {86400, true}, {86401, false},
	} {
		got, err := automaticBanDuration(&tc.seconds)
		if (err == nil) != tc.valid {
			t.Fatalf("seconds=%d valid=%t err=%v", tc.seconds, tc.valid, err)
		}
		if tc.valid && got != time.Duration(tc.seconds)*time.Second {
			t.Fatalf("seconds=%d duration=%s", tc.seconds, got)
		}
	}
}

func TestAutomaticBanDurationDoesNotChangeManualDefault(t *testing.T) {
	previous := config.Security.AutomaticBanTTLSeconds
	defer func() { config.Security.AutomaticBanTTLSeconds = previous }()
	seconds := 60
	config.Security.AutomaticBanTTLSeconds = &seconds
	if getAutomaticBanDuration() != time.Minute {
		t.Fatal("automatic TTL was not applied")
	}
	manual, err := manualBanDuration(nil)
	if err != nil || manual != getBanDuration() {
		t.Fatalf("manual default changed: %s, %v", manual, err)
	}
}
