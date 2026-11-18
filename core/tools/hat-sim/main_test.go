package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"honeymesh/internal/adaptivetrust"
)

func TestSimulatorFixturesKeepAuthorizationBoundary(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		file      string
		effect    adaptivetrust.Effect
		reason    string
		permitted bool
	}{
		{"hat-read-allow.json", adaptivetrust.Allow, "explicit_grant_verified", true},
		{"hat-admin-deny.json", adaptivetrust.Deny, "no_active_grant", false},
	} {
		t.Run(tt.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "docs", "fixtures", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			got, err := evaluateFixture(data, at)
			if err != nil || !got.Simulation || got.Decision.Effect != tt.effect ||
				got.Decision.Reason != tt.reason || got.Decision.PermitsAt(at) != tt.permitted {
				t.Fatalf("simulation=%+v err=%v", got, err)
			}
		})
	}
}

func TestSimulatorRejectsUnknownOrMultipleObjects(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, input := range []string{`{"unknown":true}`, `{} {}`} {
		if _, err := evaluateFixture([]byte(input), at); err == nil {
			t.Fatalf("malformed fixture accepted: %q", input)
		}
	}
}
