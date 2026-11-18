package adaptivetrust

import (
	"testing"
	"time"
)

func pilotInput(now time.Time) Input {
	return Input{
		SchemaVersion: SchemaVersion,
		Request:       Request{TenantID: "tenant-a", SubjectID: "web-a", ResourceID: "api-orders", Action: "orders.read", SessionID: "session-1"},
		Identity:      &Identity{SubjectID: "web-a", SessionID: "session-1", VerifierID: "pilot-ca", Verified: true, ExpiresAt: now.Add(time.Minute)},
		Grant: &Grant{ID: "grant-1", TenantID: "tenant-a", SubjectID: "web-a", ResourceID: "api-orders",
			Actions: []string{"orders.read"}, ApprovedBy: "operator-1", IssuedAt: now.Add(-time.Minute),
			ExpiresAt: now.Add(time.Hour), PolicyVersion: "pilot-1"},
		Posture: &Posture{ID: "posture-1", SubjectID: "web-a", VerifierID: "posture-checker", Verified: true,
			ObservedAt: now.Add(-time.Second), ExpiresAt: now.Add(45 * time.Second)},
		Policy: Policy{Version: "pilot-1", RequirePosture: true, MaxLease: 30 * time.Second},
	}
}

func TestEvaluatorNeverWidensExplicitGrant(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tests := []struct {
		name   string
		change func(*Input)
		want   Effect
		reason string
	}{
		{"valid read", func(*Input) {}, Allow, "explicit_grant_verified"},
		{"missing grant", func(i *Input) { i.Grant = nil }, Deny, "no_active_grant"},
		{"admin not granted", func(i *Input) { i.Request.Action = "admin.write" }, Deny, "no_active_grant"},
		{"other tenant", func(i *Input) { i.Request.TenantID = "tenant-b" }, Deny, "no_active_grant"},
		{"other resource", func(i *Input) { i.Request.ResourceID = "api-management" }, Deny, "no_active_grant"},
		{"expired grant", func(i *Input) { i.Grant.ExpiresAt = now }, Deny, "no_active_grant"},
		{"unapproved grant", func(i *Input) { i.Grant.ApprovedBy = "" }, Deny, "no_active_grant"},
		{"wrong policy version", func(i *Input) { i.Grant.PolicyVersion = "older" }, Deny, "no_active_grant"},
		{"wrong session", func(i *Input) { i.Identity.SessionID = "session-2" }, Verify, "identity_unverified"},
		{"expired identity", func(i *Input) { i.Identity.ExpiresAt = now }, Verify, "identity_unverified"},
		{"unverified identity", func(i *Input) { i.Identity.Verified = false }, Verify, "identity_unverified"},
		{"stale posture", func(i *Input) { i.Posture.ExpiresAt = now }, Verify, "posture_unverified"},
		{"unverified posture", func(i *Input) { i.Posture.Verified = false }, Verify, "posture_unverified"},
		{"unknown schema", func(i *Input) { i.SchemaVersion++ }, Deny, "invalid_request"},
		{"invalid lease", func(i *Input) { i.Policy.MaxLease = 0 }, Deny, "invalid_policy"},
		{"verified anomaly", func(i *Input) {
			i.Anomaly = &Anomaly{ID: "anomaly-1", TenantID: "tenant-a", SubjectID: "web-a", ResourceID: "api-orders",
				Action: "orders.read", VerifierID: "local-detector", Verified: true, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}
		}, Restrict, "verified_anomaly"},
		{"quarantine hold", func(i *Input) {
			i.Hold = &Hold{ID: "hold-1", TenantID: "tenant-a", SubjectID: "web-a", ResourceID: "api-orders",
				Action: "orders.read", PlacedBy: "operator-1", PlacedAt: now.Add(-time.Minute)}
		}, Deny, "quarantine_hold"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := pilotInput(now)
			tt.change(&in)
			got := Evaluate(in, now)
			if got.Effect != tt.want || got.Reason != tt.reason || got.PermitsAt(now) != (tt.want == Allow) {
				t.Fatalf("decision=%+v; want effect=%s reason=%s", got, tt.want, tt.reason)
			}
		})
	}
}

func TestLeaseEndsAtEarliestVerifiedBoundary(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	in := pilotInput(now)
	in.Identity.ExpiresAt = now.Add(12 * time.Second)
	in.Posture.ExpiresAt = now.Add(20 * time.Second)
	got := Evaluate(in, now)
	if !got.PermitsAt(now) || !got.LeaseUntil.Equal(now.Add(12*time.Second)) {
		t.Fatalf("lease exceeded identity expiry: %+v", got)
	}
	if got.PermitsAt(now.Add(12 * time.Second)) {
		t.Fatal("expired allow lease remained usable")
	}
	in.Identity.ExpiresAt = now.Add(time.Minute)
	in.Posture.ExpiresAt = now.Add(7 * time.Second)
	got = Evaluate(in, now)
	if !got.LeaseUntil.Equal(now.Add(7 * time.Second)) {
		t.Fatalf("lease exceeded posture expiry: %+v", got)
	}
}

func TestQuarantineDoesNotExpireWithEvidence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	in := pilotInput(now)
	in.Hold = &Hold{ID: "hold-1", TenantID: "tenant-a", SubjectID: "web-a", ResourceID: "api-orders",
		Action: "orders.read", PlacedBy: "operator-1", PlacedAt: now.Add(-time.Minute)}
	in.Identity.ExpiresAt = now.Add(24 * time.Hour)
	in.Grant.ExpiresAt = now.Add(24 * time.Hour)
	in.Posture.ExpiresAt = now.Add(24 * time.Hour)
	if got := Evaluate(in, now.Add(time.Hour)); got.State != Quarantined || got.PermitsAt(now.Add(time.Hour)) {
		t.Fatalf("timer cleared quarantine: %+v", got)
	}
}

func FuzzNoGrantNeverPermits(f *testing.F) {
	f.Add("orders.read", "tenant-a")
	f.Add("admin.write", "tenant-b")
	f.Fuzz(func(t *testing.T, action, tenant string) {
		now := time.Unix(1_800_000_000, 0)
		in := pilotInput(now)
		in.Request.Action, in.Request.TenantID, in.Grant = action, tenant, nil
		if got := Evaluate(in, now); got.PermitsAt(now) {
			t.Fatalf("missing grant permitted action %q for %q", action, tenant)
		}
	})
}
