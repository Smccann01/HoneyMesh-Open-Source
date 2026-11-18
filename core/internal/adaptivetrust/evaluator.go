package adaptivetrust

import (
	"strings"
	"time"
)

const maximumLease = 5 * time.Minute

// Evaluate returns an observe-only decision. It has no storage, transport, or
// enforcement side effects. All timestamps use the caller-supplied clock.
func Evaluate(in Input, now time.Time) Decision {
	d := Decision{SchemaVersion: SchemaVersion, State: Unknown, Effect: Deny,
		Reason: "invalid_request", PolicyVersion: in.Policy.Version, EvaluatedAt: now.UTC()}
	r := in.Request
	if in.SchemaVersion != SchemaVersion || now.IsZero() || blank(r.TenantID) || blank(r.SubjectID) || blank(r.ResourceID) || blank(r.Action) || blank(r.SessionID) {
		return d
	}
	if blank(in.Policy.Version) || in.Policy.MaxLease <= 0 || in.Policy.MaxLease > maximumLease {
		d.Reason = "invalid_policy"
		return d
	}
	if in.Hold != nil {
		h := in.Hold
		if blank(h.ID) || blank(h.PlacedBy) || h.PlacedAt.IsZero() || h.PlacedAt.After(now) ||
			h.TenantID != r.TenantID || h.SubjectID != r.SubjectID || h.ResourceID != r.ResourceID || h.Action != r.Action {
			d.Reason = "invalid_hold"
			return d
		}
		d.State, d.Reason = Quarantined, "quarantine_hold"
		return d
	}
	g := in.Grant
	if g == nil || blank(g.ID) || blank(g.ApprovedBy) || g.TenantID != r.TenantID ||
		g.SubjectID != r.SubjectID || g.ResourceID != r.ResourceID || g.PolicyVersion != in.Policy.Version ||
		g.IssuedAt.IsZero() || g.IssuedAt.After(now) || !g.ExpiresAt.After(now) || !contains(g.Actions, r.Action) {
		d.Reason = "no_active_grant"
		return d
	}
	d.GrantID = g.ID
	d.State = Provisional
	i := in.Identity
	if i == nil || !i.Verified || blank(i.VerifierID) || i.SubjectID != r.SubjectID ||
		i.SessionID != r.SessionID || !i.ExpiresAt.After(now) {
		d.Effect, d.Reason = Verify, "identity_unverified"
		return d
	}
	if a := in.Anomaly; a != nil && a.Verified {
		if blank(a.ID) || blank(a.VerifierID) || a.TenantID != r.TenantID || a.SubjectID != r.SubjectID ||
			a.ResourceID != r.ResourceID || a.Action != r.Action || a.ObservedAt.IsZero() || a.ObservedAt.After(now) {
			d.Reason = "invalid_anomaly"
			return d
		}
		if a.ExpiresAt.After(now) {
			d.State, d.Effect, d.Reason = Degraded, Restrict, "verified_anomaly"
			d.EvidenceIDs = []string{a.ID}
			return d
		}
	}
	p := in.Posture
	if in.Policy.RequirePosture {
		if p == nil || !p.Verified || blank(p.ID) || blank(p.VerifierID) || p.SubjectID != r.SubjectID ||
			p.ObservedAt.IsZero() || p.ObservedAt.After(now) || !p.ExpiresAt.After(now) {
			d.Effect, d.Reason = Verify, "posture_unverified"
			return d
		}
		d.EvidenceIDs = []string{p.ID}
	}
	lease := now.Add(in.Policy.MaxLease)
	for _, limit := range []time.Time{g.ExpiresAt, i.ExpiresAt} {
		if limit.Before(lease) {
			lease = limit
		}
	}
	if in.Policy.RequirePosture && p.ExpiresAt.Before(lease) {
		lease = p.ExpiresAt
	}
	if !lease.After(now) {
		d.Effect, d.Reason = Verify, "lease_unavailable"
		return d
	}
	d.State, d.Effect, d.Reason, d.LeaseUntil = Established, Allow, "explicit_grant_verified", lease.UTC()
	return d
}

func blank(s string) bool { return strings.TrimSpace(s) == "" }

func contains(actions []string, action string) bool {
	for _, allowed := range actions {
		if allowed == action {
			return true
		}
	}
	return false
}
