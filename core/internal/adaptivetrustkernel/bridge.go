// Package adaptivetrustkernel is an opt-in, source-level bridge from a local
// Adaptive Trust network quarantine to the existing exact-IP UEE writer.
// It is not wired into Core startup or an operator API.
package adaptivetrustkernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"

	"honeymesh/internal/adaptivetrust"
	"honeymesh/internal/banownership"
	"honeymesh/internal/enforcementengine"
)

// Only a dedicated source address may be quarantined at XDP. An application
// route, user, or service relationship cannot be converted into an IP block.
const (
	NetworkResource  = "host-network"
	QuarantineAction = "network.quarantine"
	maxKernelLease   = 30 * time.Second
)

// SourceBinding must come from a trusted local verifier, not request JSON.
// Exclusive means no unrelated tenant or workload shares this source address.
type SourceBinding struct {
	TenantID, SubjectID string
	IP                  string
	VerifierID          string
	EvidenceID          string
	ApprovedBy          string
	Verified, Exclusive bool
	ExpiresAt           time.Time
}

type Store interface {
	Preview(context.Context, adaptivetrust.Input, time.Time) (adaptivetrust.Decision, error)
	ActiveHold(context.Context, adaptivetrust.Request) (*adaptivetrust.Hold, error)
}

type Engine interface {
	Put(enforcementengine.Grant, time.Time) (banownership.Decision, error)
	Inspect(string, time.Time) (enforcementengine.SnapshotEntry, []enforcementengine.Grant, error)
}

type Result struct {
	IP            string
	OwnerID       string
	LeaseUntil    time.Time
	KernelApplied bool
}

// ApplyQuarantine applies only a locally held, separately approved exact-IP
// network quarantine. Even a valid HAT deny/restrict for an API route cannot
// reach the UEE. The result reflects confirmed UEE state, including TEST mode.
func ApplyQuarantine(ctx context.Context, store Store, engine Engine, request adaptivetrust.Request,
	binding SourceBinding, policy adaptivetrust.Policy, now time.Time) (Result, error) {
	if store == nil || engine == nil || now.IsZero() || request.ResourceID != NetworkResource ||
		request.Action != QuarantineAction || request.TenantID == "" || request.SubjectID == "" ||
		request.SessionID == "" || !binding.Verified || !binding.Exclusive ||
		binding.TenantID != request.TenantID || binding.SubjectID != request.SubjectID ||
		binding.VerifierID == "" || binding.EvidenceID == "" || binding.ApprovedBy == "" ||
		!binding.ExpiresAt.After(now) || binding.ExpiresAt.Sub(now) > 5*time.Minute {
		return Result{}, errors.New("unverified or nonexclusive network quarantine scope")
	}
	ip, err := netip.ParseAddr(binding.IP)
	if err != nil || !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() {
		return Result{}, errors.New("invalid exact source address")
	}
	decision, err := store.Preview(ctx, adaptivetrust.Input{
		SchemaVersion: adaptivetrust.SchemaVersion, Request: request, Policy: policy,
	}, now)
	if err != nil || decision.SchemaVersion != adaptivetrust.SchemaVersion ||
		decision.State != adaptivetrust.Quarantined || decision.Effect != adaptivetrust.Deny ||
		decision.Reason != "quarantine_hold" || decision.PolicyVersion != policy.Version {
		return Result{}, errors.New("local network quarantine decision unavailable")
	}
	hold, err := store.ActiveHold(ctx, request)
	if err != nil || hold == nil || hold.ID == "" || hold.PlacedBy == "" ||
		hold.PlacedBy == binding.ApprovedBy || hold.PlacedBy == binding.VerifierID {
		return Result{}, errors.New("independent local quarantine approval unavailable")
	}
	expires := now.Add(maxKernelLease)
	if binding.ExpiresAt.Before(expires) {
		expires = binding.ExpiresAt
	}
	if !expires.After(now) {
		return Result{}, errors.New("network quarantine lease unavailable")
	}
	digest := sha256.Sum256([]byte(request.TenantID + "\x00" + request.SubjectID + "\x00" + hold.ID))
	ownerID := "hat-" + hex.EncodeToString(digest[:])
	ip = ip.Unmap()
	grant := enforcementengine.Grant{
		IP: ip.String(), Owner: banownership.Owner{Kind: banownership.Local, ID: ownerID},
		ExpiresAt: expires, Reason: "local adaptive trust network quarantine",
		PolicyVersion: policy.Version,
	}
	if _, err := engine.Put(grant, now); err != nil {
		return Result{}, err
	}
	view, grants, err := engine.Inspect(ip.String(), now)
	if err != nil {
		return Result{}, err
	}
	result := Result{IP: ip.String(), OwnerID: ownerID, LeaseUntil: expires}
	for _, active := range grants {
		if active.Owner == grant.Owner && active.ExpiresAt.Equal(expires) {
			result.KernelApplied = view.KernelApplied
			return result, nil
		}
	}
	return Result{}, errors.New("network quarantine owner missing after reconciliation")
}
