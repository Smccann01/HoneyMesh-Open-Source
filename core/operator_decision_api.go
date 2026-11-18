package main

import (
	"net/http"
	"strconv"
	"time"
)

type operatorGrantView struct {
	OwnerKind     string    `json:"owner_kind"`
	OwnerID       string    `json:"owner_id"`
	Reason        string    `json:"reason"`
	PolicyVersion string    `json:"policy_version"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type operatorDecisionView struct {
	IP                      string              `json:"ip"`
	SampledAt               time.Time           `json:"sampled_at"`
	Outcome                 string              `json:"outcome"`
	Mode                    string              `json:"mode"`
	XDPAttached             bool                `json:"xdp_attached"`
	KernelApplied           bool                `json:"kernel_applied"`
	OverrideExpiresAt       *time.Time          `json:"override_expires_at"`
	LastReconciliationError string              `json:"last_reconciliation_error,omitempty"`
	Grants                  []operatorGrantView `json:"grants"`
	Scope                   string              `json:"scope"`
	ObservationLimit        string              `json:"observation_limit"`
}

func inspectOperatorDecision(ip string, now time.Time) (operatorDecisionView, error) {
	view := operatorDecisionView{
		IP: ip, SampledAt: now, Mode: Mode().String(), XDPAttached: hasAttachedIface(),
		Grants:           []operatorGrantView{},
		Scope:            "An exact-source grant affects inbound traffic from this IP across applications and ports on attached interfaces.",
		ObservationLimit: "This UEE snapshot is not packet history, connection direction, hostile-intent evidence, or proof that other firewall paths accepted traffic.",
	}
	state, grants, err := liveUEE.Inspect(ip, now)
	if err != nil {
		return view, err
	}
	for _, grant := range grants {
		view.Grants = append(view.Grants, operatorGrantView{
			OwnerKind: string(grant.Owner.Kind), OwnerID: grant.Owner.ID,
			Reason: grant.Reason, PolicyVersion: grant.PolicyVersion, ExpiresAt: grant.ExpiresAt,
		})
	}
	view.KernelApplied = state.KernelApplied
	view.LastReconciliationError = state.LastError
	if state.OverrideExpiresAt.After(now) {
		expires := state.OverrideExpiresAt
		view.OverrideExpiresAt = &expires
	}
	switch {
	case view.KernelApplied:
		view.Outcome = "kernel_block_reported"
	case view.OverrideExpiresAt != nil:
		view.Outcome = "release_override_active"
	case len(view.Grants) > 0:
		view.Outcome = "grant_pending_or_not_applied"
	default:
		view.Outcome = "no_active_uee_grant"
	}
	return view, nil
}

func apiEnforcementDecision(w http.ResponseWriter, r *http.Request) {
	if !operatorAPIAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if liveUEE == nil {
		http.Error(w, "enforcement engine unavailable", http.StatusServiceUnavailable)
		return
	}
	ip, valid := operatorIP(r.URL.Query().Get("ip"))
	if !valid {
		http.Error(w, "invalid exact IP", http.StatusBadRequest)
		return
	}
	view, err := inspectOperatorDecision(ip, time.Now())
	if err != nil {
		http.Error(w, "enforcement decision unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, view)
}

func apiEnforcementHistory(w http.ResponseWriter, r *http.Request) {
	if !operatorAPIAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if liveUEE == nil {
		http.Error(w, "enforcement engine unavailable", http.StatusServiceUnavailable)
		return
	}
	ip, valid := operatorIP(r.URL.Query().Get("ip"))
	if !valid {
		http.Error(w, "invalid exact IP", http.StatusBadRequest)
		return
	}
	limit := 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			http.Error(w, "invalid history limit", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	events, err := liveUEE.History(ip, limit)
	if err != nil {
		http.Error(w, "enforcement history unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"ip": ip, "events": events,
		"scope": "Persisted UEE reconciliation actions only; not a packet trace or complete operator activity log."})
}

// Preview reports the current UEE state and the scope of a possible operator
// grant. It never writes a grant, changes mode, or simulates packets.
func apiEnforcementPreview(w http.ResponseWriter, r *http.Request) {
	if !operatorAPIAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if liveUEE == nil {
		http.Error(w, "enforcement engine unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		IP         string `json:"ip"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if !decodeOperatorRequest(w, r, &req) {
		return
	}
	ip, valid := operatorIP(req.IP)
	if !valid || req.TTLSeconds < 30 || req.TTLSeconds > 86400 {
		http.Error(w, "invalid exact IP or duration", http.StatusBadRequest)
		return
	}
	now := time.Now()
	decision, err := inspectOperatorDecision(ip, now)
	if err != nil {
		http.Error(w, "enforcement preview unavailable", http.StatusInternalServerError)
		return
	}
	blockers := []string{}
	if _, safe := operatorSource(ip); !safe {
		blockers = append(blockers, "protected_source")
	}
	if Mode() == ModeTest {
		blockers = append(blockers, "test_mode")
	}
	if !decision.XDPAttached {
		blockers = append(blockers, "no_attached_xdp_interface")
	}
	if decision.OverrideExpiresAt != nil {
		blockers = append(blockers, "release_override_active")
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{
		"decision": decision, "proposed_ttl_seconds": req.TTLSeconds,
		"proposed_expires_at":              now.Add(time.Duration(req.TTLSeconds) * time.Second),
		"existing_owner_count":             len(decision.Grants),
		"immediate_kernel_effect_possible": len(blockers) == 0 && !decision.KernelApplied,
		"blockers":                         blockers,
		"simulation":                       "Scope and readiness preview only. No packet replay, grant creation, or kernel change occurred.",
	})
}
