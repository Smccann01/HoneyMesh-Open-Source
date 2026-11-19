package main

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"honeymesh/internal/adaptivetrust"
	"honeymesh/internal/adaptivetruststore"
)

const hatPreviewPolicyLease = 30 * time.Second

var liveHATStore *adaptivetruststore.Store

// HAT starts with a local observation surface. A bad HAT store leaves this
// feature unavailable instead of altering existing Core enforcement.
func startHATReadOnly() {
	liveHATStore = nil
	if db == nil {
		log.Print("[HAT] Local preview unavailable: database not initialized")
		return
	}
	store, err := adaptivetruststore.New(db)
	if err != nil {
		log.Printf("[HAT] Local preview unavailable: %v", err)
		return
	}
	liveHATStore = store
	log.Print("[HAT] Adaptive Trust 2.0 local preview ready; enforcement disabled")
}

func validHATID(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '.' || char == '_' || char == ':' || char == '-' || char == '/' {
			continue
		}
		return false
	}
	return true
}

type hatRelationshipInput struct {
	TenantID      string `json:"tenant_id"`
	SubjectID     string `json:"subject_id"`
	ResourceID    string `json:"resource_id"`
	Action        string `json:"action"`
	PolicyVersion string `json:"policy_version"`
}

func (in hatRelationshipInput) valid() bool {
	return validHATID(in.TenantID, 128) && validHATID(in.SubjectID, 128) &&
		validHATID(in.ResourceID, 128) && validHATID(in.Action, 128) &&
		validHATID(in.PolicyVersion, 64)
}

func (in hatRelationshipInput) request() adaptivetrust.Request {
	return adaptivetrust.Request{TenantID: in.TenantID, SubjectID: in.SubjectID,
		ResourceID: in.ResourceID, Action: in.Action, SessionID: "operator-preview"}
}

func hatAPIReady(w http.ResponseWriter, r *http.Request, method string) bool {
	if !operatorAPIAuth(w, r) {
		return false
	}
	if r.Method != method {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if method == http.MethodPost && !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	if liveHATStore == nil {
		http.Error(w, "adaptive trust preview unavailable", http.StatusServiceUnavailable)
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	return true
}

func apiAdaptiveTrustStatus(w http.ResponseWriter, r *http.Request) {
	if !operatorAPIAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{
		"version_line": "HoneyMesh 2.0 development", "mode": "observe_only",
		"store_available": liveHATStore != nil, "identity_adapter": "unavailable",
		"application_enforcement": "disabled", "kernel_quarantine": "disabled",
		"scope": "Local grant and hold preview only; no live access or firewall decision is changed.",
	})
}

func apiAdaptiveTrustRelationship(w http.ResponseWriter, r *http.Request) {
	if !hatAPIReady(w, r, http.MethodGet) {
		return
	}
	query := r.URL.Query()
	in := hatRelationshipInput{TenantID: query.Get("tenant_id"), SubjectID: query.Get("subject_id"),
		ResourceID: query.Get("resource_id"), Action: query.Get("action"), PolicyVersion: query.Get("policy_version")}
	if !in.valid() {
		http.Error(w, "invalid exact relationship", http.StatusBadRequest)
		return
	}
	limit := 10
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 25 {
			http.Error(w, "invalid history limit", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	now := time.Now().UTC()
	request := in.request()
	grant, err := liveHATStore.ActiveGrant(r.Context(), request, in.PolicyVersion, now)
	if err != nil {
		http.Error(w, "adaptive trust grant unavailable", http.StatusInternalServerError)
		return
	}
	hold, err := liveHATStore.ActiveHold(r.Context(), request)
	if err != nil {
		http.Error(w, "adaptive trust hold unavailable", http.StatusInternalServerError)
		return
	}
	history, err := liveHATStore.RecentDecisions(r.Context(), request, limit)
	if err != nil {
		http.Error(w, "adaptive trust history unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"relationship": in, "grant": grant, "hold": hold,
		"history": history, "history_limit": limit, "sampled_at": now,
		"enforcement": "disabled", "identity_adapter": "unavailable"})
}

func apiAdaptiveTrustPreview(w http.ResponseWriter, r *http.Request) {
	if !hatAPIReady(w, r, http.MethodPost) {
		return
	}
	var in hatRelationshipInput
	if !decodeOperatorRequest(w, r, &in) {
		return
	}
	if !in.valid() {
		http.Error(w, "invalid exact relationship", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	decision, err := liveHATStore.Preview(r.Context(), adaptivetrust.Input{
		SchemaVersion: adaptivetrust.SchemaVersion,
		Request:       in.request(),
		Policy: adaptivetrust.Policy{Version: in.PolicyVersion,
			RequirePosture: true, MaxLease: hatPreviewPolicyLease},
	}, now)
	if err != nil || decision.Effect == adaptivetrust.Allow {
		if err == nil {
			err = errors.New("unverified operator preview returned allow")
		}
		log.Printf("[HAT] Operator preview unavailable: %v", err)
		http.Error(w, "adaptive trust preview unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"relationship": in, "decision": decision,
		"preview_only": true, "identity_adapter": "unavailable",
		"enforcement": "disabled", "note": strings.Join([]string{
			"No workload identity or posture was asserted by this browser request.",
			"This preview writes a local decision audit but cannot authorize access or change a firewall rule.",
		}, " ")})
}
