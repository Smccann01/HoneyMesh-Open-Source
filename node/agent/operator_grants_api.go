package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"honeymesh/internal/banownership"
	"honeymesh/internal/enforcementengine"
)

const operatorGrantPrefix = "firewall-console:"

func operatorAPIAuth(w http.ResponseWriter, r *http.Request) bool {
	actual, expected := []byte(r.Header.Get("X-Honey-Token")), []byte(config.AdminToken)
	if len(expected) == 0 || len(actual) != len(expected) || subtle.ConstantTimeCompare(actual, expected) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func decodeOperatorRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	return true
}

func operatorIP(raw string) (string, bool) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() {
		return "", false
	}
	ip = ip.Unmap()
	return ip.String(), true
}

func operatorSource(raw string) (string, bool) {
	source, valid := operatorIP(raw)
	if !valid {
		return "", false
	}
	if isWhitelisted(source) {
		return "", false
	}
	if bindIP := net.ParseIP(config.BindIP); bindIP != nil && bindIP.Equal(net.ParseIP(source)) {
		return "", false
	}
	for _, local := range getAvailableIPs() {
		if net.ParseIP(local).Equal(net.ParseIP(source)) {
			return "", false
		}
	}
	return source, true
}

func operatorGrantOwner(id string) (banownership.Owner, bool) {
	if !strings.HasPrefix(id, operatorGrantPrefix) || len(id) != len(operatorGrantPrefix)+32 {
		return banownership.Owner{}, false
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, operatorGrantPrefix)); err != nil {
		return banownership.Owner{}, false
	}
	return banownership.Owner{Kind: banownership.Local, ID: id}, true
}

func operatorGrantExists(ip string, owner banownership.Owner, now time.Time) (bool, error) {
	grants, err := liveUEE.Grants(ip, now)
	if err != nil {
		return false, err
	}
	for _, grant := range grants {
		if grant.Owner == owner {
			return true, nil
		}
	}
	return false, nil
}

// This authenticated contract lets the console reject older agents before it
// offers scoped writes. The installed RC4 binary does not expose version 1.
func apiEnforcementContract(w http.ResponseWriter, r *http.Request) {
	if !operatorAPIAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{
		"contract_version": 1,
		"agent_version":    Version,
		"mode":             Mode().String(),
		"uee_ready":        liveUEE != nil,
		"xdp_attached":     hasAttachedIface(),
		"operator_grants":  true,
		"scoped_release":   true,
		"min_ttl_seconds":  30,
		"max_ttl_seconds":  86400,
	})
}

// A new operator grant gets a random, independent UEE owner. Existing local,
// app, mesh, and Exchange owners are never overwritten.
func apiOperatorGrants(w http.ResponseWriter, r *http.Request) {
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
		Reason     string `json:"reason"`
	}
	if !decodeOperatorRequest(w, r, &req) {
		return
	}
	ip, valid := operatorSource(req.IP)
	if !valid || req.TTLSeconds < 30 || req.TTLSeconds > 86400 || len(req.Reason) > 120 || strings.ContainsAny(req.Reason, "\r\n\x00") {
		http.Error(w, "invalid or protected source, duration, or reason", http.StatusBadRequest)
		return
	}
	if Mode() == ModeTest {
		http.Error(w, "operator enforcement unavailable in TEST", http.StatusConflict)
		return
	}
	if req.Reason == "" {
		req.Reason = "firewall console operator"
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		http.Error(w, "grant identity unavailable", http.StatusInternalServerError)
		return
	}
	owner := banownership.Owner{Kind: banownership.Local, ID: operatorGrantPrefix + hex.EncodeToString(idBytes)}
	now := time.Now()
	expires := now.Add(time.Duration(req.TTLSeconds) * time.Second)
	banMutex.Lock()
	if Mode() == ModeTest {
		banMutex.Unlock()
		http.Error(w, "operator enforcement unavailable in TEST", http.StatusConflict)
		return
	}
	_, applyErr := liveUEE.Put(enforcementengine.Grant{IP: ip, Owner: owner, ExpiresAt: expires,
		Reason: req.Reason, PolicyVersion: runtimePolicyVersion}, now)
	stored, lookupErr := operatorGrantExists(ip, owner, now)
	var viewErr error
	if stored && lookupErr == nil {
		viewErr = refreshLegacyBanView(time.Now())
	}
	banMutex.Unlock()
	if lookupErr != nil || !stored {
		http.Error(w, "grant could not be stored", http.StatusInternalServerError)
		return
	}
	broadcastBans()
	w.Header().Set("Cache-Control", "no-store")
	if applyErr != nil || viewErr != nil {
		w.WriteHeader(http.StatusAccepted)
	}
	writeJSON(w, map[string]any{"grant_id": owner.ID, "ip": ip, "expires_at": expires.Format(time.RFC3339Nano),
		"kernel_reconciled": applyErr == nil && viewErr == nil, "reconciliation_pending": applyErr != nil || viewErr != nil})
}

// Release removes only the exact operator owner. It never sets a broad allow
// override or touches other local, app, mesh, or Exchange justifications.
func apiOperatorGrantRelease(w http.ResponseWriter, r *http.Request) {
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
		IP      string `json:"ip"`
		GrantID string `json:"grant_id"`
	}
	if !decodeOperatorRequest(w, r, &req) {
		return
	}
	ip, valid := operatorIP(req.IP)
	owner, validOwner := operatorGrantOwner(req.GrantID)
	if !valid || !validOwner {
		http.Error(w, "invalid operator grant", http.StatusBadRequest)
		return
	}
	banMutex.Lock()
	exists, lookupErr := operatorGrantExists(ip, owner, time.Now())
	if lookupErr != nil {
		banMutex.Unlock()
		http.Error(w, "grant lookup failed", http.StatusInternalServerError)
		return
	}
	if !exists {
		banMutex.Unlock()
		http.Error(w, "operator grant not found", http.StatusNotFound)
		return
	}
	_, reconcileErr := liveUEE.Remove(ip, owner, time.Now())
	remaining, remainingErr := operatorGrantExists(ip, owner, time.Now())
	if remainingErr != nil || remaining {
		banMutex.Unlock()
		http.Error(w, "operator grant removal could not be confirmed", http.StatusInternalServerError)
		return
	}
	viewErr := refreshLegacyBanView(time.Now())
	banMutex.Unlock()
	broadcastBans()
	w.Header().Set("Cache-Control", "no-store")
	if reconcileErr != nil || viewErr != nil {
		w.WriteHeader(http.StatusAccepted)
	}
	writeJSON(w, map[string]any{"grant_id": owner.ID, "ip": ip, "grant_removed": true,
		"kernel_reconciled":      reconcileErr == nil && viewErr == nil,
		"reconciliation_pending": reconcileErr != nil || viewErr != nil})
}
