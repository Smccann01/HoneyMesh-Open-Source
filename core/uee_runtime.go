package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"honeymesh/internal/banownership"
	"honeymesh/internal/enforcementengine"
)

const runtimePolicyVersion = "rc4-runtime-v1"

var liveUEE *enforcementengine.Engine

// startUEE runs before any workers or dashboard handlers can write a rule.
// The one-time import is safe only after all runtime producers have migrated.
func startUEE() error {
	if db == nil {
		return errors.New("enforcement database unavailable")
	}
	engine, err := enforcementengine.NewWithEnforcement(db, ueeKernelAdapter{}, false)
	if err != nil {
		return err
	}
	count, err := engine.ImportLegacyBans(time.Now())
	if err != nil {
		return fmt.Errorf("import legacy bans: %w", err)
	}
	if err := engine.ReconcileAll(time.Now()); err != nil {
		return fmt.Errorf("reconcile TEST startup: %w", err)
	}
	liveUEE = engine
	log.Printf("[UEE] Imported %d legacy local bans; startup mode TEST", count)
	return nil
}

func localOwner(category string) banownership.Owner {
	category = strings.ToLower(strings.TrimSpace(category))
	if category == "" {
		category = "detection"
	}
	if len(category) > 100 {
		category = category[:100]
	}
	return banownership.Owner{Kind: banownership.Local, ID: category}
}

func ueeLocalGrant(ip, category, reason string, expires time.Time) (banownership.Decision, error) {
	if liveUEE == nil {
		return banownership.Decision{}, errors.New("enforcement engine not initialized")
	}
	if len(reason) > 300 {
		reason = reason[:300]
	}
	return liveUEE.Put(enforcementengine.Grant{
		IP: ip, Owner: localOwner(category), ExpiresAt: expires,
		Reason: reason, PolicyVersion: runtimePolicyVersion,
	}, time.Now())
}

func ueeRemoteGrant(ip, category, originID, reason string, peers []string, expires time.Time) (banownership.Decision, error) {
	if liveUEE == nil {
		return banownership.Decision{}, errors.New("enforcement engine not initialized")
	}
	kind := banownership.Mesh
	if category == "NETTOOLS_EXCHANGE" {
		kind = banownership.Exchange
	}
	if originID == "" {
		origins := append([]string(nil), peers...)
		sort.Strings(origins)
		originID = strings.Join(origins, ",")
	}
	if originID == "" {
		return banownership.Decision{}, errors.New("remote grant lacks origin identity")
	}
	digest := sha256.Sum256([]byte(category + ":" + originID))
	owner := banownership.Owner{Kind: kind, ID: hex.EncodeToString(digest[:])}
	if len(reason) > 300 {
		reason = reason[:300]
	}
	return liveUEE.Put(enforcementengine.Grant{
		IP: ip, Owner: owner, ExpiresAt: expires,
		Reason: reason, PolicyVersion: runtimePolicyVersion,
	}, time.Now())
}

func ueeReleaseLocal(ip, actor string, now time.Time) error {
	if liveUEE == nil {
		return errors.New("enforcement engine not initialized")
	}
	// The override prevents a still-valid peer grant from immediately undoing
	// the operator's emergency release. Local justifications are then removed.
	if _, err := liveUEE.SetOverride(ip, actor, "operator release", time.Minute, now); err != nil {
		return err
	}
	grants, err := liveUEE.Grants(ip, now)
	if err != nil {
		return err
	}
	for _, grant := range grants {
		if grant.Owner.Kind == banownership.Local {
			if _, err := liveUEE.Remove(ip, grant.Owner, now); err != nil {
				return err
			}
		}
	}
	if _, err := db.Exec(`DELETE FROM bans WHERE ip=?`, ip); err != nil {
		return fmt.Errorf("remove legacy ban row: %w", err)
	}
	return nil
}

// Caller holds banMutex. This map is a compatibility view for legacy readers;
// the grant store and kernel-confirmed snapshot remain authoritative.
func refreshLegacyBanView(now time.Time) error {
	if liveUEE == nil {
		return errors.New("enforcement engine not initialized")
	}
	entries, err := liveUEE.Snapshot(now)
	if err != nil {
		return err
	}
	next := make(map[string]time.Time, len(entries))
	for _, entry := range entries {
		if entry.KernelApplied && entry.ExpiresAt.After(now) {
			next[entry.IP] = entry.ExpiresAt
		}
	}
	banExpirations = next
	banMetaMu.Lock()
	for ip := range banMeta {
		if _, ok := next[ip]; !ok {
			delete(banMeta, ip)
		}
	}
	banMetaMu.Unlock()
	return nil
}

// apiEnforcementGrants exposes desired ownership beside confirmed kernel
// state to authenticated operators. A pending grant is never labeled blocked.
func apiEnforcementGrants(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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
	now := time.Now()
	entries, err := liveUEE.Snapshot(now)
	if err != nil {
		http.Error(w, "enforcement snapshot unavailable", http.StatusInternalServerError)
		return
	}
	type item struct {
		State  enforcementengine.SnapshotEntry `json:"state"`
		Grants []enforcementengine.Grant       `json:"grants"`
	}
	out := make([]item, 0, len(entries))
	for _, entry := range entries {
		grants, err := liveUEE.Grants(entry.IP, now)
		if err != nil {
			http.Error(w, "enforcement grants unavailable", http.StatusInternalServerError)
			return
		}
		out = append(out, item{State: entry, Grants: grants})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, out)
}
