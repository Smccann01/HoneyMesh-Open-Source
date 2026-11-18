package enforcementengine

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"honeymesh/internal/banownership"
)

// Inspect reads one IP's current owners and last confirmed kernel state under
// one engine lock. It does not infer packet-level history or other policy paths.
func (e *Engine) Inspect(rawIP string, now time.Time) (SnapshotEntry, []Grant, error) {
	ip, err := canonicalIP(rawIP)
	if err != nil {
		return SnapshotEntry{}, nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	state := SnapshotEntry{IP: ip}
	grants := []Grant{}
	rows, err := e.db.Query(`SELECT owner_kind,owner_id,expires_at_ns,reason,policy_version,evidence_refs_json
		FROM enforcement_grants WHERE ip=? AND expires_at_ns>? ORDER BY owner_kind,owner_id`, ip, now.UnixNano())
	if err != nil {
		return state, nil, err
	}
	for rows.Next() {
		var kind, id, reason, version, refsJSON string
		var expires int64
		if err := rows.Scan(&kind, &id, &expires, &reason, &version, &refsJSON); err != nil {
			rows.Close()
			return state, nil, err
		}
		var refs []string
		if err := json.Unmarshal([]byte(refsJSON), &refs); err != nil {
			rows.Close()
			return state, nil, err
		}
		grant := Grant{IP: ip, Owner: banownership.Owner{Kind: banownership.Kind(kind), ID: id},
			ExpiresAt: time.Unix(0, expires), Reason: reason, PolicyVersion: version, EvidenceRefs: refs}
		grants = append(grants, grant)
		if grant.ExpiresAt.After(state.ExpiresAt) {
			state.ExpiresAt = grant.ExpiresAt
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return state, nil, err
	}
	rows.Close()
	state.Owners = len(grants)
	var applied int
	var overrideExpiry int64
	err = e.db.QueryRow(`SELECT s.kernel_applied,s.last_error,COALESCE(o.expires_at_ns,0)
		FROM enforcement_ip_state s LEFT JOIN enforcement_overrides o ON o.ip=s.ip AND o.expires_at_ns>?
		WHERE s.ip=?`, now.UnixNano(), ip).Scan(&applied, &state.LastError, &overrideExpiry)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return state, nil, err
	}
	state.KernelApplied = applied != 0
	if overrideExpiry > 0 {
		state.OverrideExpiresAt = time.Unix(0, overrideExpiry)
	}
	return state, grants, nil
}
