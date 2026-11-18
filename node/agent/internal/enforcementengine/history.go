package enforcementengine

import (
	"encoding/json"
	"errors"
	"time"
)

// ReconciliationEvent is a persisted UEE action, not a packet-level trace.
type ReconciliationEvent struct {
	ID                int64      `json:"id"`
	IP                string     `json:"ip"`
	At                time.Time  `json:"at"`
	PreviousActive    bool       `json:"previous_active"`
	NextActive        bool       `json:"next_active"`
	PreviousExpiresAt *time.Time `json:"previous_expires_at"`
	NextExpiresAt     *time.Time `json:"next_expires_at"`
	OwnerIDs          []string   `json:"owner_ids"`
	PolicyVersions    []string   `json:"policy_versions"`
	Operation         string     `json:"operation"`
	Result            string     `json:"result"`
	ReconcileStatus   string     `json:"reconcile_status"`
	KernelError       string     `json:"kernel_error,omitempty"`
	OverrideActive    bool       `json:"override_active"`
}

// History returns the newest bounded UEE reconciliation records for one exact IP.
func (e *Engine) History(rawIP string, limit int) ([]ReconciliationEvent, error) {
	ip, err := canonicalIP(rawIP)
	if err != nil || limit < 1 || limit > 100 {
		return nil, errors.New("invalid history source or limit")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	rows, err := e.db.Query(`SELECT id,at_ns,previous_active,next_active,previous_expires_ns,next_expires_ns,
		owner_ids_json,policy_versions_json,operation,result,reconcile_status,kernel_error,override_active
		FROM enforcement_decision_audit WHERE ip=? ORDER BY id DESC LIMIT ?`, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []ReconciliationEvent{}
	for rows.Next() {
		var event ReconciliationEvent
		var at, previousExpiry, nextExpiry int64
		var previousActive, nextActive, overrideActive int
		var ownersJSON, versionsJSON string
		if err := rows.Scan(&event.ID, &at, &previousActive, &nextActive, &previousExpiry, &nextExpiry,
			&ownersJSON, &versionsJSON, &event.Operation, &event.Result, &event.ReconcileStatus,
			&event.KernelError, &overrideActive); err != nil {
			return nil, err
		}
		event.IP, event.At = ip, time.Unix(0, at)
		event.PreviousActive, event.NextActive, event.OverrideActive = previousActive != 0, nextActive != 0, overrideActive != 0
		if previousExpiry > 0 {
			value := time.Unix(0, previousExpiry)
			event.PreviousExpiresAt = &value
		}
		if nextExpiry > 0 {
			value := time.Unix(0, nextExpiry)
			event.NextExpiresAt = &value
		}
		if err := json.Unmarshal([]byte(ownersJSON), &event.OwnerIDs); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(versionsJSON), &event.PolicyVersions); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}
