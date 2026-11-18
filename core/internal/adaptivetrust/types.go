// Package adaptivetrust contains the side-effect-free HoneyMesh Adaptive Trust
// decision contract. Its inputs must come from trusted identity, policy, and
// evidence adapters; this package does not authenticate a caller or a signal.
package adaptivetrust

import "time"

const SchemaVersion = 1

type State string

const (
	Unknown     State = "unknown"
	Provisional State = "provisional"
	Established State = "established"
	Degraded    State = "degraded"
	Quarantined State = "quarantined"
)

type Effect string

const (
	Allow    Effect = "allow"
	Verify   Effect = "verify"
	Restrict Effect = "restrict"
	Deny     Effect = "deny"
)

type Request struct {
	TenantID   string `json:"tenant_id"`
	SubjectID  string `json:"subject_id"`
	ResourceID string `json:"resource_id"`
	Action     string `json:"action"`
	SessionID  string `json:"session_id"`
}

// Identity is an adapter-verified assertion bound to one session. Verified
// must only be set after credential, issuer, and binding verification.
type Identity struct {
	SubjectID  string    `json:"subject_id"`
	SessionID  string    `json:"session_id"`
	VerifierID string    `json:"verifier_id"`
	Verified   bool      `json:"verified"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Grant is the operator-approved maximum scope. Evidence cannot add actions.
type Grant struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	SubjectID     string    `json:"subject_id"`
	ResourceID    string    `json:"resource_id"`
	Actions       []string  `json:"actions"`
	ApprovedBy    string    `json:"approved_by"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	PolicyVersion string    `json:"policy_version"`
}

// Posture is fresh evidence that an independently verified subject meets the
// policy's baseline. It cannot authorize a missing or ungranted action.
type Posture struct {
	ID         string    `json:"id"`
	SubjectID  string    `json:"subject_id"`
	VerifierID string    `json:"verifier_id"`
	Verified   bool      `json:"verified"`
	ObservedAt time.Time `json:"observed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Anomaly is independently verified risk for one exact relationship/action.
// A verified anomaly can restrict an existing grant, never widen it.
type Anomaly struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	SubjectID  string    `json:"subject_id"`
	ResourceID string    `json:"resource_id"`
	Action     string    `json:"action"`
	VerifierID string    `json:"verifier_id"`
	Verified   bool      `json:"verified"`
	ObservedAt time.Time `json:"observed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Hold is a durable local quarantine decision. It has no timer: a separate
// authorized release must remove it from storage before evaluation can allow.
type Hold struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	SubjectID  string    `json:"subject_id"`
	ResourceID string    `json:"resource_id"`
	Action     string    `json:"action"`
	PlacedBy   string    `json:"placed_by"`
	PlacedAt   time.Time `json:"placed_at"`
}

type Policy struct {
	Version        string        `json:"version"`
	RequirePosture bool          `json:"require_posture"`
	MaxLease       time.Duration `json:"-"`
}

type Input struct {
	SchemaVersion int
	Request       Request
	Identity      *Identity
	Grant         *Grant
	Posture       *Posture
	Anomaly       *Anomaly
	Hold          *Hold
	Policy        Policy
}

type Decision struct {
	SchemaVersion int        `json:"schema_version"`
	State         State      `json:"state"`
	Effect        Effect     `json:"effect"`
	Reason        string     `json:"reason"`
	GrantID       string     `json:"grant_id,omitempty"`
	EvidenceIDs   []string   `json:"evidence_ids,omitempty"`
	PolicyVersion string     `json:"policy_version"`
	EvaluatedAt   time.Time  `json:"evaluated_at"`
	LeaseUntil    *time.Time `json:"lease_until,omitempty"`
}

// PermitsAt is the only interpretation of a decision that may pass traffic.
// A stored allow cannot be reused after its bounded lease expires.
func (d Decision) PermitsAt(now time.Time) bool {
	return d.SchemaVersion == SchemaVersion && d.Effect == Allow && d.LeaseUntil != nil &&
		!now.IsZero() && !now.Before(d.EvaluatedAt) && now.Before(*d.LeaseUntil)
}
