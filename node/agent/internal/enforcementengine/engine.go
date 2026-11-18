package enforcementengine

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"honeymesh/internal/banownership"
)

// Kernel callbacks must be idempotent and verify that a requested map update
// succeeded. The engine persists desired grants before touching the kernel.
type Kernel interface {
	Apply(ip string) error
	Remove(ip string) error
}

type Grant struct {
	IP            string
	Owner         banownership.Owner
	ExpiresAt     time.Time
	Reason        string
	PolicyVersion string
	EvidenceRefs  []string
}

// SnapshotEntry separates desired grants from the last confirmed kernel state.
// Operators must not describe a pending or failed apply as an active block.
type SnapshotEntry struct {
	IP                string
	ExpiresAt         time.Time
	Owners            int
	KernelApplied     bool
	LastError         string
	OverrideExpiresAt time.Time
}

type Engine struct {
	db      *sql.DB
	kernel  Kernel
	mu      sync.Mutex
	enabled bool
}

const maxActiveGrantsPerIP = 128

func kindLimit(kind banownership.Kind) int {
	switch kind {
	case banownership.Local:
		return 16
	case banownership.App:
		return 32
	case banownership.Mesh:
		return 16
	case banownership.Exchange:
		return 64
	default:
		return 0
	}
}

func New(db *sql.DB, kernel Kernel) (*Engine, error) {
	return NewWithEnforcement(db, kernel, true)
}

// NewWithEnforcement lets the runtime start in TEST with durable grants but
// no effective kernel rules. Existing New callers retain their prior default.
func NewWithEnforcement(db *sql.DB, kernel Kernel, enabled bool) (*Engine, error) {
	if db == nil || kernel == nil {
		return nil, errors.New("enforcement engine requires storage and kernel")
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS enforcement_grants (
		ip TEXT NOT NULL,
		owner_kind TEXT NOT NULL,
		owner_id TEXT NOT NULL,
		expires_at_ns INTEGER NOT NULL,
		reason TEXT NOT NULL,
		policy_version TEXT NOT NULL DEFAULT '',
		evidence_refs_json TEXT NOT NULL DEFAULT '[]',
		PRIMARY KEY (ip, owner_kind, owner_id)
	);
	CREATE INDEX IF NOT EXISTS idx_enforcement_grants_expiry ON enforcement_grants(expires_at_ns);
	CREATE TABLE IF NOT EXISTS enforcement_ip_state (
		ip TEXT PRIMARY KEY,
		kernel_applied INTEGER NOT NULL DEFAULT 0,
		effective_expires_ns INTEGER NOT NULL DEFAULT 0,
		last_error TEXT NOT NULL DEFAULT ''
	);
	CREATE TABLE IF NOT EXISTS enforcement_overrides (
		ip TEXT PRIMARY KEY,
		actor TEXT NOT NULL,
		reason TEXT NOT NULL,
		expires_at_ns INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS enforcement_override_audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		actor TEXT NOT NULL,
		reason TEXT NOT NULL,
		expires_at_ns INTEGER NOT NULL,
		action TEXT NOT NULL,
		at_ns INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS enforcement_decision_audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		at_ns INTEGER NOT NULL,
		previous_active INTEGER NOT NULL,
		next_active INTEGER NOT NULL,
		previous_expires_ns INTEGER NOT NULL,
		next_expires_ns INTEGER NOT NULL,
		owner_ids_json TEXT NOT NULL,
		policy_versions_json TEXT NOT NULL,
		operation TEXT NOT NULL,
		result TEXT NOT NULL,
		reconcile_status TEXT NOT NULL,
		kernel_error TEXT NOT NULL DEFAULT '',
		override_active INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_enforcement_decision_audit_ip_id ON enforcement_decision_audit(ip,id);
	CREATE TABLE IF NOT EXISTS enforcement_migrations (
		name TEXT PRIMARY KEY,
		completed_at_ns INTEGER NOT NULL
	);`)
	if err != nil {
		return nil, err
	}
	for _, column := range []struct{ table, name, definition string }{
		{"enforcement_grants", "policy_version", "TEXT NOT NULL DEFAULT ''"},
		{"enforcement_grants", "evidence_refs_json", "TEXT NOT NULL DEFAULT '[]'"},
		{"enforcement_ip_state", "effective_expires_ns", "INTEGER NOT NULL DEFAULT 0"},
		{"enforcement_decision_audit", "override_active", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := ensureColumn(db, column.table, column.name, column.definition); err != nil {
			return nil, err
		}
	}
	return &Engine{db: db, kernel: kernel, enabled: enabled}, nil
}

func ensureColumn(db *sql.DB, table, name, definition string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	var found bool
	for rows.Next() {
		var cid, notnull, pk int
		var columnName, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &columnName, &columnType, &notnull, &defaultValue, &pk); err != nil {
			rows.Close()
			return err
		}
		if columnName == name {
			found = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil || found {
		return err
	}
	_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + name + " " + definition)
	return err
}

func canonicalIP(raw string) (string, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.IsValid() || ip.Zone() != "" {
		return "", errors.New("invalid source IP")
	}
	return ip.Unmap().String(), nil
}

func validOwner(owner banownership.Owner) bool {
	if len(owner.ID) == 0 || len(owner.ID) > 128 {
		return false
	}
	switch owner.Kind {
	case banownership.Local, banownership.App, banownership.Mesh, banownership.Exchange:
		return true
	default:
		return false
	}
}

func validEvidenceRefs(refs []string) bool {
	if len(refs) > 8 {
		return false
	}
	for _, ref := range refs {
		if len(ref) == 0 || len(ref) > 128 {
			return false
		}
		for _, r := range ref {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == ':' || r == '_' || r == '-' || r == '.' {
				continue
			}
			return false
		}
	}
	return true
}

// Put persists one justification and reconciles the effective kernel rule.
// A failed kernel operation leaves the desired grant in storage for retry.
func (e *Engine) Put(grant Grant, now time.Time) (banownership.Decision, error) {
	ip, err := canonicalIP(grant.IP)
	if err != nil || !validOwner(grant.Owner) || !grant.ExpiresAt.After(now) || grant.ExpiresAt.Sub(now) > 24*time.Hour || len(grant.Reason) > 300 || len(grant.PolicyVersion) == 0 || len(grant.PolicyVersion) > 64 || !validEvidenceRefs([]string{grant.PolicyVersion}) || !validEvidenceRefs(grant.EvidenceRefs) {
		return banownership.Decision{}, errors.New("invalid enforcement grant")
	}
	refsJSON, err := json.Marshal(grant.EvidenceRefs)
	if err != nil {
		return banownership.Decision{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	tx, err := e.db.Begin()
	if err != nil {
		return banownership.Decision{}, err
	}
	defer tx.Rollback()
	var activeOthers int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM enforcement_grants WHERE ip=? AND expires_at_ns>? AND NOT (owner_kind=? AND owner_id=?)`,
		ip, now.UnixNano(), grant.Owner.Kind, grant.Owner.ID).Scan(&activeOthers); err != nil {
		return banownership.Decision{}, err
	}
	if activeOthers >= maxActiveGrantsPerIP {
		return banownership.Decision{}, errors.New("active enforcement grant limit reached for source IP")
	}
	var sameKindOthers int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM enforcement_grants WHERE ip=? AND owner_kind=? AND expires_at_ns>? AND owner_id<>?`,
		ip, grant.Owner.Kind, now.UnixNano(), grant.Owner.ID).Scan(&sameKindOthers); err != nil {
		return banownership.Decision{}, err
	}
	if sameKindOthers >= kindLimit(grant.Owner.Kind) {
		return banownership.Decision{}, errors.New("active enforcement grant limit reached for owner kind")
	}
	_, err = tx.Exec(`INSERT INTO enforcement_grants (ip,owner_kind,owner_id,expires_at_ns,reason,policy_version,evidence_refs_json)
		VALUES (?,?,?,?,?,?,?) ON CONFLICT(ip,owner_kind,owner_id)
		DO UPDATE SET expires_at_ns=excluded.expires_at_ns, reason=excluded.reason, policy_version=excluded.policy_version, evidence_refs_json=excluded.evidence_refs_json`,
		ip, grant.Owner.Kind, grant.Owner.ID, grant.ExpiresAt.UnixNano(), grant.Reason, grant.PolicyVersion, string(refsJSON))
	if err != nil {
		return banownership.Decision{}, err
	}
	if _, err = tx.Exec(`INSERT OR IGNORE INTO enforcement_ip_state (ip) VALUES (?)`, ip); err != nil {
		return banownership.Decision{}, err
	}
	if err = tx.Commit(); err != nil {
		return banownership.Decision{}, err
	}
	return e.reconcileLocked(ip, now)
}

// Remove drops exactly one justification. Other grants still justify the rule.
func (e *Engine) Remove(ipRaw string, owner banownership.Owner, now time.Time) (banownership.Decision, error) {
	ip, err := canonicalIP(ipRaw)
	if err != nil || !validOwner(owner) {
		return banownership.Decision{}, errors.New("invalid enforcement owner")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.db.Exec(`DELETE FROM enforcement_grants WHERE ip=? AND owner_kind=? AND owner_id=?`, ip, owner.Kind, owner.ID); err != nil {
		return banownership.Decision{}, err
	}
	if _, err := e.db.Exec(`INSERT OR IGNORE INTO enforcement_ip_state (ip) VALUES (?)`, ip); err != nil {
		return banownership.Decision{}, err
	}
	return e.reconcileLocked(ip, now)
}

// SetOverride temporarily suppresses effective enforcement for one exact
// source. Grants remain intact and are reconsidered when the override expires.
func (e *Engine) SetOverride(ipRaw, actor, reason string, ttl time.Duration, now time.Time) (banownership.Decision, error) {
	ip, err := canonicalIP(ipRaw)
	if err != nil || strings.TrimSpace(actor) == "" || len(actor) > 128 || strings.ContainsAny(actor, "\r\n") || strings.TrimSpace(reason) == "" || len(reason) > 300 || strings.ContainsAny(reason, "\r\n") || ttl < 30*time.Second || ttl > 24*time.Hour {
		return banownership.Decision{}, errors.New("invalid enforcement override")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	expires := now.Add(ttl).UnixNano()
	tx, err := e.db.Begin()
	if err != nil {
		return banownership.Decision{}, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO enforcement_overrides (ip,actor,reason,expires_at_ns) VALUES (?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET actor=excluded.actor,reason=excluded.reason,expires_at_ns=excluded.expires_at_ns`,
		ip, actor, reason, expires); err != nil {
		return banownership.Decision{}, err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO enforcement_ip_state (ip) VALUES (?)`, ip); err != nil {
		return banownership.Decision{}, err
	}
	if _, err := tx.Exec(`INSERT INTO enforcement_override_audit (ip,actor,reason,expires_at_ns,action,at_ns) VALUES (?,?,?,?,'set',?)`, ip, actor, reason, expires, now.UnixNano()); err != nil {
		return banownership.Decision{}, err
	}
	if err := tx.Commit(); err != nil {
		return banownership.Decision{}, err
	}
	return e.reconcileLocked(ip, now)
}

// ClearOverride restores ordinary grant evaluation for one source.
func (e *Engine) ClearOverride(ipRaw, actor string, now time.Time) (banownership.Decision, error) {
	ip, err := canonicalIP(ipRaw)
	if err != nil || strings.TrimSpace(actor) == "" || len(actor) > 128 || strings.ContainsAny(actor, "\r\n") {
		return banownership.Decision{}, errors.New("invalid enforcement override actor or source")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	tx, err := e.db.Begin()
	if err != nil {
		return banownership.Decision{}, err
	}
	defer tx.Rollback()
	var reason string
	var expires int64
	err = tx.QueryRow(`SELECT reason,expires_at_ns FROM enforcement_overrides WHERE ip=?`, ip).Scan(&reason, &expires)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return banownership.Decision{}, err
	}
	if _, err := tx.Exec(`DELETE FROM enforcement_overrides WHERE ip=?`, ip); err != nil {
		return banownership.Decision{}, err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO enforcement_ip_state (ip) VALUES (?)`, ip); err != nil {
		return banownership.Decision{}, err
	}
	if reason != "" {
		if _, err := tx.Exec(`INSERT INTO enforcement_override_audit (ip,actor,reason,expires_at_ns,action,at_ns) VALUES (?,?,?,?,'clear',?)`, ip, actor, reason, expires, now.UnixNano()); err != nil {
			return banownership.Decision{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return banownership.Decision{}, err
	}
	return e.reconcileLocked(ip, now)
}

// ReconcileAll is required after the BPF objects are loaded at startup. It
// also retries operations that failed after desired state was persisted.
func (e *Engine) ReconcileAll(now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reconcileAllLocked(now)
}

// RetryFailed revisits only addresses whose last kernel operation failed.
// Routine expiry ticks avoid rewriting every active map entry and audit row.
func (e *Engine) RetryFailed(now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rows, err := e.db.Query(`SELECT ip FROM enforcement_ip_state WHERE last_error<>'' ORDER BY ip`)
	if err != nil {
		return err
	}
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return err
		}
		ips = append(ips, ip)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var failures []error
	for _, ip := range ips {
		if _, err := e.reconcileLocked(ip, now); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", ip, err))
		}
	}
	return errors.Join(failures...)
}

// SetEnabled reconciles every stored justification when entering or leaving
// enforcement. Grants survive TEST mode and are reconsidered on ENFORCE.
func (e *Engine) SetEnabled(enabled bool, now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	previous := e.enabled
	e.enabled = enabled
	if err := e.reconcileAllLocked(now); err != nil {
		e.enabled = previous
		return errors.Join(err, e.reconcileAllLocked(now))
	}
	return nil
}

func (e *Engine) reconcileAllLocked(now time.Time) error {
	rows, err := e.db.Query(`SELECT ip FROM enforcement_ip_state ORDER BY ip`)
	if err != nil {
		return err
	}
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return err
		}
		ips = append(ips, ip)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var failures []error
	for _, ip := range ips {
		if _, err := e.reconcileLocked(ip, now); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", ip, err))
		}
	}
	return errors.Join(failures...)
}

// Sweep removes expired grants, then reconciles every affected address.
func (e *Engine) Sweep(now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rows, err := e.db.Query(`SELECT ip FROM enforcement_grants WHERE expires_at_ns<=?
		UNION SELECT ip FROM enforcement_overrides WHERE expires_at_ns<=?`, now.UnixNano(), now.UnixNano())
	if err != nil {
		return err
	}
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return err
		}
		ips = append(ips, ip)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM enforcement_grants WHERE expires_at_ns<=?`, now.UnixNano()); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM enforcement_overrides WHERE expires_at_ns<=?`, now.UnixNano()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	var failures []error
	for _, ip := range ips {
		if _, err := e.reconcileLocked(ip, now); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", ip, err))
		}
	}
	return errors.Join(failures...)
}

// Grants returns the active, independently attributable reasons for an IP.
func (e *Engine) Grants(raw string, now time.Time) ([]Grant, error) {
	ip, err := canonicalIP(raw)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	rows, err := e.db.Query(`SELECT owner_kind,owner_id,expires_at_ns,reason,policy_version,evidence_refs_json FROM enforcement_grants WHERE ip=? AND expires_at_ns>?`, ip, now.UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var grants []Grant
	for rows.Next() {
		var kind, id, reason, policyVersion, refsJSON string
		var exp int64
		if err := rows.Scan(&kind, &id, &exp, &reason, &policyVersion, &refsJSON); err != nil {
			return nil, err
		}
		var refs []string
		if err := json.Unmarshal([]byte(refsJSON), &refs); err != nil {
			return nil, err
		}
		grants = append(grants, Grant{IP: ip, Owner: banownership.Owner{Kind: banownership.Kind(kind), ID: id}, ExpiresAt: time.Unix(0, exp), Reason: reason, PolicyVersion: policyVersion, EvidenceRefs: refs})
	}
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].Owner.Kind != grants[j].Owner.Kind {
			return grants[i].Owner.Kind < grants[j].Owner.Kind
		}
		return grants[i].Owner.ID < grants[j].Owner.ID
	})
	return grants, rows.Err()
}

// GrantsByKind lists active grants for lifecycle reconciliation. Callers may
// remove each owner without disturbing independent justifications.
func (e *Engine) GrantsByKind(kind banownership.Kind, now time.Time) ([]Grant, error) {
	if kindLimit(kind) == 0 {
		return nil, errors.New("invalid enforcement owner kind")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	rows, err := e.db.Query(`SELECT ip,owner_id,expires_at_ns,reason,policy_version,evidence_refs_json FROM enforcement_grants WHERE owner_kind=? AND expires_at_ns>?`, kind, now.UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var grants []Grant
	for rows.Next() {
		var ip, id, reason, policyVersion, refsJSON string
		var exp int64
		if err := rows.Scan(&ip, &id, &exp, &reason, &policyVersion, &refsJSON); err != nil {
			return nil, err
		}
		var refs []string
		if err := json.Unmarshal([]byte(refsJSON), &refs); err != nil {
			return nil, err
		}
		grants = append(grants, Grant{IP: ip, Owner: banownership.Owner{Kind: kind, ID: id}, ExpiresAt: time.Unix(0, exp), Reason: reason, PolicyVersion: policyVersion, EvidenceRefs: refs})
	}
	return grants, rows.Err()
}

// Snapshot returns all currently justified addresses for authenticated
// operator views. An active override suppresses enforcement without deleting
// the underlying grants.
func (e *Engine) Snapshot(now time.Time) ([]SnapshotEntry, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rows, err := e.db.Query(`WITH active AS (
		SELECT ip,MAX(expires_at_ns) AS expires_at_ns,COUNT(*) AS owners
		FROM enforcement_grants WHERE expires_at_ns>? GROUP BY ip
	)
	SELECT s.ip,COALESCE(a.expires_at_ns,0),COALESCE(a.owners,0),
		s.kernel_applied,s.last_error,COALESCE(o.expires_at_ns,0)
		FROM enforcement_ip_state s
		LEFT JOIN active a ON a.ip=s.ip
		LEFT JOIN enforcement_overrides o ON o.ip=s.ip AND o.expires_at_ns>?
		WHERE a.owners>0 OR s.kernel_applied=1 OR s.last_error<>'' OR o.ip IS NOT NULL
		ORDER BY s.ip`, now.UnixNano(), now.UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []SnapshotEntry
	for rows.Next() {
		var entry SnapshotEntry
		var expiry, overrideExpiry int64
		var applied int
		if err := rows.Scan(&entry.IP, &expiry, &entry.Owners, &applied, &entry.LastError, &overrideExpiry); err != nil {
			return nil, err
		}
		if expiry > 0 {
			entry.ExpiresAt = time.Unix(0, expiry)
		}
		entry.KernelApplied = applied != 0
		if overrideExpiry > 0 {
			entry.OverrideExpiresAt = time.Unix(0, overrideExpiry)
		}
		result = append(result, entry)
	}
	return result, rows.Err()
}

func (e *Engine) reconcileLocked(ip string, now time.Time) (banownership.Decision, error) {
	rows, err := e.db.Query(`SELECT owner_kind,owner_id,expires_at_ns,policy_version FROM enforcement_grants WHERE ip=? AND expires_at_ns>?`, ip, now.UnixNano())
	if err != nil {
		return banownership.Decision{}, err
	}
	ledger := banownership.New()
	var ownerIDs []string
	versions := make(map[string]struct{})
	for rows.Next() {
		var kind, id, policyVersion string
		var exp int64
		if err := rows.Scan(&kind, &id, &exp, &policyVersion); err != nil {
			rows.Close()
			return banownership.Decision{}, err
		}
		ownerIDs = append(ownerIDs, kind+"/"+id)
		versions[policyVersion] = struct{}{}
		if _, err := ledger.Put(ip, banownership.Owner{Kind: banownership.Kind(kind), ID: id}, time.Unix(0, exp), now); err != nil {
			rows.Close()
			return banownership.Decision{}, err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return banownership.Decision{}, err
	}
	decision, err := ledger.Decision(ip, now)
	if err != nil {
		return decision, err
	}
	var overrideExpiry int64
	overrideErr := e.db.QueryRow(`SELECT expires_at_ns FROM enforcement_overrides WHERE ip=? AND expires_at_ns>?`, ip, now.UnixNano()).Scan(&overrideExpiry)
	if overrideErr != nil && !errors.Is(overrideErr, sql.ErrNoRows) {
		return decision, overrideErr
	}
	overrideActive := overrideErr == nil
	if overrideActive {
		decision.Active = false
		decision.ExpiresAt = time.Time{}
	}
	if !e.enabled {
		decision.Active = false
		decision.ExpiresAt = time.Time{}
	}
	sort.Strings(ownerIDs)
	var policyVersions []string
	for version := range versions {
		policyVersions = append(policyVersions, version)
	}
	sort.Strings(policyVersions)
	ownersJSON, _ := json.Marshal(ownerIDs)
	versionsJSON, _ := json.Marshal(policyVersions)
	var previousActive int
	var previousExpiry int64
	stateErr := e.db.QueryRow(`SELECT kernel_applied,effective_expires_ns FROM enforcement_ip_state WHERE ip=?`, ip).Scan(&previousActive, &previousExpiry)
	if stateErr != nil && !errors.Is(stateErr, sql.ErrNoRows) {
		return decision, stateErr
	}
	operation := "remove"
	nextExpiry := int64(0)
	if decision.Active {
		operation = "apply"
		nextExpiry = decision.ExpiresAt.UnixNano()
	}
	journal, err := e.db.Exec(`INSERT INTO enforcement_decision_audit
		(ip,at_ns,previous_active,next_active,previous_expires_ns,next_expires_ns,owner_ids_json,policy_versions_json,operation,override_active,result,reconcile_status)
		VALUES (?,?,?,?,?,?,?,?,?,?,'pending','pending')`, ip, now.UnixNano(), previousActive, decision.Active, previousExpiry, nextExpiry, string(ownersJSON), string(versionsJSON), operation, overrideActive)
	if err != nil {
		return decision, err
	}
	journalID, err := journal.LastInsertId()
	if err != nil {
		return decision, err
	}
	if decision.Active {
		err = e.kernel.Apply(ip)
	} else {
		err = e.kernel.Remove(ip)
	}
	tx, txErr := e.db.Begin()
	if txErr != nil {
		return decision, errors.Join(err, txErr)
	}
	defer tx.Rollback()
	if err != nil {
		if _, txErr = tx.Exec(`UPDATE enforcement_ip_state SET last_error=? WHERE ip=?`, err.Error(), ip); txErr != nil {
			return decision, errors.Join(err, txErr)
		}
		_, txErr = tx.Exec(`UPDATE enforcement_decision_audit SET result='error',reconcile_status='retry',kernel_error=? WHERE id=?`, err.Error(), journalID)
	} else {
		if decision.Active {
			_, txErr = tx.Exec(`UPDATE enforcement_ip_state SET kernel_applied=1,effective_expires_ns=?,last_error='' WHERE ip=?`, decision.ExpiresAt.UnixNano(), ip)
		} else if overrideActive || len(ownerIDs) > 0 {
			_, txErr = tx.Exec(`UPDATE enforcement_ip_state SET kernel_applied=0,effective_expires_ns=0,last_error='' WHERE ip=?`, ip)
		} else {
			_, txErr = tx.Exec(`DELETE FROM enforcement_ip_state WHERE ip=?`, ip)
		}
		if txErr != nil {
			return decision, txErr
		}
		_, txErr = tx.Exec(`UPDATE enforcement_decision_audit SET result='success',reconcile_status='converged' WHERE id=?`, journalID)
	}
	if txErr != nil {
		return decision, errors.Join(err, txErr)
	}
	if txErr = tx.Commit(); txErr != nil {
		return decision, errors.Join(err, txErr)
	}
	return decision, err
}
