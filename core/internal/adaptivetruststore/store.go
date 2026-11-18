// Package adaptivetruststore persists local Adaptive Trust grants, holds, and
// decision audit records. The caller owns the SQLite connection and verifies
// the authority of every operator and evidence issuer before calling it.
package adaptivetruststore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"honeymesh/internal/adaptivetrust"
)

type Store struct{ db *sql.DB }

var ErrConflict = errors.New("adaptive trust record conflicts with existing ID")

func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("adaptive trust store requires SQLite")
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS hat_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE IF NOT EXISTS hat_grants (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL,
			resource_id TEXT NOT NULL, issued_ns INTEGER NOT NULL, expires_ns INTEGER NOT NULL,
			policy_version TEXT NOT NULL, payload_json BLOB NOT NULL,
			revoked_at_ns INTEGER, revoked_by TEXT
		);
		CREATE TABLE IF NOT EXISTS hat_grant_actions (
			grant_id TEXT NOT NULL, action TEXT NOT NULL, PRIMARY KEY (grant_id, action)
		);
		CREATE INDEX IF NOT EXISTS hat_grants_lookup ON hat_grants(tenant_id, subject_id, resource_id, policy_version, expires_ns);
		CREATE TABLE IF NOT EXISTS hat_holds (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL,
			resource_id TEXT NOT NULL, action TEXT NOT NULL, placed_by TEXT NOT NULL,
			placed_ns INTEGER NOT NULL, released_ns INTEGER, released_by TEXT,
			verifier_id TEXT, verification_id TEXT
		);
		CREATE UNIQUE INDEX IF NOT EXISTS hat_one_active_hold ON hat_holds(tenant_id, subject_id, resource_id, action) WHERE released_ns IS NULL;
		CREATE TABLE IF NOT EXISTS hat_decisions (
			id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,
			subject_id TEXT NOT NULL, resource_id TEXT NOT NULL, action TEXT NOT NULL,
			evaluated_ns INTEGER NOT NULL, effect TEXT NOT NULL, reason TEXT NOT NULL,
			policy_version TEXT NOT NULL, payload_json BLOB NOT NULL
		);
		CREATE INDEX IF NOT EXISTS hat_decisions_lookup ON hat_decisions(tenant_id, subject_id, resource_id, evaluated_ns);`)
	if err != nil {
		return nil, fmt.Errorf("create adaptive trust schema: %w", err)
	}
	var version string
	err = db.QueryRow(`SELECT value FROM hat_meta WHERE key='schema_version'`).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = db.Exec(`INSERT INTO hat_meta(key,value) VALUES('schema_version','1')`)
		version = "1"
	}
	if err != nil {
		return nil, fmt.Errorf("read adaptive trust schema: %w", err)
	}
	if version != "1" {
		return nil, fmt.Errorf("unsupported adaptive trust schema %q", version)
	}
	return &Store{db: db}, nil
}

// PutGrant is insert-only. An identical retry is idempotent; changing a grant
// requires revoking the old ID and obtaining a new operator approval.
func (s *Store) PutGrant(ctx context.Context, grant adaptivetrust.Grant) error {
	if blank(grant.ID) || blank(grant.TenantID) || blank(grant.SubjectID) || blank(grant.ResourceID) ||
		blank(grant.ApprovedBy) || blank(grant.PolicyVersion) || grant.IssuedAt.IsZero() ||
		!grant.ExpiresAt.After(grant.IssuedAt) || len(grant.Actions) == 0 {
		return errors.New("invalid adaptive trust grant")
	}
	grant.Actions = append([]string(nil), grant.Actions...)
	sort.Strings(grant.Actions)
	for idx, action := range grant.Actions {
		if blank(action) || (idx > 0 && grant.Actions[idx-1] == action) {
			return errors.New("invalid adaptive trust grant actions")
		}
	}
	payload, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO hat_grants
		(id,tenant_id,subject_id,resource_id,issued_ns,expires_ns,policy_version,payload_json)
		VALUES(?,?,?,?,?,?,?,?)`, grant.ID, grant.TenantID, grant.SubjectID, grant.ResourceID,
		grant.IssuedAt.UnixNano(), grant.ExpiresAt.UnixNano(), grant.PolicyVersion, payload)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		var existing []byte
		if err := tx.QueryRowContext(ctx, `SELECT payload_json FROM hat_grants WHERE id=?`, grant.ID).Scan(&existing); err != nil {
			return err
		}
		if !bytes.Equal(existing, payload) {
			return ErrConflict
		}
		return tx.Commit()
	}
	for _, action := range grant.Actions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO hat_grant_actions(grant_id,action) VALUES(?,?)`, grant.ID, action); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ActiveGrant(ctx context.Context, request adaptivetrust.Request, policyVersion string, now time.Time) (*adaptivetrust.Grant, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT g.payload_json FROM hat_grants g
		JOIN hat_grant_actions a ON a.grant_id=g.id
		WHERE g.tenant_id=? AND g.subject_id=? AND g.resource_id=? AND a.action=?
		AND g.policy_version=? AND g.issued_ns<=? AND g.expires_ns>? AND g.revoked_at_ns IS NULL
		ORDER BY g.issued_ns DESC, g.id DESC LIMIT 1`, request.TenantID, request.SubjectID,
		request.ResourceID, request.Action, policyVersion, now.UnixNano(), now.UnixNano()).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var grant adaptivetrust.Grant
	if err := json.Unmarshal(payload, &grant); err != nil {
		return nil, fmt.Errorf("corrupt adaptive trust grant: %w", err)
	}
	return &grant, nil
}

func (s *Store) RevokeGrant(ctx context.Context, id, by string, at time.Time) error {
	if blank(id) || blank(by) || at.IsZero() {
		return errors.New("invalid grant revocation")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE hat_grants SET revoked_at_ns=?, revoked_by=? WHERE id=? AND revoked_at_ns IS NULL`, at.UnixNano(), by, id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("grant not active")
	}
	return nil
}

func (s *Store) PlaceHold(ctx context.Context, hold adaptivetrust.Hold) error {
	if blank(hold.ID) || blank(hold.TenantID) || blank(hold.SubjectID) || blank(hold.ResourceID) ||
		blank(hold.Action) || blank(hold.PlacedBy) || hold.PlacedAt.IsZero() {
		return errors.New("invalid adaptive trust hold")
	}
	result, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO hat_holds(id,tenant_id,subject_id,resource_id,action,placed_by,placed_ns)
		VALUES(?,?,?,?,?,?,?)`, hold.ID, hold.TenantID, hold.SubjectID, hold.ResourceID,
		hold.Action, hold.PlacedBy, hold.PlacedAt.UnixNano())
	if err != nil {
		return fmt.Errorf("place adaptive trust hold: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count == 1 {
		return err
	}
	var tenant, subject, resource, action, placedBy string
	var placed int64
	err = s.db.QueryRowContext(ctx, `SELECT tenant_id,subject_id,resource_id,action,placed_by,placed_ns FROM hat_holds WHERE id=?`, hold.ID).
		Scan(&tenant, &subject, &resource, &action, &placedBy, &placed)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if tenant != hold.TenantID || subject != hold.SubjectID || resource != hold.ResourceID || action != hold.Action ||
		placedBy != hold.PlacedBy || placed != hold.PlacedAt.UnixNano() {
		return ErrConflict
	}
	return nil
}

func (s *Store) ActiveHold(ctx context.Context, request adaptivetrust.Request) (*adaptivetrust.Hold, error) {
	hold := new(adaptivetrust.Hold)
	var placed int64
	err := s.db.QueryRowContext(ctx, `SELECT id,placed_by,placed_ns FROM hat_holds
		WHERE tenant_id=? AND subject_id=? AND resource_id=? AND action=? AND released_ns IS NULL`,
		request.TenantID, request.SubjectID, request.ResourceID, request.Action).Scan(&hold.ID, &hold.PlacedBy, &placed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	hold.TenantID, hold.SubjectID, hold.ResourceID, hold.Action = request.TenantID, request.SubjectID, request.ResourceID, request.Action
	hold.PlacedAt = time.Unix(0, placed).UTC()
	return hold, nil
}

type ReleaseApproval struct {
	By             string
	VerifierID     string
	VerificationID string
	At             time.Time
}

// ReleaseHold requires a separate approver and independent verification ID.
// The caller must authenticate both authorities before calling this method.
func (s *Store) ReleaseHold(ctx context.Context, id string, approval ReleaseApproval) error {
	if blank(id) || blank(approval.By) || blank(approval.VerifierID) || blank(approval.VerificationID) || approval.At.IsZero() {
		return errors.New("invalid quarantine release approval")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var placedBy string
	var placed int64
	if err := tx.QueryRowContext(ctx, `SELECT placed_by,placed_ns FROM hat_holds WHERE id=? AND released_ns IS NULL`, id).Scan(&placedBy, &placed); err != nil {
		return err
	}
	if approval.By == placedBy || approval.VerifierID == placedBy || approval.VerifierID == approval.By ||
		!approval.At.After(time.Unix(0, placed)) {
		return errors.New("quarantine release requires a separate approver after placement")
	}
	result, err := tx.ExecContext(ctx, `UPDATE hat_holds SET released_ns=?,released_by=?,verifier_id=?,verification_id=?
		WHERE id=? AND released_ns IS NULL`, approval.At.UnixNano(), approval.By, approval.VerifierID, approval.VerificationID, id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return errors.New("quarantine hold changed before release")
	}
	return tx.Commit()
}

func (s *Store) AppendDecision(ctx context.Context, request adaptivetrust.Request, decision adaptivetrust.Decision) error {
	if decision.SchemaVersion != adaptivetrust.SchemaVersion || decision.EvaluatedAt.IsZero() ||
		blank(request.TenantID) || blank(request.SubjectID) || blank(request.ResourceID) || blank(request.Action) {
		return errors.New("invalid adaptive trust decision audit")
	}
	payload, err := json.Marshal(decision)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO hat_decisions
		(tenant_id,subject_id,resource_id,action,evaluated_ns,effect,reason,policy_version,payload_json)
		VALUES(?,?,?,?,?,?,?,?,?)`, request.TenantID, request.SubjectID, request.ResourceID,
		request.Action, decision.EvaluatedAt.UnixNano(), decision.Effect, decision.Reason,
		decision.PolicyVersion, payload)
	return err
}

// RecentDecisions reads bounded local audit history for one exact relationship.
func (s *Store) RecentDecisions(ctx context.Context, request adaptivetrust.Request, limit int) ([]adaptivetrust.Decision, error) {
	if blank(request.TenantID) || blank(request.SubjectID) || blank(request.ResourceID) || blank(request.Action) || limit < 1 || limit > 100 {
		return nil, errors.New("invalid adaptive trust audit query")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT payload_json FROM hat_decisions
		WHERE tenant_id=? AND subject_id=? AND resource_id=? AND action=?
		ORDER BY id DESC LIMIT ?`, request.TenantID, request.SubjectID, request.ResourceID, request.Action, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]adaptivetrust.Decision, 0, limit)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var decision adaptivetrust.Decision
		if err := json.Unmarshal(payload, &decision); err != nil || decision.SchemaVersion != adaptivetrust.SchemaVersion {
			return nil, errors.New("corrupt adaptive trust decision audit")
		}
		out = append(out, decision)
	}
	return out, rows.Err()
}

func blank(s string) bool { return strings.TrimSpace(s) == "" }
