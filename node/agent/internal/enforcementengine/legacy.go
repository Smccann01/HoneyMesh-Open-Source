package enforcementengine

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"honeymesh/internal/banownership"
)

const legacyMigrationName = "legacy-bans-v1"

// ImportLegacyBans is a one-time cutover operation. It copies exactly the
// unexpired legacy bans at the point all legacy writers are stopped. It does
// not touch the kernel; ReconcileAll must follow after the new writer starts.
// Do not call this while old ban/release handlers can still mutate `bans`.
func (e *Engine) ImportLegacyBans(now time.Time) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	tx, err := e.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var marker string
	err = tx.QueryRow(`SELECT name FROM enforcement_migrations WHERE name=?`, legacyMigrationName).Scan(&marker)
	if err == nil {
		if err := verifyLegacySnapshot(tx, now); err != nil {
			return 0, err
		}
		return 0, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	rows, err := tx.Query(`SELECT ip,expires FROM bans`)
	if err != nil {
		return 0, fmt.Errorf("read legacy bans: %w", err)
	}
	type legacyBan struct {
		ip      string
		expires time.Time
	}
	var pending []legacyBan
	for rows.Next() {
		var raw string
		var seconds int64
		if err := rows.Scan(&raw, &seconds); err != nil {
			rows.Close()
			return 0, err
		}
		if seconds <= now.Unix() {
			continue
		}
		ip, err := canonicalIP(raw)
		if err != nil {
			rows.Close()
			return 0, fmt.Errorf("invalid legacy ban address: %w", err)
		}
		expires := time.Unix(seconds, 0)
		pending = append(pending, legacyBan{ip: ip, expires: expires})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, ban := range pending {
		owner := banownership.Owner{Kind: banownership.Local, ID: "legacy:" + ban.ip}
		if !validOwner(owner) {
			return 0, errors.New("legacy owner ID exceeds limit")
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO enforcement_grants
			(ip,owner_kind,owner_id,expires_at_ns,reason,policy_version,evidence_refs_json)
			VALUES (?,?,?,?,?,'rc4-legacy-import-v1','[]')`, ban.ip, owner.Kind, owner.ID, ban.expires.UnixNano(), "legacy_ban"); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO enforcement_ip_state (ip) VALUES (?)`, ban.ip); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(`INSERT INTO enforcement_migrations (name,completed_at_ns) VALUES (?,?)`, legacyMigrationName, now.UnixNano()); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(pending), nil
}

// A downgrade can write the old bans table after the one-time import marker
// exists. Refuse a later RC4 startup if that table no longer matches the
// imported legacy grants, instead of silently dropping or reviving a rule.
func verifyLegacySnapshot(tx *sql.Tx, now time.Time) error {
	legacyRows := make(map[string]int64)
	rows, err := tx.Query(`SELECT ip,expires FROM bans WHERE expires>?`, now.Unix())
	if err != nil {
		return fmt.Errorf("verify legacy bans: %w", err)
	}
	for rows.Next() {
		var raw string
		var seconds int64
		if err := rows.Scan(&raw, &seconds); err != nil {
			rows.Close()
			return err
		}
		ip, err := canonicalIP(raw)
		if err != nil {
			rows.Close()
			return fmt.Errorf("invalid legacy ban address: %w", err)
		}
		if _, exists := legacyRows[ip]; exists {
			rows.Close()
			return errors.New("duplicate canonical legacy ban address after UEE cutover")
		}
		legacyRows[ip] = seconds
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	grants, err := tx.Query(`SELECT ip,owner_id,expires_at_ns FROM enforcement_grants
		WHERE owner_kind=? AND owner_id LIKE 'legacy:%' AND expires_at_ns>?`,
		banownership.Local, now.UnixNano())
	if err != nil {
		return fmt.Errorf("verify imported grants: %w", err)
	}
	for grants.Next() {
		var ip, ownerID string
		var nanos int64
		if err := grants.Scan(&ip, &ownerID, &nanos); err != nil {
			grants.Close()
			return err
		}
		seconds, ok := legacyRows[ip]
		if !ok || ownerID != "legacy:"+ip || nanos != time.Unix(seconds, 0).UnixNano() {
			grants.Close()
			return errors.New("legacy bans changed after UEE cutover; restore the reviewed database snapshot")
		}
		delete(legacyRows, ip)
	}
	err = grants.Err()
	grants.Close()
	if err != nil {
		return err
	}
	if len(legacyRows) != 0 {
		return errors.New("legacy bans changed after UEE cutover; restore the reviewed database snapshot")
	}
	return nil
}
