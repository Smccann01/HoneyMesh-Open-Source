package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"honeymesh/internal/banownership"
	"honeymesh/internal/enforcementengine"
)

const exchangeBanCategory = "NETTOOLS_EXCHANGE"

type exchangeRetraction struct {
	Seq         int64  `json:"seq"`
	SignalID    string `json:"signalId"`
	ClusterID   string `json:"clusterId"`
	AttackerIP  string `json:"attackerIp"`
	RetractedAt string `json:"retractedAt"`
}

type exchangeRuleManager struct {
	db     *sql.DB
	apply  func(string) error
	remove func(string) error
}

var liveExchangeRules *exchangeRuleManager

func newExchangeRuleManager(database *sql.DB, apply, remove func(string) error) (*exchangeRuleManager, error) {
	if database == nil || apply == nil || remove == nil {
		return nil, errors.New("Exchange rule manager requires storage and kernel callbacks")
	}
	_, err := database.Exec(`CREATE TABLE IF NOT EXISTS exchange_rule_owners (
		signal_id TEXT PRIMARY KEY,
		ip TEXT NOT NULL,
		cluster_id TEXT NOT NULL,
		expires INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_exchange_rule_owners_ip ON exchange_rule_owners(ip);`)
	if err != nil {
		return nil, err
	}
	return &exchangeRuleManager{db: database, apply: apply, remove: remove}, nil
}

func (m *exchangeRuleManager) effective(ip string, excludeID string, now time.Time) (banownership.Decision, error) {
	rows, err := m.db.Query(`SELECT signal_id, expires FROM exchange_rule_owners WHERE ip=? AND signal_id<>?`, ip, excludeID)
	if err != nil {
		return banownership.Decision{}, err
	}
	defer rows.Close()
	ledger := banownership.New()
	for rows.Next() {
		var id string
		var seconds int64
		if err := rows.Scan(&id, &seconds); err != nil {
			return banownership.Decision{}, err
		}
		exp := time.Unix(seconds, 0)
		if exp.After(now) {
			if _, err := ledger.Put(ip, banownership.Owner{Kind: banownership.Exchange, ID: id}, exp, now); err != nil {
				return banownership.Decision{}, err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return banownership.Decision{}, err
	}
	return ledger.Decision(ip, now)
}

func exchangeCategoryForIP(ip string) string {
	banMetaMu.Lock()
	category := banMeta[ip].Category
	banMetaMu.Unlock()
	return category
}

func (m *exchangeRuleManager) applyRecord(record exchangeFeedRecord, ttl time.Duration) error {
	ip := normalizeIPKey(record.AttackerIP)
	if ip == "" || record.ID == "" || record.ClusterID == "" || record.Status != "approved" {
		return errors.New("invalid Exchange signal")
	}
	if ttl <= 0 || ttl > maxExchangeTTL {
		return errors.New("invalid Exchange signal TTL")
	}
	now := time.Now()
	expires := now.Add(ttl).Truncate(time.Second)
	if !expires.After(now) {
		return errors.New("Exchange signal already expired")
	}
	banMutex.Lock()
	defer banMutex.Unlock()
	if liveUEE == nil && banExpirations[ip].After(now) && exchangeCategoryForIP(ip) != exchangeBanCategory {
		log.Printf("[EXCHANGE] signal observed; independent ban owns ip=%s", ip)
		return nil
	}
	var storedIP, storedCluster string
	var previousExpiry int64
	err := m.db.QueryRow(`SELECT ip,cluster_id,expires FROM exchange_rule_owners WHERE signal_id=?`, record.ID).Scan(&storedIP, &storedCluster, &previousExpiry)
	inserted := errors.Is(err, sql.ErrNoRows)
	if err != nil && !inserted {
		return err
	}
	if !inserted && (storedIP != ip || storedCluster != record.ClusterID) {
		return errors.New("Exchange signal ID ownership mismatch")
	}
	if inserted {
		_, err = m.db.Exec(`INSERT INTO exchange_rule_owners (signal_id,ip,cluster_id,expires) VALUES (?,?,?,?)`, record.ID, ip, record.ClusterID, expires.Unix())
	} else {
		_, err = m.db.Exec(`UPDATE exchange_rule_owners SET expires=? WHERE signal_id=?`, expires.Unix(), record.ID)
	}
	if err != nil {
		return err
	}
	if liveUEE != nil {
		_, err := liveUEE.Put(enforcementengine.Grant{
			IP: ip, Owner: banownership.Owner{Kind: banownership.Exchange, ID: record.ID},
			ExpiresAt: expires, Reason: "approved shared signal", PolicyVersion: runtimePolicyVersion,
			EvidenceRefs: []string{record.ID},
		}, now)
		if err != nil {
			return err
		}
		return refreshLegacyBanView(now)
	}
	decision, err := m.effective(ip, "", now)
	if err != nil {
		return err
	}
	if !decision.Active {
		return errors.New("Exchange signal has no active owner")
	}
	if err := m.apply(ip); err != nil {
		if inserted {
			_, _ = m.db.Exec(`DELETE FROM exchange_rule_owners WHERE signal_id=?`, record.ID)
		} else {
			_, _ = m.db.Exec(`UPDATE exchange_rule_owners SET expires=? WHERE signal_id=?`, previousExpiry, record.ID)
		}
		return fmt.Errorf("Exchange kernel apply: %w", err)
	}
	banExpirations[ip] = decision.ExpiresAt
	banMetaMu.Lock()
	banMeta[ip] = BanMeta{Category: exchangeBanCategory, Reason: "approved shared signal"}
	banMetaMu.Unlock()
	remoteBanMu.Lock()
	if remoteBanCache == nil {
		remoteBanCache = make(map[string]time.Time)
	}
	remoteBanCache[ip] = decision.ExpiresAt
	remoteBanMu.Unlock()
	return nil
}

func (m *exchangeRuleManager) retract(event exchangeRetraction) error {
	ip := normalizeIPKey(event.AttackerIP)
	if event.Seq <= 0 || event.SignalID == "" || event.ClusterID == "" || ip == "" {
		return errors.New("invalid Exchange retraction")
	}
	banMutex.Lock()
	defer banMutex.Unlock()
	var ownedIP, cluster string
	err := m.db.QueryRow(`SELECT ip,cluster_id FROM exchange_rule_owners WHERE signal_id=?`, event.SignalID).Scan(&ownedIP, &cluster)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if ownedIP != ip || cluster != event.ClusterID {
		return errors.New("Exchange retraction ownership mismatch")
	}
	now := time.Now()
	if liveUEE != nil {
		if _, err := liveUEE.Remove(ip, banownership.Owner{Kind: banownership.Exchange, ID: event.SignalID}, now); err != nil {
			return err
		}
		if _, err := m.db.Exec(`DELETE FROM exchange_rule_owners WHERE signal_id=?`, event.SignalID); err != nil {
			return err
		}
		return refreshLegacyBanView(now)
	}
	decision, err := m.effective(ip, event.SignalID, now)
	if err != nil {
		return err
	}
	if exchangeCategoryForIP(ip) == exchangeBanCategory {
		if !decision.Active {
			if err := m.remove(ip); err != nil {
				return fmt.Errorf("Exchange kernel release: %w", err)
			}
			delete(banExpirations, ip)
			banMetaMu.Lock()
			delete(banMeta, ip)
			banMetaMu.Unlock()
			remoteBanMu.Lock()
			delete(remoteBanCache, ip)
			delete(remoteBanSources, ip)
			remoteBanMu.Unlock()
		} else {
			banExpirations[ip] = decision.ExpiresAt
			remoteBanMu.Lock()
			remoteBanCache[ip] = decision.ExpiresAt
			remoteBanMu.Unlock()
		}
	}
	if _, err := m.db.Exec(`DELETE FROM exchange_rule_owners WHERE signal_id=?`, event.SignalID); err != nil {
		return err
	}
	return nil
}

func (m *exchangeRuleManager) clearIP(ip string) error {
	if m == nil || m.db == nil {
		return nil
	}
	if liveUEE != nil {
		return nil
	}
	_, err := m.db.Exec(`DELETE FROM exchange_rule_owners WHERE ip=?`, normalizeIPKey(ip))
	return err
}

func (m *exchangeRuleManager) releaseAll() error {
	if m == nil {
		return nil
	}
	if liveUEE != nil {
		grants, err := liveUEE.GrantsByKind(banownership.Exchange, time.Now())
		if err != nil {
			return err
		}
		for _, grant := range grants {
			if _, err := liveUEE.Remove(grant.IP, grant.Owner, time.Now()); err != nil {
				return err
			}
		}
		if _, err := m.db.Exec(`DELETE FROM exchange_rule_owners`); err != nil {
			return err
		}
		banMutex.Lock()
		err = refreshLegacyBanView(time.Now())
		banMutex.Unlock()
		if err == nil {
			broadcastBans()
		}
		return err
	}
	rows, err := m.db.Query(`SELECT DISTINCT ip FROM exchange_rule_owners`)
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
	for _, ip := range ips {
		banMutex.Lock()
		if exchangeCategoryForIP(ip) == exchangeBanCategory {
			if err := m.remove(ip); err != nil {
				banMutex.Unlock()
				return err
			}
			delete(banExpirations, ip)
			banMetaMu.Lock()
			delete(banMeta, ip)
			banMetaMu.Unlock()
			remoteBanMu.Lock()
			delete(remoteBanCache, ip)
			remoteBanMu.Unlock()
		}
		if err := m.clearIP(ip); err != nil {
			banMutex.Unlock()
			return err
		}
		banMutex.Unlock()
	}
	if len(ips) > 0 {
		broadcastBans()
	}
	return nil
}

func (m *exchangeRuleManager) reconcileTrust() error {
	if m == nil {
		return nil
	}
	rows, err := m.db.Query(`SELECT signal_id,ip,cluster_id FROM exchange_rule_owners`)
	if err != nil {
		return err
	}
	var revoked []exchangeRetraction
	for rows.Next() {
		var event exchangeRetraction
		if err := rows.Scan(&event.SignalID, &event.AttackerIP, &event.ClusterID); err != nil {
			rows.Close()
			return err
		}
		if !exchangeTrustedCluster(event.ClusterID) {
			event.Seq = 1
			revoked = append(revoked, event)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, event := range revoked {
		if err := m.retract(event); err != nil {
			return err
		}
	}
	if len(revoked) > 0 {
		broadcastBans()
	}
	return nil
}

func (m *exchangeRuleManager) reconcileSnapshot(records []exchangeFeedRecord) error {
	wanted := make(map[string]struct{}, len(records))
	// Reject a malformed complete snapshot before changing any kernel rule.
	// The caller retains its previous cursor and can retry a fresh snapshot.
	for _, record := range records {
		if !exchangeRecordEligible(record) {
			continue
		}
		if _, exists := wanted[record.ID]; exists {
			return errors.New("duplicate Exchange snapshot signal")
		}
		wanted[record.ID] = struct{}{}
		ttl := time.Duration(record.TTL) * time.Second
		if ttl <= 0 || ttl > maxExchangeTTL || normalizeIPKey(record.AttackerIP) == "" || record.ClusterID == "" {
			return errors.New("invalid Exchange snapshot record")
		}
	}
	for _, record := range records {
		if !exchangeRecordEligible(record) {
			continue
		}
		ttl := time.Duration(record.TTL) * time.Second
		if err := m.applyRecord(record, ttl); err != nil {
			return err
		}
	}
	rows, err := m.db.Query(`SELECT signal_id,ip,cluster_id FROM exchange_rule_owners`)
	if err != nil {
		return err
	}
	var stale []exchangeRetraction
	for rows.Next() {
		var event exchangeRetraction
		if err := rows.Scan(&event.SignalID, &event.AttackerIP, &event.ClusterID); err != nil {
			rows.Close()
			return err
		}
		if _, ok := wanted[event.SignalID]; !ok {
			event.Seq = 1
			stale = append(stale, event)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, event := range stale {
		if err := m.retract(event); err != nil {
			return err
		}
	}
	if len(records) > 0 || len(stale) > 0 {
		broadcastBans()
	}
	return nil
}

func (m *exchangeRuleManager) restore() error {
	if m == nil {
		return nil
	}
	// RC4 shared rules are intentionally ephemeral across process restart.
	// Reapplying from stale local state before receiving signed retractions could
	// revive a withdrawn rule. A future full-snapshot protocol can change this.
	_, err := m.db.Exec(`DELETE FROM exchange_rule_owners`)
	return err
}
