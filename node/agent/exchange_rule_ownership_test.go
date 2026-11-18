package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testExchangeRuleManager(t *testing.T) (*exchangeRuleManager, *int, *int) {
	t.Helper()
	database := testNodeEdgeDB(t)
	oldCache := remoteBanCache
	remoteBanCache = make(map[string]time.Time)
	t.Cleanup(func() { remoteBanCache = oldCache })
	apply, remove := 0, 0
	m, err := newExchangeRuleManager(database, func(string) error { apply++; return nil }, func(string) error { remove++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	return m, &apply, &remove
}

func TestIncompleteExchangeSnapshotLeavesExistingRuleForTTL(t *testing.T) {
	m, _, removed := testExchangeRuleManager(t)
	ip := "8.8.8.8"
	if err := m.applyRecord(exchangeRecord("signal_alpha_01", ip), time.Minute); err != nil {
		t.Fatal(err)
	}
	oldExchange, oldRules := config.Exchange, liveExchangeRules
	t.Cleanup(func() { config.Exchange, liveExchangeRules = oldExchange, oldRules })
	liveExchangeRules = m
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := []byte(`{"error":"snapshot_too_large","limit":2500}`)
		stamp := time.Now().UTC().Format(time.RFC3339)
		hash := exchangeBodyHash(body)
		w.Header().Set("X-HM-Response-Timestamp", stamp)
		w.Header().Set("X-HM-Response-Body-SHA256", hash)
		w.Header().Set("X-HM-Response-Signature", exchangeResponseSignature(http.StatusConflict, stamp, hash))
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	config.Exchange = ExchangeConfig{BaseURL: server.URL, NodeID: "test-node", SharedSecret: "test-secret", FeedCursor: "old-cursor"}
	if err := reconcileExchangeSnapshot(); err == nil {
		t.Fatal("incomplete snapshot was accepted")
	}
	if *removed != 0 || !banExpirations[ip].After(time.Now()) || config.Exchange.FeedCursor != "old-cursor" {
		t.Fatalf("incomplete snapshot changed enforcement or cursor: removed=%d expiry=%v cursor=%q", *removed, banExpirations[ip], config.Exchange.FeedCursor)
	}
}

func exchangeRecord(id, ip string) exchangeFeedRecord {
	return exchangeFeedRecord{ID: id, AttackerIP: ip, ClusterID: "trusted_cluster_01", Status: "approved"}
}

func retraction(id, ip string) exchangeRetraction {
	return exchangeRetraction{Seq: 1, SignalID: id, AttackerIP: ip, ClusterID: "trusted_cluster_01"}
}

func TestExchangeRetractionPreservesOtherSignal(t *testing.T) {
	m, applied, removed := testExchangeRuleManager(t)
	ip := "8.8.8.8"
	if err := m.applyRecord(exchangeRecord("signal_alpha_01", ip), 60*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := m.applyRecord(exchangeRecord("signal_bravo_02", ip), 120*time.Second); err != nil {
		t.Fatal(err)
	}
	if *applied != 2 {
		t.Fatalf("kernel apply calls=%d", *applied)
	}
	if err := m.retract(retraction("signal_alpha_01", ip)); err != nil {
		t.Fatal(err)
	}
	if *removed != 0 || !banExpirations[ip].After(time.Now().Add(100*time.Second)) {
		t.Fatalf("first retraction removed another owner: removed=%d expiry=%v", *removed, banExpirations[ip])
	}
	if err := m.retract(retraction("signal_bravo_02", ip)); err != nil {
		t.Fatal(err)
	}
	if *removed != 1 || len(banExpirations) != 0 {
		t.Fatalf("final retraction: removed=%d bans=%v", *removed, banExpirations)
	}
}

func TestExchangeRetractionPreservesIndependentLocalBan(t *testing.T) {
	m, _, removed := testExchangeRuleManager(t)
	ip := "8.8.8.8"
	if err := m.applyRecord(exchangeRecord("signal_alpha_01", ip), time.Minute); err != nil {
		t.Fatal(err)
	}
	banMeta[ip] = BanMeta{Category: "MANUAL", Reason: "local evidence"}
	banExpirations[ip] = time.Now().Add(10 * time.Minute)
	if err := m.retract(retraction("signal_alpha_01", ip)); err != nil {
		t.Fatal(err)
	}
	if *removed != 0 || banMeta[ip].Category != "MANUAL" || !banExpirations[ip].After(time.Now().Add(9*time.Minute)) {
		t.Fatalf("local ban changed: removed=%d meta=%+v expiry=%v", *removed, banMeta[ip], banExpirations[ip])
	}
}

func TestExchangeRetractionRejectsMismatchAndRetriesFailedRemoval(t *testing.T) {
	m, _, _ := testExchangeRuleManager(t)
	ip := "8.8.8.8"
	if err := m.applyRecord(exchangeRecord("signal_alpha_01", ip), time.Minute); err != nil {
		t.Fatal(err)
	}
	bad := retraction("signal_alpha_01", "1.1.1.1")
	if err := m.retract(bad); err == nil {
		t.Fatal("wrong address retraction accepted")
	}
	m.remove = func(string) error { return errors.New("kernel delete failed") }
	if err := m.retract(retraction("signal_alpha_01", ip)); err == nil {
		t.Fatal("failed kernel removal acknowledged")
	}
	var count int
	if err := m.db.QueryRow(`SELECT COUNT(*) FROM exchange_rule_owners WHERE signal_id='signal_alpha_01'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("ownership lost on failed release: %d %v", count, err)
	}
	if !banExpirations[ip].After(time.Now()) {
		t.Fatal("failed release disappeared from registry")
	}
	m.remove = func(string) error { return nil }
	if err := m.retract(retraction("signal_alpha_01", ip)); err != nil {
		t.Fatal(err)
	}
}

func TestExchangeOwnersAreNotRestoredFromStaleState(t *testing.T) {
	m, _, _ := testExchangeRuleManager(t)
	if _, err := m.db.Exec(`INSERT INTO exchange_rule_owners (signal_id,ip,cluster_id,expires) VALUES (?,?,?,?)`,
		"signal_before_restart", "8.8.8.8", "trusted_cluster_01", time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := m.restore(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := m.db.QueryRow(`SELECT COUNT(*) FROM exchange_rule_owners`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale Exchange owners survived restart: count=%d err=%v", count, err)
	}
}

func TestExchangeSnapshotReconcilesCurrentOwners(t *testing.T) {
	m, _, removed := testExchangeRuleManager(t)
	ip := "8.8.8.8"
	first := exchangeRecord("signal_alpha_01", ip)
	second := exchangeRecord("signal_bravo_02", ip)
	first.TTL, second.TTL = 60, 90
	if err := m.reconcileSnapshot([]exchangeFeedRecord{first, second}); err != nil {
		t.Fatal(err)
	}
	if err := m.reconcileSnapshot([]exchangeFeedRecord{second}); err != nil {
		t.Fatal(err)
	}
	if *removed != 0 || !banExpirations[ip].After(time.Now()) {
		t.Fatalf("snapshot removed a still-owned block: removed=%d", *removed)
	}
	if err := m.reconcileSnapshot(nil); err != nil {
		t.Fatal(err)
	}
	if *removed != 1 || len(banExpirations) != 0 {
		t.Fatalf("empty snapshot did not release stale block: removed=%d bans=%v", *removed, banExpirations)
	}
}

func TestInvalidExchangeSnapshotDoesNotPartiallyApply(t *testing.T) {
	m, applied, removed := testExchangeRuleManager(t)
	first := exchangeRecord("signal_alpha_01", "8.8.8.8")
	first.TTL = 60
	bad := exchangeRecord("signal_bravo_02", "1.1.1.1")
	bad.TTL = 0
	if err := m.reconcileSnapshot([]exchangeFeedRecord{first, bad}); err == nil {
		t.Fatal("accepted snapshot with invalid second record")
	}
	var owners int
	if err := m.db.QueryRow(`SELECT COUNT(*) FROM exchange_rule_owners`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 0 || *applied != 0 || *removed != 0 {
		t.Fatalf("invalid snapshot changed rules: owners=%d applied=%d removed=%d", owners, *applied, *removed)
	}
}
