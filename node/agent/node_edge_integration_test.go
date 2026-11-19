package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"honeymesh/internal/agentbridge"
)

func testNodeEdgeDB(t *testing.T) *sql.DB {
	t.Helper()
	oldDB, oldBans, oldMeta := db, banExpirations, banMeta
	t.Cleanup(func() { db, banExpirations, banMeta = oldDB, oldBans, oldMeta })
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	banExpirations = make(map[string]time.Time)
	banMeta = make(map[string]BanMeta)
	if err := initNodeEdgeAudit(); err != nil {
		t.Fatal(err)
	}
	return db
}

func testNodeEdgeEvent(id string) agentbridge.Event {
	return agentbridge.Event{EventID: id, Source: "node_guard", IP: "8.8.8.8", ReasonCode: "invalid_signature_burst", EvidenceHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Confidence: 90, TTLSeconds: 60}
}

func testNodeEdgeController(database *sql.DB, auto bool, now time.Time) *nodeEdgeController {
	return &nodeEdgeController{
		db: database, autoBlock: auto, modeEnforce: func() bool { return true },
		attached: func() bool { return true }, allowed: func(string) bool { return true },
		canaryAllowed: func(string) bool { return true },
		apply:         func(string) error { return nil }, remove: func(string) error { return nil },
		now: func() time.Time { return now }, lastBySource: make(map[string]time.Time),
	}
}

func TestNodeEdgeObserveAndDurableReplay(t *testing.T) {
	database := testNodeEdgeDB(t)
	now := time.Now()
	c := testNodeEdgeController(database, false, now)
	event := testNodeEdgeEvent("event_observe_1234")
	status, err := c.onEvent(context.Background(), event)
	if err != nil || status != "observed" {
		t.Fatalf("observe: %s %v", status, err)
	}
	if len(banExpirations) != 0 {
		t.Fatal("observe mode created a ban")
	}
	// A fresh controller simulates a restart with no in-memory replay state.
	c = testNodeEdgeController(database, true, now.Add(2*time.Minute))
	if _, err := c.onEvent(context.Background(), event); err == nil {
		t.Fatal("durable duplicate event was accepted")
	}
	if len(banExpirations) != 0 {
		t.Fatal("duplicate event created a ban")
	}
}

func TestNodeEdgeFreeCanaryRequiresLocalEnforcementPolicy(t *testing.T) {
	database := testNodeEdgeDB(t)
	c := testNodeEdgeController(database, true, time.Now())
	t.Setenv("HM_NODE_PRO_ENTITLEMENT_FILE", "")
	t.Setenv("HM_NODE_PRO_UNIT_ID", "")
	modeEnforce := false
	c.modeEnforce = func() bool { return modeEnforce }
	applied := 0
	c.apply = func(string) error { applied++; return nil }
	status, err := c.onEvent(context.Background(), testNodeEdgeEvent("event_test_mode_01"))
	if err != nil || status != "observed" || applied != 0 {
		t.Fatalf("TEST event: status=%s err=%v applied=%d", status, err, applied)
	}
	var detail string
	if err := database.QueryRow(`SELECT detail FROM node_edge_events WHERE event_id='event_test_mode_01'`).Scan(&detail); err != nil || detail != "mode_not_enforce" {
		t.Fatalf("TEST audit detail=%q err=%v", detail, err)
	}
	modeEnforce = true
	allowed := testNodeEdgeEvent("event_free_canary_02")
	allowed.IP = "1.1.1.1"
	status, err = c.onEvent(context.Background(), allowed)
	if err != nil || status != "blocked" || applied != 1 {
		t.Fatalf("free canary event: status=%s err=%v applied=%d", status, err, applied)
	}
}

func TestNodeEdgeKernelAcknowledgementAndExpiry(t *testing.T) {
	database := testNodeEdgeDB(t)
	c := testNodeEdgeController(database, true, time.Now())
	oldController := liveNodeEdge
	liveNodeEdge = c
	t.Cleanup(func() { liveNodeEdge = oldController })
	applied := 0
	c.apply = func(ip string) error {
		if ip != "8.8.8.8" {
			t.Fatal(ip)
		}
		applied++
		return nil
	}
	status, err := c.onEvent(context.Background(), testNodeEdgeEvent("event_block_12345"))
	if err != nil || status != "blocked" || applied != 1 {
		t.Fatalf("block: %s %v applied=%d", status, err, applied)
	}
	blocks, err := nodeEdgeActiveBlocks(context.Background())
	if err != nil || len(blocks) != 1 {
		t.Fatalf("active blocks: %v %v", blocks, err)
	}
	var stored string
	if err := database.QueryRow(`SELECT status FROM node_edge_events WHERE event_id=?`, "event_block_12345").Scan(&stored); err != nil || stored != "kernel_applied" {
		t.Fatalf("audit: %s %v", stored, err)
	}
	banExpirations["8.8.8.8"] = time.Now().Add(-time.Second)
	cleanupBans()
	if err := database.QueryRow(`SELECT status FROM node_edge_events WHERE event_id=?`, "event_block_12345").Scan(&stored); err != nil || stored != "expired" {
		t.Fatalf("expiry audit: %s %v", stored, err)
	}
	if len(banExpirations) != 0 {
		t.Fatal("expired ban remained active")
	}
}

func TestNodeEdgeFailedApplyCannotClaimBlock(t *testing.T) {
	database := testNodeEdgeDB(t)
	c := testNodeEdgeController(database, true, time.Now())
	c.apply = func(string) error { return errors.New("map unavailable") }
	status, err := c.onEvent(context.Background(), testNodeEdgeEvent("event_failed_1234"))
	if err == nil || status == "blocked" || len(banExpirations) != 0 {
		t.Fatalf("false block: %s %v", status, err)
	}
	var stored, detail string
	if err := database.QueryRow(`SELECT status,detail FROM node_edge_events WHERE event_id=?`, "event_failed_1234").Scan(&stored, &detail); err != nil || stored != "rejected" || detail != "kernel_error" {
		t.Fatalf("audit: %s %s %v", stored, detail, err)
	}
}

func TestNodeEdgeCanaryGateAndParsing(t *testing.T) {
	addresses, err := parseNodeEdgeCanarySources("8.8.8.8,2606:4700:4700::1111")
	if err != nil || len(addresses) != 2 {
		t.Fatalf("parse exact canary sources: %v %v", addresses, err)
	}
	for _, raw := range []string{"10.0.0.1", "127.0.0.1", "8.8.8.0/24", "8.8.8.8,", "::ffff:8.8.8.8"} {
		if _, err := parseNodeEdgeCanarySources(raw); err == nil {
			t.Fatalf("accepted unsafe canary source %q", raw)
		}
	}
	database := testNodeEdgeDB(t)
	c := testNodeEdgeController(database, true, time.Now())
	c.canaryAllowed = func(ip string) bool { _, ok := addresses[ip]; return ok }
	status, err := c.onEvent(context.Background(), testNodeEdgeEvent("excluded_event_1234"))
	if err != nil || status != "blocked" {
		t.Fatalf("listed source not blocked: %s %v", status, err)
	}
	c.canaryAllowed = func(string) bool { return false }
	event := testNodeEdgeEvent("excluded_event_5678")
	event.IP = "1.1.1.1"
	status, err = c.onEvent(context.Background(), event)
	if err != nil || status != "observed" {
		t.Fatalf("unlisted source: %s %v", status, err)
	}
	var detail string
	if err := database.QueryRow(`SELECT detail FROM node_edge_events WHERE event_id=?`, event.EventID).Scan(&detail); err != nil || detail != "canary_excluded" {
		t.Fatalf("gate audit: %s %v", detail, err)
	}
}

func TestNodeEdgeModeChangeReleasesOnlyAppRules(t *testing.T) {
	testPaidHostLicense(t)
	database := testNodeEdgeDB(t)
	c := testNodeEdgeController(database, true, time.Now())
	oldController := liveNodeEdge
	oldMode := Mode()
	t.Cleanup(func() { liveNodeEdge = oldController; _ = SetMode(oldMode) })
	liveNodeEdge = c
	if err := SetMode(ModeEnforce); err != nil {
		t.Fatal(err)
	}
	if status, err := c.onEvent(context.Background(), testNodeEdgeEvent("release_event_1234")); err != nil || status != "blocked" {
		t.Fatalf("block: %s %v", status, err)
	}
	banExpirations["1.1.1.1"] = time.Now().Add(time.Minute)
	banMeta["1.1.1.1"] = BanMeta{Category: "MANUAL"}
	removed := 0
	c.remove = func(string) error { removed++; return nil }
	if err := SetMode(ModeTest); err != nil {
		t.Fatal(err)
	}
	if removed != 1 || len(banExpirations) != 1 || banMeta["1.1.1.1"].Category != "MANUAL" {
		t.Fatalf("incorrect emergency release: removed=%d bans=%v", removed, banExpirations)
	}
	var status, actor string
	if err := database.QueryRow(`SELECT status,release_actor FROM node_edge_events WHERE event_id='release_event_1234'`).Scan(&status, &actor); err != nil || status != "released" || actor != "mode_change" {
		t.Fatalf("release audit: %s %s %v", status, actor, err)
	}
}

func TestNodeEdgeReleaseFailureRemainsVisible(t *testing.T) {
	database := testNodeEdgeDB(t)
	c := testNodeEdgeController(database, true, time.Now())
	oldController := liveNodeEdge
	liveNodeEdge = c
	t.Cleanup(func() { liveNodeEdge = oldController })
	if status, err := c.onEvent(context.Background(), testNodeEdgeEvent("release_failure_1234")); err != nil || status != "blocked" {
		t.Fatalf("block: %s %v", status, err)
	}
	c.remove = func(string) error { return errors.New("map delete failed") }
	if err := releaseNodeEdgeBlocks("mode_change"); err == nil {
		t.Fatal("failed kernel release was reported successful")
	}
	if len(banExpirations) != 1 {
		t.Fatal("failed release disappeared from active registry")
	}
	var status string
	if err := database.QueryRow(`SELECT status FROM node_edge_events WHERE event_id='release_failure_1234'`).Scan(&status); err != nil || status != "kernel_applied" {
		t.Fatalf("failed release audit: %s %v", status, err)
	}
}

func TestNodeEdgeSignedRequestToAgent(t *testing.T) {
	database := testNodeEdgeDB(t)
	c := testNodeEdgeController(database, false, time.Now())
	secret := []byte("separate-node-bridge-test-secret-1234567890")
	bridge, err := agentbridge.New(agentbridge.Config{
		Secret:         secret,
		ExpectedSource: "node_guard",
		AllowedSource:  func(ip netip.Addr) bool { return ip.String() == "8.8.8.8" },
		OnEvent:        c.onEvent,
		ActiveBlocks:   nodeEdgeActiveBlocks,
		AgentMode:      func(context.Context) (string, error) { return "TEST", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(bridge.Handler())
	defer server.Close()
	event := testNodeEdgeEvent("signed_event_1234")
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := "signed_nonce_1234"
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(timestamp + "\n" + nonce + "\n"))
	_, _ = mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/event", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Edge-Timestamp", timestamp)
	req.Header.Set("X-Edge-Nonce", nonce)
	req.Header.Set("X-Edge-Signature", hex.EncodeToString(mac.Sum(nil)))
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("signed request status: %d", response.StatusCode)
	}
	var result map[string]string
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["status"] != "observed" {
		t.Fatalf("signed request result: %v", result)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM node_edge_events WHERE event_id=?`, event.EventID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("audit count %d: %v", count, err)
	}
	replay, err := http.NewRequest(http.MethodPost, server.URL+"/v1/event", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	replay.Header = req.Header.Clone()
	response, err = http.DefaultClient.Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("replay status: %d", response.StatusCode)
	}
}

func TestNodeEdgeRealNodeClientOverUnix(t *testing.T) {
	clientPath := os.Getenv("HM_NODE_CLIENT_PATH")
	if clientPath == "" {
		t.Skip("set HM_NODE_CLIENT_PATH to test the real Node client")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is unavailable")
	}
	database := testNodeEdgeDB(t)
	c := testNodeEdgeController(database, false, time.Now())
	secret := "separate-node-bridge-test-secret-1234567890"
	bridge, err := agentbridge.New(agentbridge.Config{
		Secret:         []byte(secret),
		ExpectedSource: "node_guard",
		AllowedSource:  func(ip netip.Addr) bool { return ip.String() == "8.8.8.8" },
		OnEvent:        c.onEvent,
		ActiveBlocks:   nodeEdgeActiveBlocks,
		AgentMode:      func(context.Context) (string, error) { return "TEST", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: bridge.Handler()}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	script := `import { pathToFileURL } from 'node:url';
const { createAgentBridge } = await import(pathToFileURL(process.env.HM_NODE_CLIENT_PATH).href);
const client = createAgentBridge({ socketPath: process.env.HM_TEST_SOCKET, secret: process.env.HM_TEST_SECRET });
const result = await client.sendEvent({ eventId: 'real_node_event_1234', sourceIp: '8.8.8.8', reasonCode: 'invalid_signature_burst', evidenceHash: 'a'.repeat(64), confidence: 90, ttlSeconds: 60 });
if (result.status !== 'observed') process.exit(2);
const snapshot = await client.activeBlocks();
if (snapshot.mode !== 'TEST' || snapshot.total !== 0) process.exit(3);
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "--input-type=module", "-e", script)
	cmd.Env = append(os.Environ(), "HM_NODE_CLIENT_PATH="+clientPath, "HM_TEST_SOCKET="+socket, "HM_TEST_SECRET="+secret)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real Node client: %v: %s", err, strings.TrimSpace(string(out)))
	}
	var status string
	if err := database.QueryRow(`SELECT status FROM node_edge_events WHERE event_id='real_node_event_1234'`).Scan(&status); err != nil || status != "observed" {
		t.Fatalf("agent audit: %s %v", status, err)
	}
}
