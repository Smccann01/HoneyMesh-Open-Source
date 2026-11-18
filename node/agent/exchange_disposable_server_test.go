package main

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
)

// This opt-in test talks to a disposable Exchange process created by the
// Exchange repository's discovery suite. It exercises the real Go signer and
// response verifier against the real Next.js route, without a packet rule.
func TestExchangeDisposableServerContract(t *testing.T) {
	origin := os.Getenv("HM_EXCHANGE_TEST_ORIGIN")
	if origin == "" {
		t.Skip("set HM_EXCHANGE_TEST_ORIGIN from the disposable Exchange suite")
	}
	nodeID := os.Getenv("HM_EXCHANGE_TEST_NODE_ID")
	secret := os.Getenv("HM_EXCHANGE_TEST_SECRET")
	expected := strings.Split(os.Getenv("HM_EXCHANGE_TEST_IPS"), ",")
	if nodeID == "" || secret == "" || len(expected) == 0 || expected[0] == "" {
		t.Fatal("disposable Exchange test credentials and expected IPs required")
	}
	prior := config.Exchange
	t.Cleanup(func() { config.Exchange = prior })
	config.Exchange.BaseURL = origin
	config.Exchange.NodeID = nodeID
	config.Exchange.SharedSecret = secret
	body, status, err := doExchangeRequest(http.MethodGet, "/api/hm/attack-snapshot?trustThreshold=50", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("signed snapshot failed: status=%d err=%v", status, err)
	}
	var snapshot exchangeSnapshotResponse
	if err := json.Unmarshal(body, &snapshot); err != nil || !snapshot.Complete {
		t.Fatalf("incomplete snapshot: %v", err)
	}
	got := make([]string, 0, len(snapshot.Records))
	for _, record := range snapshot.Records {
		got = append(got, record.AttackerIP)
	}
	sort.Strings(got)
	sort.Strings(expected)
	if strings.Join(got, ",") != strings.Join(expected, ",") {
		t.Fatalf("snapshot IPs=%v expected=%v", got, expected)
	}
	body, status, err = doExchangeRequest(http.MethodGet, "/api/hm/attack-feed?limit=50&retractionAfter=0", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("signed feed failed: status=%d err=%v", status, err)
	}
	var feed exchangeFeedResponse
	if err := json.Unmarshal(body, &feed); err != nil {
		t.Fatal(err)
	}
	if len(feed.MergedFeed) != len(expected) {
		t.Fatalf("feed count=%d expected=%d", len(feed.MergedFeed), len(expected))
	}
	if wantRetraction := os.Getenv("HM_EXCHANGE_TEST_RETRACTED") == "true"; wantRetraction != (len(feed.Retractions) == 1) {
		t.Fatalf("retraction state mismatch: count=%d expected=%t", len(feed.Retractions), wantRetraction)
	}
}
