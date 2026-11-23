package main

import (
	"testing"
	"time"

	"honeymesh/internal/license"
)

func TestCommunityDirectPeerLimitKeepsPrivateConfig(t *testing.T) {
	oldConfig := config
	tier, valid, expiry, nodes := license.Tier(), license.Valid(), license.ExpiresAt(), license.MaxNodes()
	defer func() {
		config = oldConfig
		license.SetStateForTesting(tier, valid, expiry, nodes)
	}()
	license.SetStateForTesting(license.TierFree, true, time.Now().Add(time.Hour), 0)
	config = Config{}
	config.Mesh.Peers = []string{
		"10.0.0.1:9000", "10.0.0.2:9000", "10.0.0.3:9000",
		"10.0.0.4:9000", "10.0.0.5:9000", "10.0.0.6:9000",
		"10.0.0.1:9000", // duplicate must not consume a slot
	}
	if max := meshMaxNodesAllowed(); max != 6 {
		t.Fatalf("Community max nodes = %d, want local node plus five peers", max)
	}
	if got := activeMeshPeers(); len(got) != 5 {
		t.Fatalf("Community active peers = %v, want five", got)
	}
	if activeMeshPeerConfigured("10.0.0.6:9000") {
		t.Fatal("sixth configured peer should remain saved but inactive")
	}
	if len(config.Mesh.Peers) != 7 {
		t.Fatal("peer selection should not erase saved configuration")
	}
	license.SetStateForTesting(license.TierPro, true, time.Now().Add(time.Hour), 0)
	if max := meshMaxNodesAllowed(); max != 0 {
		t.Fatalf("unlimited Pro mesh max nodes = %d", max)
	}
	if got := activeMeshPeers(); len(got) != 6 {
		t.Fatalf("Pro active peers = %v, want six distinct peers", got)
	}
	license.SetStateForTesting(license.TierPro, true, time.Now().Add(time.Hour), 3)
	if got := activeMeshPeers(); len(got) != 2 {
		t.Fatalf("three-node Pro license selected %v, want two direct peers", got)
	}
}
