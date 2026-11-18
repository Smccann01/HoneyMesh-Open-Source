package main

import (
	"testing"
	"time"
)

func TestRemoteSignalCannotCreateRuleInTestMode(t *testing.T) {
	previousMode := Mode()
	previousBans, previousRemote := banExpirations, remoteBanCache
	defer func() {
		banExpirations, remoteBanCache = previousBans, previousRemote
		_ = SetMode(previousMode)
	}()
	banExpirations = make(map[string]time.Time)
	remoteBanCache = make(map[string]time.Time)
	if err := SetMode(ModeTest); err != nil {
		t.Fatal(err)
	}
	applyRemoteBanWithTTL("192.0.2.77", "test observation", nil, "", "", time.Minute, "REMOTE_MESH")
	if len(banExpirations) != 0 || len(remoteBanCache) != 0 {
		t.Fatalf("TEST retained remote enforcement: bans=%v remote=%v", banExpirations, remoteBanCache)
	}
}
