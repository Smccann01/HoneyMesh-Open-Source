package main

import (
	"testing"
	"time"
)

func TestTrustValidityUpdateCompletesForExistingPeer(t *testing.T) {
	initTrustStore()
	peer := "192.0.2.83:9000"
	before := getOrCreateTrust(peer).Valid
	done := make(chan struct{})
	go func() {
		updateTrustOnValidity([]string{peer}, true)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("valid peer update deadlocked")
	}
	if got := getOrCreateTrust(peer).Valid; got != before+1 {
		t.Fatalf("valid count = %d, want %d", got, before+1)
	}
}
