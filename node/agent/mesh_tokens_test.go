package main

import (
	"testing"
	"time"
)

func TestExpiredJoinTokenCannotBeUsed(t *testing.T) {
	previous := stateDir
	stateDir = t.TempDir()
	t.Cleanup(func() { stateDir = previous })
	if err := addJoinToken("expired-test-token", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if validateAndUseJoinToken("expired-test-token") {
		t.Fatal("expired join token was accepted")
	}
}
