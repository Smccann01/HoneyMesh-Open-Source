package main

import (
	"encoding/hex"
	"testing"
)

func TestGenerateAdminToken(t *testing.T) {
	first, err := generateAdminToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateAdminToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 64 || first == second {
		t.Fatal("admin tokens must be unique 256-bit values")
	}
	if _, err := hex.DecodeString(first); err != nil {
		t.Fatal(err)
	}
}
