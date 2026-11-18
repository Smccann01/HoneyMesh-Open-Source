package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"honeymesh/internal/license"
)

func TestMarketplaceLicenseRejectsNonHTTPS(t *testing.T) {
	previous := config.Marketplace
	defer func() { config.Marketplace = previous }()
	config.Marketplace = MarketplaceConfig{RefreshURL: "http://example.com/license", NodeToken: "test-token"}
	if err := refreshMarketplaceLicense(); err == nil {
		t.Fatal("HTTP refresh URL was accepted")
	}
}

func TestMarketplaceLicenseRevocationInvalidatesLocalPro(t *testing.T) {
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldDir)
	previousConfig, previousClient := config.Marketplace, marketplaceHTTPClient
	defer func() { config.Marketplace, marketplaceHTTPClient = previousConfig, previousClient }()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("bearer token missing")
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	marketplaceHTTPClient = server.Client()
	config.Marketplace = MarketplaceConfig{RefreshURL: server.URL, NodeToken: "test-token"}
	license.SetStateForTesting("pro", true, time.Now().Add(time.Hour), 2)
	if err := os.WriteFile(marketplaceLicensePath, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := refreshMarketplaceLicense(); err == nil {
		t.Fatal("revocation was accepted")
	}
	if license.PremiumEnabled() {
		t.Fatal("Pro remained enabled after revocation")
	}
	if _, err := os.Stat(marketplaceLicensePath); !os.IsNotExist(err) {
		t.Fatalf("old license remained: %v", err)
	}
}
