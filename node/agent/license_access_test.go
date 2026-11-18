package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"honeymesh/internal/license"
)

func TestTrustedNetworkSharingRequiresExplicitOptIn(t *testing.T) {
	previousFile := configFile
	configFile = t.TempDir() + "/honeymesh.json"
	defer func() { configFile = previousFile }()
	config = Config{}

	license.SetStateForTesting(license.TierFree, true, time.Now().Add(time.Hour), 0)
	if trustedNetworkSharingEnabled() {
		t.Fatal("sharing should start disabled")
	}
	if changed := setTrustedNetworkSharing(true); !changed || !trustedNetworkSharingEnabled() {
		t.Fatal("free tier explicit opt-in should activate sharing")
	}
	setTrustedNetworkSharing(false)

	license.SetStateForTesting(license.TierPro, true, time.Now().Add(time.Hour), 0)
	if trustedNetworkSharingEnabled() {
		t.Fatal("pro tier should still require explicit opt-in")
	}
	setTrustedNetworkSharing(true)
	if !trustedNetworkSharingEnabled() {
		t.Fatal("pro tier with opt-in should enable trusted network sharing")
	}

	config.TrustedMeshNetworkEnabled = true
	license.Invalidate()
	handleLicenseRuntimeStateChange()
	if !trustedMeshNetworkEnabled() {
		t.Fatal("legacy license expiration must not disable community mesh opt-in")
	}
	if premiumFeaturesEnabled() {
		t.Fatal("downgraded or invalid license should disable premium features")
	}
	if !config.TrustedNetworkSharingEnabled {
		t.Fatal("license state should not override explicit sharing opt-in")
	}
}

func TestSecurityAndHealthAPIsReflectLicenseState(t *testing.T) {
	origConfigFile := configFile
	configFile = t.TempDir() + "/honeymesh.json"
	defer func() { configFile = origConfigFile }()

	config = Config{
		NodeName:   "node-a",
		AdminToken: "secret",
		Security: SecurityConfig{
			AllowlistBase: boolPtr(true),
		},
	}
	remoteBanCache = map[string]time.Time{}
	remoteBanSources = map[string]map[string]struct{}{}

	if !strings.Contains(dashboardHTML, "Requires explicit mesh TLS trust and operator opt-in") {
		t.Fatal("dashboard should explain community mesh trust requirements")
	}
	if !strings.Contains(dashboardHTML, "JA4 / JA3 LEGACY") {
		t.Fatal("dashboard should expose JA4-first fingerprint labels")
	}
	if !strings.Contains(dashboardHTML, "Trusted Mesh Networks") {
		t.Fatal("dashboard should identify the trusted mesh controls")
	}

	license.SetStateForTesting(license.TierFree, true, time.Now().Add(time.Hour), 0)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	apiHealth(rec, req)
	var health map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health["license_label"] != "Community" {
		t.Fatalf("expected Community label, got %#v", health["license_label"])
	}
	if health["trusted_network_sharing_enabled"] != false {
		t.Fatalf("expected sharing off for Community, got %#v", health["trusted_network_sharing_enabled"])
	}

	req = httptest.NewRequest(http.MethodPost, "/api/security", strings.NewReader(`{"scan_ports":10,"scan_window_s":60,"allowlist_base":true,"trusted_peers":[],"whitelist":[],"trusted_network_sharing_enabled":true}`))
	req.Header.Set("X-Honey-Token", config.AdminToken)
	rec = httptest.NewRecorder()
	apiSecurity(rec, req)
	var sec securitySettings
	if err := json.Unmarshal(rec.Body.Bytes(), &sec); err != nil {
		t.Fatalf("decode security: %v", err)
	}
	if !sec.TrustedNetworkSharingEnabled {
		t.Fatal("Community mode should persist explicit sharing opt-in")
	}

	license.SetStateForTesting(license.TierPro, true, time.Now().Add(time.Hour), 0)
	setTrustedNetworkSharing(false)
	req = httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec = httptest.NewRecorder()
	apiHealth(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode pro health: %v", err)
	}
	if health["license_label"] != "Pro" {
		t.Fatalf("expected Pro label, got %#v", health["license_label"])
	}
	if health["trusted_network_sharing_enabled"] != false {
		t.Fatal("Pro without opt-in should keep trusted network sharing off")
	}

	setTrustedNetworkSharing(true)
	req = httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec = httptest.NewRecorder()
	apiHealth(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode pro sharing health: %v", err)
	}
	if health["trusted_network_sharing_enabled"] != true {
		t.Fatal("Pro with opt-in should report trusted network sharing enabled")
	}

	license.Invalidate()
	handleLicenseRuntimeStateChange()
	req = httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec = httptest.NewRecorder()
	apiHealth(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode downgraded health: %v", err)
	}
	if health["license_label"] != "Community" {
		t.Fatalf("expected Community after downgrade, got %#v", health["license_label"])
	}
	if health["trusted_network_sharing_enabled"] != true {
		t.Fatal("license state should not disable explicit sharing opt-in")
	}
}

func boolPtr(v bool) *bool {
	return &v
}
