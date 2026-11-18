package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"honeymesh/internal/license"
	"honeymesh/internal/mesh"
)

func TestValidatePeerCapabilityAllowsCommunitySharing(t *testing.T) {
	resetFederationSecurityState()
	oldVerify := verifyPeerLicenseClaim
	verifyPeerLicenseClaim = func(cap mesh.PeerCapability) error { return nil }
	defer func() { verifyPeerLicenseClaim = oldVerify }()

	pub, _, _ := ed25519.GenerateKey(nil)
	nodeID := deriveNodeID(pub)

	freeCap := mesh.PeerCapability{
		SchemaVersion:         federationSchemaVersion,
		NodeID:                nodeID,
		LicenseTier:           license.TierFree,
		TrustedNetworkSharing: true,
		PublicKey:             base64.StdEncoding.EncodeToString(pub),
		Capabilities:          []string{"trusted_network_sharing"},
	}
	if err := validatePeerCapability(freeCap); err != nil {
		t.Fatalf("expected community capability to be accepted, got %v", err)
	}

	proNoShare := freeCap
	proNoShare.LicenseTier = license.TierPro
	proNoShare.TrustedNetworkSharing = false
	if err := validatePeerCapability(proNoShare); err == nil || err.Error() != "sharing_disabled" {
		t.Fatalf("expected sharing_disabled, got %v", err)
	}
}

func TestCommunityPeerRequiresConfiguredClusterTrust(t *testing.T) {
	previous := license.GetOrGenerateClusterID()
	t.Chdir(t.TempDir())
	if err := license.SetClusterID("community-cluster"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = license.SetClusterID(previous) })
	cap := mesh.PeerCapability{ClusterID: "community-cluster", LicenseTier: license.TierFree}
	if err := defaultVerifyPeerLicenseClaim(cap); err != nil {
		t.Fatalf("same-cluster community peer rejected: %v", err)
	}
	cap.ClusterID = "other-cluster"
	if err := defaultVerifyPeerLicenseClaim(cap); err == nil {
		t.Fatal("untrusted community cluster accepted")
	}
	cap.ClusterID = ""
	if err := defaultVerifyPeerLicenseClaim(cap); err == nil {
		t.Fatal("peer without cluster identity accepted")
	}
}

func TestValidateTrustedNetworkSignalRejectsInvalidSignature(t *testing.T) {
	resetFederationSecurityState()
	oldVerify := verifyPeerLicenseClaim
	verifyPeerLicenseClaim = func(cap mesh.PeerCapability) error { return nil }
	defer func() { verifyPeerLicenseClaim = oldVerify }()

	signal := signedTestSignal(t, "evt-1", time.Now().UTC())
	signal.Signature = "not-valid"
	if err := validateTrustedNetworkSignal("peer-a:9000", signal); err == nil || err.Error() != "invalid_signature" {
		t.Fatalf("expected invalid_signature, got %v", err)
	}
}

func TestValidateTrustedNetworkSignalRejectsLegacyOrUnversionedPayloads(t *testing.T) {
	resetFederationSecurityState()
	oldVerify := verifyPeerLicenseClaim
	verifyPeerLicenseClaim = func(cap mesh.PeerCapability) error { return nil }
	defer func() { verifyPeerLicenseClaim = oldVerify }()

	legacy := signedTestSignal(t, "evt-legacy", time.Now().UTC())
	legacy.SchemaVersion = "v1"
	if err := validateTrustedNetworkSignal("peer-a:9000", legacy); err == nil || err.Error() != "schema_mismatch" {
		t.Fatalf("expected schema_mismatch for v1 payload, got %v", err)
	}

	unversioned := signedTestSignal(t, "evt-unversioned", time.Now().UTC())
	unversioned.SchemaVersion = ""
	if err := validateTrustedNetworkSignal("peer-a:9000", unversioned); err == nil || err.Error() != "schema_mismatch" {
		t.Fatalf("expected schema_mismatch for unversioned payload, got %v", err)
	}
}

func TestValidateTrustedNetworkSignalRejectsReplay(t *testing.T) {
	resetFederationSecurityState()
	oldVerify := verifyPeerLicenseClaim
	verifyPeerLicenseClaim = func(cap mesh.PeerCapability) error { return nil }
	defer func() { verifyPeerLicenseClaim = oldVerify }()

	now := time.Now().UTC()
	signal := signedTestSignal(t, "evt-replay", now)
	if err := validateTrustedNetworkSignal("peer-a:9000", signal); err != nil {
		t.Fatalf("first signal rejected: %v", err)
	}
	if err := validateTrustedNetworkSignal("peer-a:9000", signal); err == nil || err.Error() != "replay_detected" {
		t.Fatalf("expected replay_detected, got %v", err)
	}
}

func TestValidateTrustedNetworkSignalRateLimitsPublisher(t *testing.T) {
	resetFederationSecurityState()
	oldVerify := verifyPeerLicenseClaim
	verifyPeerLicenseClaim = func(cap mesh.PeerCapability) error { return nil }
	defer func() { verifyPeerLicenseClaim = oldVerify }()

	oldBurst := config.Security.MeshEventBurst
	oldPerMin := config.Security.MeshEventRateLimitPerMin
	config.Security.MeshEventBurst = 2
	config.Security.MeshEventRateLimitPerMin = 10
	defer func() {
		config.Security.MeshEventBurst = oldBurst
		config.Security.MeshEventRateLimitPerMin = oldPerMin
	}()

	now := time.Now().UTC()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	for i := 0; i < 2; i++ {
		signal := signedTestSignalWithKey(t, pub, priv, "evt-burst-"+string(rune('a'+i)), now)
		if err := validateTrustedNetworkSignal("peer-a:9000", signal); err != nil {
			t.Fatalf("signal %d rejected unexpectedly: %v", i, err)
		}
	}
	signal := signedTestSignalWithKey(t, pub, priv, "evt-burst-c", now)
	if err := validateTrustedNetworkSignal("peer-a:9000", signal); err == nil || err.Error() != "rate_limit_exceeded" {
		t.Fatalf("expected rate_limit_exceeded, got %v", err)
	}
}

func TestPrepareTrustedNetworkSignalAppliesClassification(t *testing.T) {
	resetFederationSecurityState()
	pub, priv, _ := ed25519.GenerateKey(nil)
	setNodeIdentity(nodeIdentityState{
		NodeID:     deriveNodeID(pub),
		PublicKey:  pub,
		PrivateKey: priv,
	})

	oldTier := config.LicenseTier
	oldSharing := config.TrustedMeshNetworkEnabled
	oldClass := config.Security.MeshDataClassification
	license.SetStateForTesting(license.TierPro, true, time.Now().Add(time.Hour), 0)
	config.LicenseTier = license.TierPro
	config.TrustedMeshNetworkEnabled = true
	config.Security.MeshDataClassification = "L2"
	defer func() {
		config.LicenseTier = oldTier
		config.TrustedMeshNetworkEnabled = oldSharing
		config.Security.MeshDataClassification = oldClass
	}()

	signal, err := prepareTrustedNetworkSignal(mesh.BanSignal{
		IP:       "1.2.3.4",
		Reason:   "payload anomaly",
		TargetIP: "10.0.0.4",
		Payload:  "raw evidence",
	})
	if err != nil {
		t.Fatalf("prepareTrustedNetworkSignal: %v", err)
	}
	if signal.TargetIP != "" {
		t.Fatalf("expected L2 classification to omit target_ip, got %q", signal.TargetIP)
	}
	if signal.Payload != "" {
		t.Fatalf("expected L2 classification to omit payload, got %q", signal.Payload)
	}
	if signal.Signature == "" {
		t.Fatal("expected signed trusted network signal")
	}
}

func signedTestSignal(t *testing.T, eventID string, publishedAt time.Time) mesh.BanSignal {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return signedTestSignalWithKey(t, pub, priv, eventID, publishedAt)
}

func signedTestSignalWithKey(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, eventID string, publishedAt time.Time) mesh.BanSignal {
	t.Helper()
	nodeID := deriveNodeID(pub)
	signal := mesh.BanSignal{
		SchemaVersion:      federationSchemaVersion,
		EventID:            eventID,
		PublisherNodeID:    nodeID,
		PublishedAt:        publishedAt.Format(time.RFC3339),
		DataClassification: "L2",
		Capability: mesh.PeerCapability{
			SchemaVersion:         federationSchemaVersion,
			NodeID:                nodeID,
			ClusterID:             "cluster-a",
			TenantID:              "cluster-a",
			LicenseTier:           license.TierPro,
			LicenseExpiresAt:      publishedAt.Add(time.Hour).Format(time.RFC3339),
			LicenseMaxNodes:       10,
			LicenseSignature:      "test",
			TrustedNetworkSharing: true,
			PublicKey:             base64.StdEncoding.EncodeToString(pub),
			Capabilities:          []string{"trusted_network_sharing"},
		},
		IP:  "1.2.3.4",
		JA4: "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
	}
	signature, err := signBanSignal(priv, signal)
	if err != nil {
		t.Fatalf("signBanSignal: %v", err)
	}
	signal.Signature = signature
	return signal
}
