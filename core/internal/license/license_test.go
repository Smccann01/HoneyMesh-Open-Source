package license

import (
	"os"
	"testing"
	"time"
)

func TestExternalSignedLicenseCompatibility(t *testing.T) {
	path := os.Getenv("HM_TEST_SIGNED_LICENSE_PATH")
	if path == "" {
		t.Skip("set HM_TEST_SIGNED_LICENSE_PATH to verify a website-signed license")
	}
	document, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLicense(document); err != nil {
		t.Fatal(err)
	}
	tampered := *document
	tampered.MaxNodes++
	if err := VerifyLicense(&tampered); err == nil {
		t.Fatal("modified node limit retained a valid signature")
	}
}

func TestTrustedLicensePublicKeysAreValid(t *testing.T) {
	if len(trustedPublicKeyPEMs) != 2 {
		t.Fatalf("trusted signer count = %d, want 2", len(trustedPublicKeyPEMs))
	}
	for i, key := range trustedPublicKeyPEMs {
		if _, err := parsePublicKey(key); err != nil {
			t.Fatalf("trusted signer %d: %v", i, err)
		}
	}
}

func TestNormalizeTier(t *testing.T) {
	cases := map[string]string{
		"":           TierFree,
		"free":       TierFree,
		"community":  TierFree,
		"trial":      TierFree,
		"pro":        TierPro,
		"enterprise": TierPro,
		"weird":      TierFree,
	}

	for in, want := range cases {
		if got := NormalizeTier(in); got != want {
			t.Fatalf("NormalizeTier(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPremiumEnabledFollowsSimplifiedModel(t *testing.T) {
	SetStateForTesting(TierFree, true, time.Now().Add(time.Hour), 0)
	if PremiumEnabled() {
		t.Fatal("free tier should not enable premium features")
	}

	SetStateForTesting(TierPro, true, time.Now().Add(time.Hour), 0)
	if !PremiumEnabled() {
		t.Fatal("pro tier should enable premium features when valid")
	}

	SetStateForTesting(TierPro, false, time.Now().Add(time.Hour), 0)
	if PremiumEnabled() {
		t.Fatal("invalid pro tier should disable premium features")
	}

	Invalidate()
	if Tier() != TierFree {
		t.Fatalf("Invalidate should force free tier, got %q", Tier())
	}
	if PremiumEnabled() {
		t.Fatal("Invalidate should disable premium features")
	}
}
