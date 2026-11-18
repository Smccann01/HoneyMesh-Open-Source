package license

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

type LicenseFile struct {
	ClusterID string    `json:"cluster_id"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxNodes  int       `json:"max_nodes"`
	Tier      string    `json:"tier"`
	Signature string    `json:"signature"`
}

// VerifySignature is a placeholder for license signature verification.
func VerifySignature(data []byte, sig []byte) bool {
	for _, pemText := range trustedPublicKeyPEMs {
		pub, err := parsePublicKey(pemText)
		if err == nil && ed25519.Verify(pub, data, sig) {
			return true
		}
	}
	return false
}

// Load parses license file and extracts max nodes.
func Load(path string) (*LicenseFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lf LicenseFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, err
	}
	return &lf, nil
}

func VerifyLicense(lf *LicenseFile) error {
	if lf == nil {
		return fmt.Errorf("nil license")
	}
	if lf.Signature == "" {
		return fmt.Errorf("missing signature")
	}
	payload := buildLicensePayload(lf)
	sig, err := base64.StdEncoding.DecodeString(lf.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	if !VerifySignature([]byte(payload), sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func buildLicensePayload(lf *LicenseFile) string {
	tier := strings.ToUpper(NormalizeTier(lf.Tier))
	return fmt.Sprintf("%s|%s|%d|%s", lf.ClusterID, lf.ExpiresAt.Format(time.RFC3339), lf.MaxNodes, tier)
}

func parsePublicKey(pemText string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("invalid public key pem")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not ed25519 public key")
	}
	return pub, nil
}
