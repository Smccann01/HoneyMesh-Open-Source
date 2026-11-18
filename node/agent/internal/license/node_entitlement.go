package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const nodeEntitlementDomain = "HoneyMesh-Node-Entitlement-v1"

var nodeSubscriptionID = regexp.MustCompile(`^sub_[A-Za-z0-9_]+$`)
var nodeHostUnitID = regexp.MustCompile(`^host_[a-f0-9]{24}$`)
var nodeExpiry = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`)

type NodeEntitlement struct {
	SchemaVersion  int    `json:"schema_version"`
	Product        string `json:"product"`
	SubscriptionID string `json:"subscription_id"`
	UnitID         string `json:"unit_id"`
	ExpiresAt      string `json:"expires_at"`
	Signature      string `json:"signature"`
}

func ParseNodeProEntitlement(data []byte) (*NodeEntitlement, error) {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var document NodeEntitlement
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("node entitlement has trailing data")
	}
	return &document, nil
}

func VerifyNodeProEntitlement(document *NodeEntitlement, expectedUnitID string, now time.Time) error {
	keys := make([]ed25519.PublicKey, 0, len(trustedPublicKeyPEMs))
	for _, key := range trustedPublicKeyPEMs {
		public, err := parsePublicKey(key)
		if err != nil {
			return err
		}
		keys = append(keys, public)
	}
	return verifyNodeProEntitlementWithKeys(document, expectedUnitID, now, keys)
}

func verifyNodeProEntitlementWithKeys(document *NodeEntitlement, expectedUnitID string, now time.Time, keys []ed25519.PublicKey) error {
	if document == nil || document.SchemaVersion != 1 || document.Product != "node_pro" ||
		!nodeSubscriptionID.MatchString(document.SubscriptionID) || !nodeHostUnitID.MatchString(document.UnitID) ||
		!nodeHostUnitID.MatchString(expectedUnitID) || document.UnitID != expectedUnitID || !nodeExpiry.MatchString(document.ExpiresAt) {
		return errors.New("node pro entitlement scope invalid")
	}
	expires, err := time.Parse(time.RFC3339, document.ExpiresAt)
	if err != nil || !expires.After(now) {
		return errors.New("node pro entitlement expired or invalid")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(document.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("node pro entitlement signature invalid")
	}
	payload := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", nodeEntitlementDomain, document.Product,
		document.SubscriptionID, document.UnitID, document.ExpiresAt)
	for _, key := range keys {
		if ed25519.Verify(key, []byte(payload), signature) {
			return nil
		}
	}
	return errors.New("node pro entitlement signature invalid")
}
