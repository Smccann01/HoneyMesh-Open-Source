package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestNodeProEntitlementScopeSignatureAndExpiry(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	doc := &NodeEntitlement{SchemaVersion: 1, Product: "node_pro", SubscriptionID: "sub_test_1",
		UnitID: "host_0123456789abcdef01234567", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	payload := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", nodeEntitlementDomain, doc.Product,
		doc.SubscriptionID, doc.UnitID, doc.ExpiresAt)
	doc.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(payload)))
	bytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseNodeProEntitlement(bytes)
	if err != nil {
		t.Fatal(err)
	}
	keys := []ed25519.PublicKey{public}
	if err := verifyNodeProEntitlementWithKeys(parsed, doc.UnitID, now, keys); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*NodeEntitlement){
		"wrong product":     func(d *NodeEntitlement) { d.Product = "node_guard" },
		"wrong unit":        func(d *NodeEntitlement) { d.UnitID = "host_ffffffffffffffffffffffff" },
		"modified expiry":   func(d *NodeEntitlement) { d.ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339) },
		"invalid signature": func(d *NodeEntitlement) { d.Signature = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *parsed
			mutate(&copy)
			if err := verifyNodeProEntitlementWithKeys(&copy, doc.UnitID, now, keys); err == nil {
				t.Fatal("invalid entitlement accepted")
			}
		})
	}
	if err := verifyNodeProEntitlementWithKeys(parsed, doc.UnitID, now.Add(time.Hour), keys); err == nil {
		t.Fatal("expired entitlement accepted")
	}
	if _, err := ParseNodeProEntitlement(append(bytes, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing document accepted")
	}
}

func TestExternalNodeEntitlementCompatibility(t *testing.T) {
	path := os.Getenv("HM_TEST_NODE_ENTITLEMENT_PATH")
	publicPath := os.Getenv("HM_TEST_NODE_ENTITLEMENT_PUBLIC_PEM")
	unitID := os.Getenv("HM_TEST_NODE_ENTITLEMENT_UNIT_ID")
	if path == "" || publicPath == "" || unitID == "" {
		t.Skip("set cross-language Node entitlement fixture paths")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	document, err := ParseNodeProEntitlement(data)
	if err != nil {
		t.Fatal(err)
	}
	pemData, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	public, err := parsePublicKey(string(pemData))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyNodeProEntitlementWithKeys(document, unitID, time.Now(), []ed25519.PublicKey{public}); err != nil {
		t.Fatal(err)
	}
}
