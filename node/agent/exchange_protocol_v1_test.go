package main

import "testing"

func TestExchangeProtocolV1CrossLanguageVector(t *testing.T) {
	prior := config.Exchange
	t.Cleanup(func() { config.Exchange = prior })
	config.Exchange.SharedSecret = "hm-protocol-v1-test-secret-not-production"
	stamp := "2026-11-05T08:00:00.000Z"
	body := []byte(`{"attackerIp":"203.0.113.7","ttl":120}`)
	hash := "4965071b54371dbea99d28cf19853f2d6eafefbf4492c8b4ec1b91ed866467b7"
	if got := exchangeBodyHash(body); got != hash {
		t.Fatalf("body hash mismatch: %s", got)
	}
	if got := exchangeSignature("POST", "/api/hm/publish-ban?sample=1", stamp, "fixture-nonce-001", body); got !=
		"c6a80cc213d54ac15618634c9ca4a2c798cbb71ad1f526297a0c331c79f5eaed" {
		t.Fatalf("request signature mismatch: %s", got)
	}
	if got := exchangeResponseSignature(200, stamp, hash); got !=
		"eeee4b1733fa1cf824fbf046675c4b269ef500428e9288483801ad587d8f7952" {
		t.Fatalf("response signature mismatch: %s", got)
	}
}
