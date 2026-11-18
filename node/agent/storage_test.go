package main

import (
	"database/sql"
	"testing"
)

func TestStoreEventPersistsJA4AndJA3(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() {
		_ = db.Close()
		db = nil
	}()

	createTables()
	storeEvent(Event{
		Timestamp:                "2026-03-21T00:00:00Z",
		Attacker:                 "8.8.8.8",
		TargetIP:                 "1.1.1.1",
		Target:                   "443",
		Service:                  "tcp",
		Type:                     "TRAP",
		Interface:                "trap",
		JA4:                      "t13d0406h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
		JA3:                      "0123456789abcdef0123456789abcdef",
		TLSFingerprintFamily:     "ja4",
		TLSFingerprintVersion:    "ja4",
		TLSFingerprintConfidence: 100,
	})

	var ja4, ja3, family, version string
	var confidence int
	if err := db.QueryRow(`SELECT ja4, ja3, tls_fingerprint_family, tls_fingerprint_version, tls_fingerprint_confidence FROM events LIMIT 1`).Scan(
		&ja4, &ja3, &family, &version, &confidence,
	); err != nil {
		t.Fatalf("query stored event: %v", err)
	}

	if ja4 == "" || ja3 == "" {
		t.Fatalf("expected dual-write fingerprints, got ja4=%q ja3=%q", ja4, ja3)
	}
	if family != "ja4" || version != "ja4" || confidence != 100 {
		t.Fatalf("unexpected stored fingerprint metadata: family=%q version=%q confidence=%d", family, version, confidence)
	}
}
