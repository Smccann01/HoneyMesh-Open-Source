package main

import (
	"time"

	"honeymesh/internal/mesh"
)

func emitRemoteMeshSignal(peer string, signal mesh.BanSignal, observedAt time.Time) {
	if signal.IP == "" {
		return
	}
	ts := observedAt
	if ts.IsZero() {
		ts = time.Now()
	}
	eventType := signal.EventType
	if eventType == "" {
		eventType = "MESH_INTEL"
	}
	payload := signal.Payload
	if payload == "" {
		payload = signal.Reason
	}
	family := "ja4"
	version := "ja4"
	confidence := 100
	if normalizeJA4(signal.JA4) == "" && normalizeJA3Key(signal.JA3) != "" {
		family = "ja3"
		version = "ja3"
		confidence = 70
	}

	emitEvent(Event{
		Timestamp:                ts.Format(time.RFC3339),
		Attacker:                 signal.IP,
		TargetIP:                 signal.TargetIP,
		Target:                   signal.Target,
		Service:                  signal.Service,
		Node:                     peer,
		Type:                     eventType,
		Payload:                  sanitizePayload([]byte(payload), 200),
		Interface:                "mesh",
		JA4:                      normalizeJA4(signal.JA4),
		JA3:                      normalizeJA3Key(signal.JA3),
		TLSFingerprintFamily:     family,
		TLSFingerprintVersion:    version,
		TLSFingerprintConfidence: confidence,
	})
}
