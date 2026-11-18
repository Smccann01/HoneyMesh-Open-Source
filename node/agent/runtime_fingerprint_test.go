package main

import (
	"testing"
	"time"

	"honeymesh/internal/mesh"
)

func TestProcessEventJA4FirstDetection(t *testing.T) {
	testPaidHostLicense(t)
	resetFingerprintRuntimeState()
	GlobalMode = ModeEnforce
	config = Config{BindIP: "1.1.1.1", Traps: map[string]*TrapState{}}

	ja4 := "t13d0406h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
	addJA4Blacklist(ja4, time.Hour)

	processEvent(Event{
		Timestamp: time.Now().Format(time.RFC3339),
		Attacker:  "8.8.8.8",
		TargetIP:  "1.1.1.1",
		Target:    "443",
		Service:   "tcp",
		Type:      "OBS",
		Interface: "trap",
		JA4:       ja4,
	})

	if _, ok := banExpirations["8.8.8.8"]; !ok {
		t.Fatal("expected JA4-blacklisted event to trigger a ban")
	}
	if got := banMeta["8.8.8.8"].JA4; got != ja4 {
		t.Fatalf("expected JA4 ban metadata, got %q", got)
	}
}

func TestProcessEventJA3FallbackDetection(t *testing.T) {
	testPaidHostLicense(t)
	resetFingerprintRuntimeState()
	GlobalMode = ModeEnforce
	config = Config{BindIP: "1.1.1.1", Traps: map[string]*TrapState{}}

	ja3 := "0123456789abcdef0123456789abcdef"
	addJA3Blacklist(ja3, time.Hour)

	processEvent(Event{
		Timestamp: time.Now().Format(time.RFC3339),
		Attacker:  "9.9.9.9",
		TargetIP:  "1.1.1.1",
		Target:    "443",
		Service:   "tcp",
		Type:      "OBS",
		Interface: "trap",
		JA3:       ja3,
	})

	if _, ok := banExpirations["9.9.9.9"]; !ok {
		t.Fatal("expected JA3 fallback event to trigger a ban")
	}
	if got := banMeta["9.9.9.9"].JA3; got != ja3 {
		t.Fatalf("expected JA3 ban metadata, got %q", got)
	}
}

func TestEmitRemoteMeshSignalAddsStructuredEvent(t *testing.T) {
	resetFingerprintRuntimeState()
	config = Config{BindIP: "1.1.1.1", Traps: map[string]*TrapState{}}
	logChan = make(chan Event, 4)
	shutdown := make(chan struct{})
	go startLogWorker(shutdown)
	defer close(shutdown)

	emitRemoteMeshSignal("peer-a:9000", mesh.BanSignal{
		IP:        "7.7.7.7",
		Reason:    "mesh intel",
		JA4:       "t13d0406h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
		JA3:       "0123456789abcdef0123456789abcdef",
		Service:   "tcp",
		EventType: "MESH_INTEL",
	}, time.Now())

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		events := snapshotEvents(5)
		if len(events) > 0 {
			last := events[len(events)-1]
			if last.JA4 == "" || last.Type != "MESH_INTEL" || last.Interface != "mesh" {
				t.Fatalf("unexpected remote mesh event: %+v", last)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected remote mesh signal to appear in the event log")
}

func resetFingerprintRuntimeState() {
	banExpirations = make(map[string]time.Time)
	banMeta = make(map[string]BanMeta)
	lastJA4ByIP = make(map[string]string)
	lastJA3ByIP = make(map[string]string)
	scanCounts = make(map[string]map[string]time.Time)
	trapHitCounts = make(map[string][]time.Time)
	ja4Blacklist = make(map[string]time.Time)
	ja3Blacklist = make(map[string]time.Time)
	remoteBanCache = make(map[string]time.Time)
	remoteBanSources = make(map[string]map[string]struct{})
	allowCIDRs = nil
	whitelistCIDRs = nil
	trustedCIDRs = nil
	eventLog = nil
	eventIdx = 0
	eventCnt = 0
	db = nil
	scp = nil
	bpfObjs.BanMap = nil
	bpfObjs.BanMapV6 = nil
}
