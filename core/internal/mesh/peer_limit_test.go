package mesh

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDirectPeerAdmissionCapsJoinAndHeartbeat(t *testing.T) {
	oldSharing, oldToken, oldMax := SharingEnabled, ValidateJoinToken, MaxNodesAllowed
	oldCount, oldConfigured, oldCapability := PeerCount, PeerConfigured, ValidatePeerCapability
	defer func() {
		SharingEnabled, ValidateJoinToken, MaxNodesAllowed = oldSharing, oldToken, oldMax
		PeerCount, PeerConfigured, ValidatePeerCapability = oldCount, oldConfigured, oldCapability
	}()
	SharingEnabled = func() bool { return true }
	ValidateJoinToken = func(string) bool { return true }
	ValidatePeerCapability = nil
	MaxNodesAllowed = func() int { return 6 } // local node plus five direct peers
	configured := make(map[string]struct{})
	PeerCount = func() int { return len(configured) }
	PeerConfigured = func(peer string) bool {
		_, ok := configured[normalizePeer(peer)]
		return ok
	}
	s := &Server{
		peers: make(map[string]time.Time), peersKnown: make(map[string]time.Time),
		stats: make(map[string]PeerStats), caps: make(map[string]PeerCapability),
		peerCerts: make(map[string]string),
		onPeer:    func(peer string) { configured[normalizePeer(peer)] = struct{}{} },
	}
	join := func(addr string) int {
		req := httptest.NewRequest(http.MethodPost, "/mesh/join", strings.NewReader(fmt.Sprintf(`{"token":"t","addr":%q}`, addr)))
		rec := httptest.NewRecorder()
		s.handleJoin(rec, req)
		return rec.Code
	}
	for i := 1; i <= 5; i++ {
		if got := join(fmt.Sprintf("10.0.0.%d:9000", i)); got != http.StatusOK {
			t.Fatalf("peer %d join status = %d", i, got)
		}
	}
	if got := join("10.0.0.6:9000"); got != http.StatusForbidden {
		t.Fatalf("sixth peer join status = %d, want 403", got)
	}
	if got := join("10.0.0.1:9000"); got != http.StatusOK {
		t.Fatalf("existing peer rejoin status = %d", got)
	}
	heartbeat := func(addr string) int {
		req := httptest.NewRequest(http.MethodPost, "/mesh/heartbeat", strings.NewReader(fmt.Sprintf(`{"addr":%q}`, addr)))
		rec := httptest.NewRecorder()
		s.handleHeartbeat(rec, req)
		return rec.Code
	}
	if got := heartbeat("10.0.0.6:9000"); got != http.StatusForbidden {
		t.Fatalf("sixth peer heartbeat status = %d, want 403", got)
	}
	if got := heartbeat("10.0.0.1:9000"); got != http.StatusOK {
		t.Fatalf("existing peer heartbeat status = %d", got)
	}
	MaxNodesAllowed = func() int { return 0 }
	if got := heartbeat("10.0.0.6:9000"); got != http.StatusOK {
		t.Fatalf("uncapped heartbeat status = %d", got)
	}
}
