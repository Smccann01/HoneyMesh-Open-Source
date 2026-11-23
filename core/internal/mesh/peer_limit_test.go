package mesh

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDirectPeerAdmissionCapsJoinAndHeartbeat(t *testing.T) {
	oldSharing, oldToken, oldMax := SharingEnabled, ValidateJoinToken, MaxNodesAllowed
	oldCount, oldConfigured, oldCapability, oldSignal := PeerCount, PeerConfigured, ValidatePeerCapability, ValidateBanSignal
	defer func() {
		SharingEnabled, ValidateJoinToken, MaxNodesAllowed = oldSharing, oldToken, oldMax
		PeerCount, PeerConfigured, ValidatePeerCapability, ValidateBanSignal = oldCount, oldConfigured, oldCapability, oldSignal
	}()
	SharingEnabled = func() bool { return true }
	ValidateJoinToken = func(string) bool { return true }
	ValidatePeerCapability = nil
	ValidateBanSignal = nil
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
	beforeJoin := httptest.NewRequest(http.MethodPost, "/mesh/heartbeat", strings.NewReader(`{"addr":"10.0.0.1:9000"}`))
	beforeJoinResult := httptest.NewRecorder()
	s.handleHeartbeat(beforeJoinResult, beforeJoin)
	if beforeJoinResult.Code != http.StatusForbidden {
		t.Fatalf("unjoined peer heartbeat status = %d, want 403", beforeJoinResult.Code)
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
	admittedCert := &x509.Certificate{Raw: []byte("admitted test certificate")}
	unknownCert := &x509.Certificate{Raw: []byte("unknown test certificate")}
	banRequest := func(cert *x509.Certificate) int {
		req := httptest.NewRequest(http.MethodPost, "/mesh/ban", strings.NewReader(`{"ip":"1.2.3.4"}`))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		rec := httptest.NewRecorder()
		s.handleBan(rec, req)
		return rec.Code
	}
	admittedRequest := httptest.NewRequest(http.MethodPost, "/mesh/heartbeat", nil)
	admittedRequest.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{admittedCert}}
	s.recordPeerCertificate("10.0.0.1:9000", admittedRequest)
	var bans int
	s.onBan = func(string, BanSignal, time.Time) { bans++ }
	if got := banRequest(unknownCert); got != http.StatusForbidden || bans != 0 {
		t.Fatalf("unjoined certificate ban status = %d, callbacks = %d", got, bans)
	}
	if got := banRequest(admittedCert); got != http.StatusOK || bans != 1 {
		t.Fatalf("admitted certificate ban status = %d, callbacks = %d", got, bans)
	}
	MaxNodesAllowed = func() int { return 0 }
	if got := heartbeat("10.0.0.6:9000"); got != http.StatusOK {
		t.Fatalf("uncapped heartbeat status = %d", got)
	}
}
