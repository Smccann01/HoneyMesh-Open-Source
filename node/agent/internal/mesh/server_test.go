package mesh

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMeshPeerURLRequiresIPLiteral(t *testing.T) {
	valid := map[string]string{
		"10.0.0.2":       "https://10.0.0.2:9000/mesh/join",
		"10.0.0.2:9443":  "https://10.0.0.2:9443/mesh/join",
		"[fd00::2]:9000": "https://[fd00::2]:9000/mesh/join",
	}
	for peer, want := range valid {
		got, err := meshPeerURL(peer, "/mesh/join")
		if err != nil || got != want {
			t.Errorf("meshPeerURL(%q) = %q, %v; want %q", peer, got, err, want)
		}
	}
	for _, peer := range []string{"", "localhost:9000", "https://10.0.0.2:9000", "10.0.0.2@evil.example", "10.0.0.2/other", "10.0.0.2:0", "0.0.0.0:9000", "224.0.0.1:9000", "[fe80::1%eth0]:9000"} {
		if _, err := meshPeerURL(peer, "/mesh/join"); err == nil {
			t.Errorf("meshPeerURL(%q) accepted an invalid peer", peer)
		}
	}
}

func TestJoinRejectsInjectedPeerBeforeSendingToken(t *testing.T) {
	var calls atomic.Int32
	s := &Server{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, fmt.Errorf("unexpected network request")
	})}}
	if err := s.Join("10.0.0.2@evil.example", "private-test-token", "10.0.0.3:9000"); err == nil {
		t.Fatal("join accepted an injected peer authority")
	}
	if calls.Load() != 0 {
		t.Fatal("join sent its token before validating the peer")
	}
}

func TestRevokedPeerCertificateRejectedAfterRestart(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("test peer certificate")}
	request := httptest.NewRequest(http.MethodPost, "/mesh/heartbeat", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	s := &Server{peers: map[string]time.Time{}, peersKnown: map[string]time.Time{}, peerCerts: map[string]string{}, revokedCerts: map[string]struct{}{}}
	s.recordPeerCertificate("10.0.0.2:9000", request)
	fingerprint, ok := s.RevokePeer("10.0.0.2:9000")
	if !ok || fingerprint == "" || !s.isRevokedCertificate(request) {
		t.Fatal("revoked certificate remained usable")
	}
	restarted := &Server{revokedCerts: map[string]struct{}{fingerprint: {}}}
	if !restarted.isRevokedCertificate(request) {
		t.Fatal("persisted revocation was not applied after restart")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestHandleBanRequiresTrustedNetworkSharing(t *testing.T) {
	s := &Server{}
	var calls atomic.Int32
	var gotJA4, gotJA3 string
	s.onBan = func(peer string, signal BanSignal, observedAt time.Time) {
		calls.Add(1)
		gotJA4 = signal.JA4
		gotJA3 = signal.JA3
	}

	SharingEnabled = func() bool { return false }
	req := httptest.NewRequest(http.MethodPost, "/mesh/ban", strings.NewReader(`{"ip":"1.2.3.4"}`))
	rec := httptest.NewRecorder()
	s.handleBan(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if calls.Load() != 0 {
		t.Fatal("onBan should not run when sharing is disabled")
	}

	SharingEnabled = func() bool { return true }
	req = httptest.NewRequest(http.MethodPost, "/mesh/ban", strings.NewReader(`{"ip":"1.2.3.4","ja4":"t13d0406h2_aaaaaaaaaaaa_bbbbbbbbbbbb","ja3":"0123456789abcdef0123456789abcdef"}`))
	rec = httptest.NewRecorder()
	s.handleBan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if calls.Load() != 1 {
		t.Fatal("onBan should run when sharing is enabled")
	}
	if gotJA4 == "" || gotJA3 == "" {
		t.Fatalf("expected JA4 and JA3 to propagate through handleBan, got ja4=%q ja3=%q", gotJA4, gotJA3)
	}
}

func TestMeshBanRejectsOversizedBody(t *testing.T) {
	previous := SharingEnabled
	defer func() { SharingEnabled = previous }()
	SharingEnabled = func() bool { return true }
	s := &Server{onBan: func(string, BanSignal, time.Time) { t.Fatal("oversized ban reached handler") }}
	body := `{"ip":"1.2.3.4","reason":"` + strings.Repeat("x", 65<<10) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/mesh/ban", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleBan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body status %d", rec.Code)
	}
}

func TestBroadcastBanStopsWhenSharingDisabled(t *testing.T) {
	var calls atomic.Int32
	payloads := make(chan string, 1)
	s := &Server{
		client: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				body, _ := io.ReadAll(r.Body)
				payloads <- string(body)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("ok")),
					Header:     make(http.Header),
				}, nil
			}),
		},
		peers: map[string]time.Time{"127.0.0.1:9000": time.Now()},
	}

	SharingEnabled = func() bool { return false }
	s.BroadcastBan(BanSignal{IP: "1.2.3.4", Reason: "blocked"})
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("broadcast should not publish when sharing is disabled")
	}

	SharingEnabled = func() bool { return true }
	s.BroadcastBan(BanSignal{
		IP:     "1.2.3.4",
		Reason: "blocked",
		JA4:    "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
		JA3:    "abc123",
	})
	select {
	case payload := <-payloads:
		if !strings.Contains(payload, "\"ja4\":\"t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb\"") || !strings.Contains(payload, "\"ja3\":\"abc123\"") {
			t.Fatalf("expected JA4 and JA3 in broadcast payload, got %s", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("broadcast should publish when sharing is enabled")
	}
}
