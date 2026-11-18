package agentbridge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var testSecret = []byte("test-only-bridge-secret-with-32-plus-bytes")

func signedRequest(t *testing.T, method, route string, event *Event, nonce string) *http.Request {
	return signedRequestWithSecret(t, method, route, event, nonce, testSecret)
}

func signedRequestWithSecret(t *testing.T, method, route string, event *Event, nonce string, secret []byte) *http.Request {
	t.Helper()
	var body []byte
	if event != nil {
		body, _ = json.Marshal(event)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(timestamp + "\n" + nonce + "\n"))
	_, _ = mac.Write(body)
	r := httptest.NewRequest(method, route, bytes.NewReader(body))
	r.Header.Set("X-Edge-Timestamp", timestamp)
	r.Header.Set("X-Edge-Nonce", nonce)
	r.Header.Set("X-Edge-Signature", hex.EncodeToString(mac.Sum(nil)))
	return r
}

func TestTwoAppCredentialsCannotCrossBridges(t *testing.T) {
	secretA := []byte("test-only-app-a-secret-with-32-plus-bytes")
	secretB := []byte("test-only-app-b-secret-with-32-plus-bytes")
	var callsA, callsB int
	newAppBridge := func(secret []byte, calls *int) *Bridge {
		b, err := New(Config{
			Secret: secret, ExpectedSource: "node_guard",
			AllowedSource: func(netip.Addr) bool { return true },
			OnEvent:       func(context.Context, Event) (string, error) { (*calls)++; return "observed", nil },
			ActiveBlocks:  func(context.Context) ([]Block, error) { return nil, nil },
			AgentMode:     func(context.Context) (string, error) { return "TEST", nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a := newAppBridge(secretA, &callsA)
	b := newAppBridge(secretB, &callsB)
	e := testEvent()
	e.EventID = "event_app_a_1234"
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, signedRequestWithSecret(t, http.MethodPost, "/v1/event", &e, "nonce_app_a_1234", secretA))
	if rec.Code != http.StatusOK || callsA != 1 {
		t.Fatalf("app A own bridge: status=%d calls=%d", rec.Code, callsA)
	}
	e.EventID = "event_cross_1234"
	rec = httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, signedRequestWithSecret(t, http.MethodPost, "/v1/event", &e, "nonce_cross_1234", secretA))
	if rec.Code != http.StatusForbidden || callsB != 0 {
		t.Fatalf("cross-app request: status=%d calls=%d", rec.Code, callsB)
	}
	e.EventID = "event_app_b_1234"
	rec = httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, signedRequestWithSecret(t, http.MethodPost, "/v1/event", &e, "nonce_app_b_1234", secretB))
	if rec.Code != http.StatusOK || callsB != 1 {
		t.Fatalf("app B own bridge: status=%d calls=%d", rec.Code, callsB)
	}
}

func TestBoundBridgeRejectsMissingOrWrongPeerUID(t *testing.T) {
	uid := uint32(os.Getuid() + 1)
	b, err := New(Config{
		Secret: testSecret, ExpectedSource: "node_guard", ExpectedAppID: "app_test_01", ExpectedUID: &uid,
		AllowedSource: func(netip.Addr) bool { return true },
		OnEvent: func(context.Context, Event) (string, error) {
			t.Fatal("wrong UID reached policy")
			return "", nil
		},
		ActiveBlocks: func(context.Context) ([]Block, error) { return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	e := testEvent()
	e.AppID = "app_test_01"
	for _, ctx := range []context.Context{context.Background(), context.WithValue(context.Background(), peerUIDKey{}, uint32(os.Getuid()))} {
		r := signedRequest(t, http.MethodPost, "/v1/event", &e, "nonce_bound_uid")
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r.WithContext(ctx))
		if w.Code != http.StatusForbidden {
			t.Fatalf("wrong peer UID status=%d", w.Code)
		}
		r = signedRequest(t, http.MethodGet, "/v1/active-blocks", nil, "nonce_bound_get")
		w = httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r.WithContext(ctx))
		if w.Code != http.StatusForbidden {
			t.Fatalf("wrong peer UID snapshot status=%d", w.Code)
		}
	}
}

func newTestBridge(t *testing.T, onEvent func(context.Context, Event) (string, error)) *Bridge {
	t.Helper()
	b, err := New(Config{
		Secret:         testSecret,
		ExpectedSource: "node_guard",
		AllowedSource:  func(ip netip.Addr) bool { return ip.String() != "1.1.1.1" },
		OnEvent:        onEvent,
		ActiveBlocks: func(context.Context) ([]Block, error) {
			return []Block{
				{IP: "8.8.8.8", ReasonCode: "invalid_signature_burst", ExpiresAt: time.Now().Add(time.Minute)},
				{IP: "1.1.1.1", ReasonCode: "invalid_signature_burst", ExpiresAt: time.Now().Add(time.Minute)},
			}, nil
		},
		AgentMode: func(context.Context) (string, error) { return "TEST", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCredentialIsBoundToAppSource(t *testing.T) {
	b := newTestBridge(t, func(context.Context, Event) (string, error) {
		t.Fatal("mismatched source reached policy")
		return "", nil
	})
	e := testEvent()
	e.Source = "exchange_guard"
	rec := httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, signedRequest(t, http.MethodPost, "/v1/event", &e, "nonce_wrongapp12"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("source mismatch: %d", rec.Code)
	}
}

func testEvent() Event {
	return Event{EventID: "event_12345678", Source: "node_guard", IP: "8.8.8.8", ReasonCode: "invalid_signature_burst", EvidenceHash: "abcdef0123456789abcdef0123456789", Confidence: 90, TTLSeconds: 120}
}

func TestSignedEventReplayAndPolicy(t *testing.T) {
	calls := 0
	b := newTestBridge(t, func(context.Context, Event) (string, error) { calls++; return "observed", nil })
	h := b.Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, http.MethodPost, "/v1/event", ptr(testEvent()), "nonce_12345678"))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"observed"`)) {
		t.Fatalf("signed event: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, http.MethodPost, "/v1/event", ptr(testEvent()), "nonce_87654321"))
	if rec.Code != http.StatusConflict || calls != 1 {
		t.Fatalf("duplicate event: %d calls=%d", rec.Code, calls)
	}
	e := testEvent()
	e.EventID = "event_abcdefgh"
	e.IP = "1.1.1.1"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, http.MethodPost, "/v1/event", &e, "nonce_excluded12"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("excluded source: %d", rec.Code)
	}
	e.IP = "127.0.0.1"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, http.MethodPost, "/v1/event", &e, "nonce_private12"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("private source: %d", rec.Code)
	}
}

func TestAuthenticationAndSnapshot(t *testing.T) {
	b := newTestBridge(t, func(context.Context, Event) (string, error) { return "observed", nil })
	h := b.Handler()
	req := signedRequest(t, http.MethodPost, "/v1/event", ptr(testEvent()), "nonce_12345678")
	req.Header.Set("X-Edge-Signature", "bad")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad signature: %d", rec.Code)
	}
	req = signedRequest(t, http.MethodGet, "/v1/active-blocks", nil, "nonce_snapshot1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("snapshot: %d", rec.Code)
	}
	var snapshot struct {
		Total  int     `json:"total"`
		Blocks []Block `json:"blocks"`
		Mode   string  `json:"mode"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Total != 1 || len(snapshot.Blocks) != 1 || snapshot.Blocks[0].IP != "8.8.8.8" || snapshot.Mode != "TEST" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("snapshot replay: %d", rec.Code)
	}
}

func TestInvalidActionCannotClaimSuccess(t *testing.T) {
	b := newTestBridge(t, func(context.Context, Event) (string, error) { return "blocked", context.Canceled })
	rec := httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, signedRequest(t, http.MethodPost, "/v1/event", ptr(testEvent()), "nonce_failure12"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed action: %d", rec.Code)
	}
}

func TestNodeClientOverUnixSocket(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node.js is required for cross-language test")
	}
	uid := uint32(os.Getuid())
	b, err := New(Config{
		Secret: testSecret, ExpectedSource: "node_guard", ExpectedAppID: "app_test_01", ExpectedUID: &uid,
		AllowedSource: func(netip.Addr) bool { return true },
		OnEvent: func(_ context.Context, e Event) (string, error) {
			if e.Source != "node_guard" || e.AppID != "app_test_01" || e.IP != "8.8.8.8" {
				t.Errorf("unexpected event: %+v", e)
			}
			return "observed", nil
		},
		ActiveBlocks: func(context.Context) ([]Block, error) {
			return []Block{{IP: "8.8.8.8", ReasonCode: "invalid_signature_burst", ExpiresAt: time.Now().Add(time.Minute)}}, nil
		},
		AgentMode: func(context.Context) (string, error) { return "TEST", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(t.TempDir(), "edge.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: b.Handler(), ConnContext: UnixPeerContext}
	go server.Serve(listener)
	t.Cleanup(func() { _ = server.Close() })
	const script = `
import { createAgentBridge } from '../node-guard/bridge.mjs';
const bridge = createAgentBridge({socketPath:process.env.HM_TEST_SOCKET,secret:process.env.HM_TEST_SECRET,appId:'app_test_01'});
const result = await bridge.sendEvent({sourceIp:'8.8.8.8',reasonCode:'invalid_signature_burst',evidenceHash:'a'.repeat(64),confidence:90,ttlSeconds:120});
if (result.status !== 'observed') throw new Error('event status mismatch');
const snapshot = await bridge.activeBlocks();
if (snapshot.total !== 1 || snapshot.mode !== 'TEST' || snapshot.blocks[0].sourceIp !== '8.8.8.8') throw new Error('snapshot mismatch');
`
	cmd := exec.Command("node", "--input-type=module", "-e", script)
	cmd.Env = append(os.Environ(), "HM_TEST_SOCKET="+socketPath, "HM_TEST_SECRET="+string(testSecret))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Node-to-Go socket contract failed: %v %s", err, output)
	}
	const wrongApp = `
import { createAgentBridge } from '../node-guard/bridge.mjs';
const bridge = createAgentBridge({socketPath:process.env.HM_TEST_SOCKET,secret:process.env.HM_TEST_SECRET,appId:'app_wrong_02'});
try {
  await bridge.sendEvent({sourceIp:'8.8.8.8',reasonCode:'invalid_signature_burst',evidenceHash:'a'.repeat(64),confidence:90,ttlSeconds:120});
  throw new Error('wrong app ID was accepted');
} catch (err) { if (!String(err).includes('HTTP 403')) throw err; }
`
	cmd = exec.Command("node", "--input-type=module", "-e", wrongApp)
	cmd.Env = append(os.Environ(), "HM_TEST_SOCKET="+socketPath, "HM_TEST_SECRET="+string(testSecret))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wrong app ID check failed: %v %s", err, output)
	}
}

func TestServeUnixRestrictsSocketAndStopsCleanly(t *testing.T) {
	b := newTestBridge(t, func(context.Context, Event) (string, error) { return "observed", nil })
	socketPath := filepath.Join(t.TempDir(), "edge.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- b.ServeUnix(ctx, socketPath, 0600) }()
	var info os.FileInfo
	for i := 0; i < 100; i++ {
		var err error
		info, err = os.Lstat(socketPath)
		if err == nil && info.Mode().Perm() == 0600 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if info == nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode: %v", info)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket not removed: %v", err)
	}
}

func ptr(e Event) *Event { return &e }
