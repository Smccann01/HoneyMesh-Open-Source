package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNodeEdgeAppsRequireDistinctIdentities(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apps.json")
	valid := `{"apps":[{"app_id":"app_alpha_01","source":"node_guard","socket":"/run/hm/a.sock","secret_file":"/run/hm/a.secret","uid":1001},{"app_id":"app_bravo_02","source":"node_guard","socket":"/run/hm/b.sock","secret_file":"/run/hm/b.secret","uid":1002}]}`
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	apps, err := readNodeEdgeApps(path)
	if err != nil || len(apps) != 2 {
		t.Fatalf("valid apps: %v %v", apps, err)
	}
	duplicateUID := `{"apps":[{"app_id":"app_alpha_01","source":"node_guard","socket":"/run/hm/a.sock","secret_file":"/run/hm/a.secret","uid":1001},{"app_id":"app_bravo_02","source":"node_guard","socket":"/run/hm/b.sock","secret_file":"/run/hm/b.secret","uid":1001}]}`
	if err := os.WriteFile(path, []byte(duplicateUID), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNodeEdgeApps(path); err == nil {
		t.Fatal("shared UID accepted")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readNodeEdgeApps(path); err == nil {
		t.Fatal("writable config accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "apps-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readNodeEdgeApps(link); err == nil {
		t.Fatal("symlinked config accepted")
	}
}

func TestNodeProHostEntitlementFailsClosed(t *testing.T) {
	t.Setenv("HM_NODE_PRO_ENTITLEMENT_FILE", "")
	t.Setenv("HM_NODE_PRO_UNIT_ID", "")
	if nodeProHostEntitled() {
		t.Fatal("missing entitlement authorized application enforcement")
	}
	if label := licenseDisplayName(); label != "Community" {
		t.Fatalf("missing entitlement displayed %q", label)
	}
	path := filepath.Join(t.TempDir(), "entitlement.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"product":"node_pro"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HM_NODE_PRO_ENTITLEMENT_FILE", path)
	t.Setenv("HM_NODE_PRO_UNIT_ID", "host_0123456789abcdef01234567")
	if nodeProHostEntitled() {
		t.Fatal("unsigned entitlement authorized application enforcement")
	}
	if label := licenseDisplayName(); label != "Community" {
		t.Fatalf("unsigned entitlement displayed %q", label)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if nodeProHostEntitled() {
		t.Fatal("writable entitlement authorized application enforcement")
	}
}

func TestNodeEdgeActiveBlocksAreScopedByApp(t *testing.T) {
	database := testNodeEdgeDB(t)
	a := testNodeEdgeController(database, true, time.Now())
	eventA := testNodeEdgeEvent("app_alpha_evt_01")
	eventA.AppID = "app_alpha_01"
	if status, err := a.onEvent(context.Background(), eventA); err != nil || status != "blocked" {
		t.Fatalf("A: %s %v", status, err)
	}
	b := testNodeEdgeController(database, true, time.Now())
	eventB := testNodeEdgeEvent("app_bravo_evt_02")
	eventB.AppID = "app_bravo_02"
	eventB.IP = "1.1.1.1"
	if status, err := b.onEvent(context.Background(), eventB); err != nil || status != "blocked" {
		t.Fatalf("B: %s %v", status, err)
	}
	blocksA, err := nodeEdgeActiveBlocksForApp(eventA.AppID)(context.Background())
	if err != nil || len(blocksA) != 1 || blocksA[0].IP != eventA.IP {
		t.Fatalf("A snapshot: %+v %v", blocksA, err)
	}
	blocksB, err := nodeEdgeActiveBlocksForApp(eventB.AppID)(context.Background())
	if err != nil || len(blocksB) != 1 || blocksB[0].IP != eventB.IP {
		t.Fatalf("B snapshot: %+v %v", blocksB, err)
	}
}

func TestMultiAppSocketsEnforcePeerUID(t *testing.T) {
	_ = testNodeEdgeDB(t)
	previous := liveNodeEdge
	liveNodeEdge = nil
	t.Cleanup(func() { liveNodeEdge = previous })
	dir := t.TempDir()
	uidA, uidB := uint32(os.Getuid()), uint32(os.Getuid()+1)
	secretA, secretB := []byte("test-only-app-alpha-secret-with-32-bytes"), []byte("test-only-app-bravo-secret-with-32-bytes")
	pathA, pathB := filepath.Join(dir, "a.secret"), filepath.Join(dir, "b.secret")
	if err := os.WriteFile(pathA, secretA, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, secretB, 0600); err != nil {
		t.Fatal(err)
	}
	apps := []nodeEdgeApp{
		{AppID: "app_alpha_01", Source: "node_guard", Socket: filepath.Join(dir, "a.sock"), SecretFile: pathA, UID: &uidA},
		{AppID: "app_bravo_02", Source: "node_guard", Socket: filepath.Join(dir, "b.sock"), SecretFile: pathB, UID: &uidB},
	}
	data, err := json.Marshal(struct {
		Apps []nodeEdgeApp `json:"apps"`
	}{apps})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "apps.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	shutdown := make(chan struct{})
	if err := startNodeEdgeApps(shutdown, configPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(shutdown) })
	request := func(socket string, secret []byte, appID string) int {
		t.Helper()
		event := testNodeEdgeEvent("multi_" + appID)
		event.AppID = appID
		body, _ := json.Marshal(event)
		timestamp := time.Now().UTC().Format(time.RFC3339)
		nonce := "nonce_" + appID
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(timestamp + "\n" + nonce + "\n"))
		_, _ = mac.Write(body)
		transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return net.Dial("unix", socket) }}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: time.Second}
		req, err := http.NewRequest(http.MethodPost, "http://unix/v1/event", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Edge-Timestamp", timestamp)
		req.Header.Set("X-Edge-Nonce", nonce)
		req.Header.Set("X-Edge-Signature", hex.EncodeToString(mac.Sum(nil)))
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	if got := request(apps[0].Socket, secretA, apps[0].AppID); got != http.StatusOK {
		t.Fatal(fmt.Sprintf("app A status=%d", got))
	}
	if got := request(apps[1].Socket, secretB, apps[1].AppID); got != http.StatusForbidden {
		t.Fatal(fmt.Sprintf("app B wrong UID status=%d", got))
	}
}
