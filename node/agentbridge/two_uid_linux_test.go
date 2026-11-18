//go:build linux

package agentbridge

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Run as root on an isolated Linux test host. This checks real SO_PEERCRED
// values from two Node processes, including cross-app attempts made with a
// valid credential for the other app. It does not prove kernel enforcement.
func TestTwoRealNodeUIDsCannotCrossBridges(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to launch two disposable application UIDs")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node.js is required")
	}
	const uidA, uidB = uint32(65532), uint32(65533)
	const appA, appB = "qual_app_a", "qual_app_b"
	const secretA = "qual-app-a-test-only-secret-32-bytes-minimum"
	const secretB = "qual-app-b-test-only-secret-32-bytes-minimum"
	dir, err := os.MkdirTemp("", "hm-bridge-two-uid-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	var countA, countB atomic.Int32
	start := func(name, secret, appID string, uid uint32, calls *atomic.Int32) string {
		t.Helper()
		bridge, err := New(Config{
			Secret: []byte(secret), ExpectedSource: "node_guard", ExpectedAppID: appID, ExpectedUID: &uid,
			AllowedSource: func(netip.Addr) bool { return true },
			OnEvent: func(context.Context, Event) (string, error) {
				calls.Add(1)
				return "observed", nil
			},
			ActiveBlocks: func(context.Context) ([]Block, error) { return nil, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".sock")
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0666); err != nil {
			_ = listener.Close()
			t.Fatal(err)
		}
		server := &http.Server{Handler: bridge.Handler(), ConnContext: UnixPeerContext}
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(func() { _ = server.Close() })
		return path
	}
	pathA := start("a", secretA, appA, uidA, &countA)
	pathB := start("b", secretB, appB, uidB, &countB)
	const script = `
import http from 'node:http';
import { createHmac, randomUUID } from 'node:crypto';
const request = (socketPath, secret, appId) => new Promise((resolve, reject) => {
  const body = JSON.stringify({event_id:'event_' + randomUUID().replaceAll('-',''),app_id:appId,source:'node_guard',ip:'8.8.8.8',reason_code:'api_probe_burst',evidence_hash:'a'.repeat(64),confidence:90,ttl_seconds:120});
  const timestamp = new Date().toISOString();
  const nonce = 'nonce_' + randomUUID().replaceAll('-','');
  const signature = createHmac('sha256',secret).update(timestamp+'\n'+nonce+'\n'+body).digest('hex');
  const req = http.request({socketPath,path:'/v1/event',method:'POST',headers:{'content-type':'application/json','x-edge-timestamp':timestamp,'x-edge-nonce':nonce,'x-edge-signature':signature}}, res => {res.resume();res.on('end',()=>resolve(res.statusCode));});
  req.on('error',reject); req.end(body);
});
const own = await request(process.env.OWN_SOCKET,process.env.OWN_SECRET,process.env.OWN_APP);
const cross = await request(process.env.CROSS_SOCKET,process.env.CROSS_SECRET,process.env.CROSS_APP);
if (own !== 200 || cross !== 403) throw new Error('unexpected own/cross status: '+own+'/'+cross);
`
	client := func(uid uint32, ownPath, ownSecret, ownApp, crossPath, crossSecret, crossApp string) *exec.Cmd {
		cmd := exec.Command("node", "--input-type=module", "-e", script)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		cmd.Env = append(os.Environ(), "OWN_SOCKET="+ownPath, "OWN_SECRET="+ownSecret, "OWN_APP="+ownApp,
			"CROSS_SOCKET="+crossPath, "CROSS_SECRET="+crossSecret, "CROSS_APP="+crossApp)
		return cmd
	}
	cmdA := client(uidA, pathA, secretA, appA, pathB, secretB, appB)
	cmdB := client(uidB, pathB, secretB, appB, pathA, secretA, appA)
	var outputA, outputB bytes.Buffer
	cmdA.Stdout, cmdA.Stderr = &outputA, &outputA
	cmdB.Stdout, cmdB.Stderr = &outputB, &outputB
	if err := cmdA.Start(); err != nil {
		t.Fatal(err)
	}
	if err := cmdB.Start(); err != nil {
		_ = cmdA.Wait()
		t.Fatal(err)
	}
	deadline := time.AfterFunc(15*time.Second, func() { _ = cmdA.Process.Kill(); _ = cmdB.Process.Kill() })
	defer deadline.Stop()
	if err := cmdA.Wait(); err != nil {
		t.Fatalf("app A: %v: %s", err, outputA.String())
	}
	if err := cmdB.Wait(); err != nil {
		t.Fatalf("app B: %v: %s", err, outputB.String())
	}
	if countA.Load() != 1 || countB.Load() != 1 {
		t.Fatalf("accepted events: A=%d B=%d", countA.Load(), countB.Load())
	}
}
