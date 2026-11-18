//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Exercises the actual multi-app agent socket startup with two separate Node
// processes. auto_block remains off; kernel enforcement has a separate gate.
func TestTwoRealAppsUseOwnAgentSockets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to launch distinct app UIDs")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node.js is required")
	}
	_ = testNodeEdgeDB(t)
	previous := liveNodeEdge
	liveNodeEdge = nil
	t.Cleanup(func() { liveNodeEdge = previous })
	dir := t.TempDir()
	if err := os.Chmod(filepath.Dir(dir), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	const uidA, uidB = uint32(65532), uint32(65533)
	const appA, appB = "pilot_app_a", "pilot_app_b"
	const secretA, secretB = "pilot-app-a-secret-32-bytes-minimum-001", "pilot-app-b-secret-32-bytes-minimum-002"
	type registration struct {
		AppID      string `json:"app_id"`
		Source     string `json:"source"`
		Socket     string `json:"socket"`
		SecretFile string `json:"secret_file"`
		UID        uint32 `json:"uid"`
		AutoBlock  bool   `json:"auto_block"`
	}
	makeApp := func(id, name, secret string, uid uint32) registration {
		path := filepath.Join(dir, name+".secret")
		if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
			t.Fatal(err)
		}
		return registration{AppID: id, Source: "node_guard", Socket: filepath.Join(dir, name+".sock"), SecretFile: path, UID: uid}
	}
	a := makeApp(appA, "a", secretA, uidA)
	b := makeApp(appB, "b", secretB, uidB)
	config, err := json.Marshal(map[string]any{"apps": []registration{a, b}})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "apps.json")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	shutdown := make(chan struct{})
	if err := startNodeEdgeApps(shutdown, configPath); err != nil {
		t.Fatal(err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			close(shutdown)
		}
	})
	const script = `
import http from 'node:http';
import {createHmac, randomUUID} from 'node:crypto';
const send=(socketPath,secret,appId)=>new Promise((resolve,reject)=>{
  const body=JSON.stringify({event_id:'event_'+randomUUID().replaceAll('-',''),app_id:appId,source:'node_guard',ip:'8.8.8.8',reason_code:'api_probe_burst',evidence_hash:'a'.repeat(64),confidence:90,ttl_seconds:120});
  const timestamp=new Date().toISOString();
  const nonce='nonce_'+randomUUID().replaceAll('-','');
  const signature=createHmac('sha256',secret).update(timestamp+'\n'+nonce+'\n'+body).digest('hex');
  const req=http.request({socketPath,path:'/v1/event',method:'POST',headers:{'content-type':'application/json','x-edge-timestamp':timestamp,'x-edge-nonce':nonce,'x-edge-signature':signature}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});
  req.on('error',reject);req.end(body);
});
const own=await send(process.env.OWN_SOCKET,process.env.OWN_SECRET,process.env.OWN_APP);
const cross=await send(process.env.CROSS_SOCKET,process.env.CROSS_SECRET,process.env.CROSS_APP);
const wrongSecret=await send(process.env.OWN_SOCKET,process.env.CROSS_SECRET,process.env.OWN_APP);
const wrongId=await send(process.env.OWN_SOCKET,process.env.OWN_SECRET,process.env.CROSS_APP);
if(own!==200||cross!==403||wrongSecret!==403||wrongId!==403) throw new Error('own/cross/secret/id status '+[own,cross,wrongSecret,wrongId].join('/'));
`
	client := func(uid uint32, own registration, ownSecret string, cross registration, crossSecret string) *exec.Cmd {
		cmd := exec.Command("node", "--input-type=module", "-e", script)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uint32(os.Getgid())}}
		cmd.Env = append(os.Environ(), "OWN_SOCKET="+own.Socket, "OWN_SECRET="+ownSecret, "OWN_APP="+own.AppID,
			"CROSS_SOCKET="+cross.Socket, "CROSS_SECRET="+crossSecret, "CROSS_APP="+cross.AppID)
		return cmd
	}
	runClients := func() {
		cmdA := client(uidA, a, secretA, b, secretB)
		cmdB := client(uidB, b, secretB, a, secretA)
		var outA, outB bytes.Buffer
		cmdA.Stdout, cmdA.Stderr = &outA, &outA
		cmdB.Stdout, cmdB.Stderr = &outB, &outB
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
			t.Fatalf("app A: %v: %s", err, outA.String())
		}
		if err := cmdB.Wait(); err != nil {
			t.Fatalf("app B: %v: %s", err, outB.String())
		}
	}
	runClients()
	close(shutdown)
	stopped = true
	for i := 0; i < 100; i++ {
		if _, err := os.Lstat(a.Socket); os.IsNotExist(err) {
			if _, err := os.Lstat(b.Socket); os.IsNotExist(err) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Lstat(a.Socket); !os.IsNotExist(err) {
		t.Fatalf("app A socket remains after stop: %v", err)
	}
	if _, err := os.Lstat(b.Socket); !os.IsNotExist(err) {
		t.Fatalf("app B socket remains after stop: %v", err)
	}
	restarted := make(chan struct{})
	if err := startNodeEdgeApps(restarted, configPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(restarted) })
	runClients()
}
