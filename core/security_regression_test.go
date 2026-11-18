package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"honeymesh/internal/mesh"
)

func testCertificate(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, host string, usages []x509.ExtKeyUsage, expired bool) ([]byte, []byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
	if caCert == nil {
		cert.IsCA = true
		cert.BasicConstraintsValid = true
		cert.KeyUsage |= x509.KeyUsageCertSign
		caCert, caKey = cert, key
	} else if ip := net.ParseIP(host); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	} else {
		cert.DNSNames = []string{host}
	}
	if expired {
		cert.NotBefore = now.Add(-48 * time.Hour)
		cert.NotAfter = now.Add(-24 * time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), parsed, key
}

func TestMeshTLSVerifiedIdentity(t *testing.T) {
	old := config
	defer func() { config = old }()
	dir := t.TempDir()
	caPEM, _, ca, caKey := testCertificate(t, nil, nil, "test-ca", nil, false)
	certPEM, keyPEM, _, _ := testCertificate(t, ca, caKey, "127.0.0.1", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, false)
	paths := []string{"node.crt", "node.key", "ca.crt"}
	for i, data := range [][]byte{certPEM, keyPEM, caPEM} {
		if err := os.WriteFile(filepath.Join(dir, paths[i]), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	config.Mesh.TLS = MeshTLSConfig{CertFile: filepath.Join(dir, paths[0]), KeyFile: filepath.Join(dir, paths[1]), PeerCAFile: filepath.Join(dir, paths[2]), ClientCAFile: filepath.Join(dir, paths[2])}
	serverTLS, clientTLS, err := meshTLSConfigs(true, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}, Timeout: 2 * time.Second}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("trusted mutual TLS failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, _, err := meshTLSConfigs(true, "wrong.example"); err == nil {
		t.Fatal("wrong advertised hostname accepted")
	}
	forgedCA, _, _, _ := testCertificate(t, nil, nil, "forged-ca", nil, false)
	forgedPool := x509.NewCertPool()
	forgedPool.AppendCertsFromPEM(forgedCA)
	forgedClient := clientTLS.Clone()
	forgedClient.RootCAs = forgedPool
	if resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: forgedClient}, Timeout: 2 * time.Second}).Get(server.URL); err == nil {
		resp.Body.Close()
		t.Fatal("untrusted server certificate accepted")
	}
	noClient := clientTLS.Clone()
	noClient.Certificates = nil
	if resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: noClient}, Timeout: 2 * time.Second}).Get(server.URL); err == nil {
		resp.Body.Close()
		t.Fatal("untrusted client certificate accepted")
	}
	expiredPEM, expiredKey, _, _ := testCertificate(t, ca, caKey, "127.0.0.1", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, true)
	expiredCert, err := tls.X509KeyPair(expiredPEM, expiredKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	expiredTLS := serverTLS.Clone()
	expiredTLS.Certificates = []tls.Certificate{expiredCert}
	expiredServer.TLS = expiredTLS
	expiredServer.StartTLS()
	defer expiredServer.Close()
	if resp, err := client.Get(expiredServer.URL); err == nil {
		resp.Body.Close()
		t.Fatal("expired server certificate accepted")
	}
	config.Mesh.TLS.PeerCAFile = filepath.Join(dir, "missing.crt")
	if _, _, err := meshTLSConfigs(true, "127.0.0.1"); err == nil {
		t.Fatal("missing CA accepted")
	}
	config.Mesh.TLS = MeshTLSConfig{}
	if _, _, err := meshTLSConfigs(true, "127.0.0.1"); err == nil {
		t.Fatal("missing explicit trust accepted")
	}
}

func TestClusterIDValidation(t *testing.T) {
	for _, id := range []string{"cluster-123", "tenant:a.b_1"} {
		if !validClusterID(id) {
			t.Fatalf("valid ID rejected: %q", id)
		}
	}
	for _, id := range []string{"", "<img src=x>", "' onclick='alert(1)", " space", strings.Repeat("a", 129)} {
		if validClusterID(id) {
			t.Fatalf("invalid ID accepted: %q", id)
		}
	}
}

func TestTwoNodeVerifiedMeshJoinAndBan(t *testing.T) {
	oldConfig := config
	defer func() { config = oldConfig }()
	oldSharing, oldToken := mesh.SharingEnabled, mesh.ValidateJoinToken
	oldCapability, oldLocal := mesh.ValidatePeerCapability, mesh.LocalPeerCapability
	oldMax, oldPeerCount, oldSignal := mesh.MaxNodesAllowed, mesh.PeerCount, mesh.ValidateBanSignal
	defer func() {
		mesh.SharingEnabled, mesh.ValidateJoinToken = oldSharing, oldToken
		mesh.ValidatePeerCapability, mesh.LocalPeerCapability = oldCapability, oldLocal
		mesh.MaxNodesAllowed, mesh.PeerCount, mesh.ValidateBanSignal = oldMax, oldPeerCount, oldSignal
	}()
	mesh.SharingEnabled = func() bool { return true }
	mesh.ValidateJoinToken = func(token string) bool { return token == "synthetic-join-token" }
	mesh.ValidatePeerCapability = nil
	mesh.LocalPeerCapability = nil
	mesh.MaxNodesAllowed = func() int { return 0 }
	mesh.PeerCount = nil
	mesh.ValidateBanSignal = nil

	caPEM, _, ca, caKey := testCertificate(t, nil, nil, "mesh-test-ca", nil, false)
	dir := t.TempDir()
	hosts := []string{"127.77.0.1", "127.77.0.2"}
	servers := make([]*tls.Config, 2)
	clients := make([]*tls.Config, 2)
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	for i, host := range hosts {
		certPEM, keyPEM, _, _ := testCertificate(t, ca, caKey, host, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, false)
		certPath, keyPath := filepath.Join(dir, host+".crt"), filepath.Join(dir, host+".key")
		if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			t.Fatal(err)
		}
		config.Mesh.TLS = MeshTLSConfig{CertFile: certPath, KeyFile: keyPath, PeerCAFile: caPath, ClientCAFile: caPath}
		var err error
		servers[i], clients[i], err = meshTLSConfigs(true, host)
		if err != nil {
			t.Fatal(err)
		}
	}
	received := make(chan string, 1)
	nodeA, err := mesh.StartMeshServer(hosts[0], hosts[0], 9000, servers[0], clients[0], nil, nil, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Shutdown(context.Background())
	nodeB, err := mesh.StartMeshServer(hosts[1], hosts[1], 9000, servers[1], clients[1], func(_ string, signal mesh.BanSignal, _ time.Time) { received <- signal.IP }, nil, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Shutdown(context.Background())
	var joinErr error
	for i := 0; i < 10; i++ {
		joinErr = nodeB.Join(hosts[0]+":9000", "synthetic-join-token", hosts[1]+":9000")
		if joinErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if joinErr != nil {
		t.Fatalf("trusted mesh join failed: %v", joinErr)
	}
	nodeA.BroadcastBan(mesh.BanSignal{IP: "198.51.100.9", Reason: "synthetic test"})
	select {
	case ip := <-received:
		if ip != "198.51.100.9" {
			t.Fatalf("wrong ban signal %q", ip)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("trusted mesh ban did not reach second node")
	}
}

func TestWSSessionAndCSVCells(t *testing.T) {
	old := config.AdminToken
	config.AdminToken = "synthetic-test-token"
	defer func() { config.AdminToken = old }()
	req := httptest.NewRequest(http.MethodPost, "https://example.test/api/session", nil)
	req.Header.Set("Origin", "https://example.test")
	req.Header.Set("X-Honey-Token", config.AdminToken)
	rec := httptest.NewRecorder()
	apiSession(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("session status %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || !validWSSession(cookies[0].Value) {
		t.Fatal("insecure or invalid session")
	}
	if validWSSession(cookies[0].Value + "x") {
		t.Fatal("forged session accepted")
	}
	req.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	apiSession(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatal("cross-origin session accepted")
	}
	for _, value := range []string{"=1+2", "+cmd", "-1", "@SUM(1)", "  =1+2"} {
		if !strings.HasPrefix(csvSafeCell(value), "\t") {
			t.Fatalf("formula cell accepted: %q", value)
		}
	}
}
