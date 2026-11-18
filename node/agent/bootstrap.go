package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"honeymesh/internal/license"
	"honeymesh/internal/mesh"
)

// ─────────────────────────────────────────────
// CONFIG LOADER
// ─────────────────────────────────────────────

func loadConfig() {
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("[CONFIG] Failed to open config file '%s': %v", configFile, err)
	}
	configFingerprint = fmt.Sprintf("%x", sha256.Sum256(data))
	if err := json.Unmarshal(data, &config); err != nil {
		log.Fatalf("[CONFIG] Failed to parse config file '%s': %v", configFile, err)
	}
	if err := loadRuntimeState(); err != nil {
		log.Fatalf("[STATE] %v", err)
	}

	// ── ENV overrides ──
	if token := os.Getenv("HM_ADMIN_TOKEN"); token != "" {
		config.AdminToken = token
	}
	if bindIP := os.Getenv("HM_BIND_IP"); bindIP != "" {
		config.BindIP = bindIP
	}
	if webPort := os.Getenv("HM_WEB_PORT"); webPort != "" {
		config.WebPort = webPort
	}

	// ── Defaults ──
	if config.NodeName == "" {
		config.NodeName = "honeymesh-node"
	}
	if config.BindIP == "" {
		config.BindIP = "0.0.0.0"
	}
	if config.WebPort == "" {
		config.WebPort = "8443"
	}
	if config.MeshPort == "" {
		config.MeshPort = "9000"
	}
	if config.UIMode == "" {
		config.UIMode = "web"
	}
	if config.Exchange.PullIntervalS <= 0 {
		config.Exchange.PullIntervalS = 300
	}
	if config.Exchange.TrustThreshold <= 0 {
		config.Exchange.TrustThreshold = 50
	}
	if config.DropUser == "" {
		config.DropUser = "nobody"
	}
	config.LicenseTier = license.NormalizeTier(config.LicenseTier)
	if config.LicenseTier == "" {
		config.LicenseTier = license.TierFree
	}
	if config.Security.ScanPorts <= 0 {
		config.Security.ScanPorts = 10
	}
	if config.Security.ScanWindowS <= 0 {
		config.Security.ScanWindowS = 60
	}
	if config.Security.AllowlistBase == nil {
		def := true
		config.Security.AllowlistBase = &def
	}
	if config.Security.StrictHeartbeatAddr == nil {
		def := false
		config.Security.StrictHeartbeatAddr = &def
	}
	if config.Security.TrapBanHits <= 0 {
		config.Security.TrapBanHits = 1
	}
	if config.Security.TrapBanWindowS <= 0 {
		config.Security.TrapBanWindowS = 60
	}
	if config.Security.MeshEventRateLimitPerMin <= 0 {
		config.Security.MeshEventRateLimitPerMin = defaultMeshRatePerMin
	}
	if config.Security.MeshEventBurst <= 0 {
		config.Security.MeshEventBurst = defaultMeshBurst
	}
	if config.Security.MeshReplayWindowS <= 0 {
		config.Security.MeshReplayWindowS = int(defaultReplayWindow.Seconds())
	}
	if strings.TrimSpace(config.Security.MeshDataClassification) == "" {
		config.Security.MeshDataClassification = "L2"
	}

	if abs, err := filepath.Abs(configFile); err == nil {
		configDir = filepath.Dir(abs)
	} else {
		configDir = filepath.Dir(configFile)
	}
	config.Security.CACert = resolveConfigPath(config.Security.CACert)
	config.Security.CertFile = resolveConfigPath(config.Security.CertFile)
	config.Security.KeyFile = resolveConfigPath(config.Security.KeyFile)
	config.Mesh.TLS.CertFile = resolveConfigPath(config.Mesh.TLS.CertFile)
	config.Mesh.TLS.KeyFile = resolveConfigPath(config.Mesh.TLS.KeyFile)
	config.Mesh.TLS.PeerCAFile = resolveConfigPath(config.Mesh.TLS.PeerCAFile)
	config.Mesh.TLS.ClientCAFile = resolveConfigPath(config.Mesh.TLS.ClientCAFile)
	config.Exchange.BaseURL = strings.TrimRight(strings.TrimSpace(config.Exchange.BaseURL), "/")

	refreshWhitelistCIDRs(config.Security.Whitelist)
	refreshTrustedCIDRs(config.Security.TrustedPeers)

	log.Printf("[CONFIG] Loaded node=%s bind=%s web=%s",
		config.NodeName, config.BindIP, config.WebPort)
}

func resolveConfigPath(path string) string {
	if path == "" {
		return path
	}
	if filepath.IsAbs(path) || configDir == "" {
		return path
	}
	return filepath.Join(configDir, path)
}

// ─────────────────────────────────────────────
// IDENTITY MANAGEMENT
// ─────────────────────────────────────────────

func initNodeIdentity() {
	if err := initNodeIdentityStore(); err != nil {
		log.Fatalf("[BOOT]⬡ Failed to initialize node identity: %v", err)
	}
	log.Printf("[BOOT]⬡ Node identity ready id=%s", currentNodeIdentity().NodeID)
}

func RepairIdentity() {
	log.Println("[IDENTITY] Repairing node identity...")
	if err := regenerateNodeIdentityStore(); err != nil {
		log.Fatalf("[IDENTITY] Failed to repair identity: %v", err)
	}
	log.Printf("[IDENTITY] Identity regenerated successfully id=%s", currentNodeIdentity().NodeID)
}

// ─────────────────────────────────────────────
// JOIN TOKEN GENERATION
// ─────────────────────────────────────────────

func issueJoinToken(ttl time.Duration) (string, time.Time, error) {
	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		return "", time.Time{}, err
	}

	tokenStr := hex.EncodeToString(token)
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	exp := time.Now().Add(ttl)
	if err := addJoinToken(tokenStr, exp); err != nil {
		return "", time.Time{}, err
	}

	err := os.WriteFile(joinTokenPath(), []byte(tokenStr), 0600)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenStr, exp, nil
}

func generateJoinToken() {
	_, exp, err := issueJoinToken(30 * time.Minute)
	if err != nil {
		log.Fatalf("[MESH] Failed to generate join token: %v", err)
	}
	log.Printf("[MESH] Join token generated (expires %s); read it from the protected join-token file", exp.Format(time.RFC3339))
}

// ─────────────────────────────────────────────
// JOIN CLUSTER
// ─────────────────────────────────────────────

func performJoin(url string, token string) {
	log.Printf("[MESH] Joining cluster at %s", url)
	if max := license.MaxNodes(); max > 0 {
		if 1+meshPeerCount() >= max {
			log.Fatalf("[MESH] Join blocked: max nodes reached (%d)", max)
		}
	}

	if config.MeshPort == "" {
		config.MeshPort = "9000"
	}
	joinURL := url
	if !strings.HasPrefix(joinURL, "https://") {
		joinURL = "https://" + joinURL
	}
	if !strings.Contains(joinURL, "/mesh/join") {
		joinURL = strings.TrimRight(joinURL, "/") + "/mesh/join"
	}

	advertise := config.BindIP
	if advertise == "" || advertise == "0.0.0.0" {
		ips := getAvailableIPs()
		if len(ips) > 0 {
			advertise = ips[0]
		}
	}
	if advertise != "" && !strings.Contains(advertise, ":") {
		advertise = advertise + ":" + config.MeshPort
	}

	client, err := meshJoinClient()
	if err != nil {
		log.Fatalf("[MESH] Failed to build join client: %v", err)
	}

	body := struct {
		Token      string              `json:"token"`
		Addr       string              `json:"addr"`
		Capability mesh.PeerCapability `json:"capability"`
	}{
		Token:      token,
		Addr:       advertise,
		Capability: currentPeerCapability(),
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", joinURL, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("[MESH] Join failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("[MESH] Join rejected: %s", resp.Status)
	}

	var out struct {
		Peers []string `json:"peers"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	for _, p := range out.Peers {
		addPeer(p)
	}
	peerHost := strings.TrimPrefix(joinURL, "https://")
	if idx := strings.Index(peerHost, "/"); idx >= 0 {
		peerHost = peerHost[:idx]
	}
	addPeer(peerHost)
	log.Println("[MESH] Join successful. Restart node to connect.")
}

// ─────────────────────────────────────────────
// CONFIG SAVE
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// MESH RECONNECT LOOP
// ─────────────────────────────────────────────

func startMeshReconnectLoop(shutdown <-chan struct{}) {
	if scp == nil {
		return
	}

	ticker := time.NewTicker(30 * time.Second)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				for _, peer := range config.Mesh.Peers {
					if peer == "" {
						continue
					}
					go scp.ConnectToPeer(peer)
				}
			case <-shutdown:
				return
			}
		}
	}()
}

func meshJoinClient() (*http.Client, error) {
	_, tlsCfg, err := meshTLSConfigs(true, advertiseAddr())
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, nil
}
