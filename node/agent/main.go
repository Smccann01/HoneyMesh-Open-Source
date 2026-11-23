package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 bpf ./bpf/main.c -- -I./bpf

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"honeymesh/internal/license"
	"honeymesh/internal/mesh"
)

const Version = "v2.3.7-rc1-nodepro1"

func printStartupBanner() {
	fmt.Println("\x1b[38;5;208m" +
		"    ^^       ^^\n" +
		"^^        (`-=-=-=-=-`)         ^^\n" +
		"        (`-=-=-=-=-=-=-`)  ^^         ^^\n" +
		"  ^^   (`-=-=-=-=-=-=-=-`)   ^^                            ^^\n" +
		"      ( `-=-=-=-(@)-=-=-` )      ^^\n" +
		"      (`-=-=-=-=-=-=-=-=-`)  ^^\n" +
		"      (`-=-=-=-=-=-=-=-=-`)              ^^\n" +
		"      (`-=-=-=-=-=-=-=-=-`)                      ^^\n" +
		"      (`-=-=-=-=-=-=-=-=-`)  ^^\n" +
		"       (`-=-=-=-=-=-=-=-`)          ^^\n" +
		"        (`-=-=-=-=-=-=-`)  ^^                 ^^\n" +
		"          (`-=-=-=-=-`)\n" +
		"           `-=-=-=-=-`\n" +
		"------------------------------------------------\x1b[0m")
	fmt.Printf("🍯  Honey Mesh %s Active\n", Version)
}

func main() {
	// ─────────────────────────────────────────────
	// 2. FLAGS
	// ─────────────────────────────────────────────
	flag.StringVar(&configFile, "config", "honeymesh.json", "Path to configuration file")
	flag.StringVar(&stateDir, "state-dir", ".", "Writable state directory")
	genTokenFlag := flag.Bool("token", false, "Generate Mesh Join Token")
	joinUrlFlag := flag.String("join", "", "Join mesh master (URL)")
	joinTokenFlag := flag.String("t", "", "Join token")
	registerExchangeFlag := flag.String("register-exchange", "", "Register this node with NetTools.cloud (base URL)")
	migrateStateFlag := flag.Bool("migrate-state", false, "Create private runtime state from the operator config and exit")
	enrollTokenFlag := flag.String("enroll-token", "", "NetTools.cloud enrollment token")
	repairFlag := flag.Bool("repair", false, "Repair/Regenerate local identity")
	setClusterIDFlag := flag.String("set-cluster-id", "", "Manually set cluster ID")
	flag.Parse()
	if abs, err := filepath.Abs(configFile); err == nil {
		configFile = abs
	} else {
		log.Fatalf("[BOOT] Invalid config path: %v", err)
	}
	if abs, err := filepath.Abs(stateDir); err == nil {
		stateDir = abs
	} else {
		log.Fatalf("[BOOT] Invalid state directory: %v", err)
	}
	if err := os.Chdir(stateDir); err != nil {
		log.Fatalf("[BOOT] Cannot enter state directory %q: %v", stateDir, err)
	}
	if *migrateStateFlag {
		loadConfig()
		if !saveConfig() {
			log.Fatal("[STATE] Migration failed")
		}
		log.Print("[STATE] Runtime state ready")
		return
	}

	// ─────────────────────────────────────────────
	// 3. LICENSE + CLUSTER ID
	// ─────────────────────────────────────────────
	if *setClusterIDFlag != "" {
		if err := license.SetClusterID(*setClusterIDFlag); err != nil {
			log.Fatalf("[HoneyMesh] Failed to set Cluster ID: %v", err)
		}
		fmt.Println("Cluster ID updated. Restart required.")
		return
	}

	clusterID := license.GetOrGenerateClusterID()
	if clusterID == "" {
		log.Printf("[HoneyMesh] Active Cluster ID: (unbound)")
	} else {
		log.Printf("[HoneyMesh] Active Cluster ID: %s", clusterID)
	}

	errLicense := license.LoadAndVerify("license.json", clusterID)
	license.LoadClockState()

	if errLicense != nil {
		log.Printf("[HoneyMesh] License/Clock error: %v. Community mode active.", errLicense)
	} else {
		log.Println("[HoneyMesh] Pro license validated")
	}

	go license.StartLicenseMonitor(handleLicenseRuntimeStateChange)

	// ─────────────────────────────────────────────
	// 4. CLI MODES
	// ─────────────────────────────────────────────
	if *repairFlag {
		loadConfig()
		RepairIdentity()
		return
	}
	if *genTokenFlag {
		loadConfig()
		generateJoinToken()
		return
	}
	if *joinUrlFlag != "" {
		if *joinTokenFlag == "" {
			log.Fatal("[HoneyMesh] Join requires -t <token>")
		}
		loadConfig()
		initNodeIdentity()
		performJoin(*joinUrlFlag, *joinTokenFlag)
		return
	}
	if *registerExchangeFlag != "" {
		if *enrollTokenFlag == "" {
			log.Fatal("[HoneyMesh] NetTools registration requires -enroll-token <token>")
		}
		loadConfig()
		initNodeIdentity()
		if err := registerWithExchange(*registerExchangeFlag, *enrollTokenFlag); err != nil {
			log.Fatalf("[HoneyMesh] NetTools registration failed: %v", err)
		}
		fmt.Printf("NetTools.cloud registration complete. Node ID: %s\n", config.Exchange.NodeID)
		return
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("[BOOT] Failed to raise memlock limit: %v", err)
	}

	// ─────────────────────────────────────────────
	// 5. CORE INIT
	// ─────────────────────────────────────────────
	loadConfig()
	if config.DropPrivileges {
		if os.Geteuid() == 0 {
			log.Fatal("[SEC] drop_privileges is obsolete; start the honeymesh system service as its dedicated user")
		}
		log.Print("[SEC] drop_privileges is obsolete; process identity is managed by the system service")
	}
	if err := refreshMarketplaceLicense(); err != nil {
		log.Printf("[LICENSE] Marketplace refresh at startup: %v", err)
	}
	syncLicenseConfigState()
	initNodeIdentity()

	if config.Security.AllowlistBase != nil && *config.Security.AllowlistBase {
		initAllowlist(baseAllowlistCIDRs())
	} else {
		initAllowlist(nil)
	}

	banExpirations = make(map[string]time.Time, 4096)
	banMeta = make(map[string]BanMeta, 4096)
	lastJA4ByIP = make(map[string]string, 4096)
	lastJA3ByIP = make(map[string]string, 4096)
	scanCounts = make(map[string]map[string]time.Time, 1024)
	trapHitCounts = make(map[string][]time.Time, 1024)
	ja4Blacklist = make(map[string]time.Time, 4096)
	ja3Blacklist = make(map[string]time.Time, 4096)
	xdpLinks = make(map[string]link.Link)
	logChan = make(chan Event, 16384)
	storeChan = make(chan Event, 8192)
	remoteBanCache = make(map[string]time.Time, 4096)
	remoteAllowCache = make(map[string]time.Time, 4096)
	remoteBanSources = make(map[string]map[string]struct{}, 4096)
	exchangePublished = make(map[string]time.Time, 4096)
	exchangeSeenFeed = make(map[string]time.Time, 4096)
	exchangeObservedClusters = make(map[string]time.Time, 256)
	trapStatus = make(map[string]trapRuntime, 256)

	seedJA4BlacklistFromConfig()
	seedJA3BlacklistFromConfig()

	if config.MaxTrapConcurrency > 0 {
		trapSem = make(chan struct{}, config.MaxTrapConcurrency)
	} else {
		trapSem = make(chan struct{}, 2048)
	}

	// ─────────────────────────────────────────────
	// 6. KERNEL + DATABASE
	// ─────────────────────────────────────────────
	var bpfOpts *ebpf.CollectionOptions
	if os.Getenv("SNAP") != "" {
		kernelTypes, err := btf.LoadSpec("/sys/kernel/btf/vmlinux")
		if err != nil {
			log.Fatalf("[HoneyMesh] Failed to read kernel BTF: %v", err)
		}
		bpfOpts = &ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: kernelTypes}}
	}
	if err := loadBpfObjects(&bpfObjs, bpfOpts); err != nil {
		log.Fatalf("[HoneyMesh] Failed to load eBPF objects: %v", err)
	}
	defer bpfObjs.Close()

	// Configure event sampling rate (1 = no sampling, N = emit 1 of N allow events).
	if bpfObjs.EventSampleRate != nil {
		sample := uint32(16)
		if config.Security.EventSampleN > 0 {
			sample = uint32(config.Security.EventSampleN)
		}
		key := uint32(0)
		_ = bpfObjs.EventSampleRate.Put(key, sample)
	}

	syncWhitelist()
	initDB()
	if err := initNodeEdgeAudit(); err != nil {
		log.Fatalf("[NODE_EDGE] audit init: %v", err)
	}
	loadHistoryFromDB()
	log.Println("[BOOT]⬡ History load complete")
	log.Println("[BOOT]⬡ Loading bans from DB")
	loadBansFromDB()
	log.Println("[BOOT]⬡ Ban load complete")
	if err := startUEE(); err != nil {
		log.Fatalf("[BOOT] Unified enforcement initialization failed: %v", err)
	}
	banMutex.Lock()
	if err := refreshLegacyBanView(time.Now()); err != nil {
		banMutex.Unlock()
		log.Fatalf("[BOOT] Unified enforcement view failed: %v", err)
	}
	banMutex.Unlock()
	ruleManager, err := newExchangeRuleManager(db, nodeEdgeKernelApply, nodeEdgeKernelRemove)
	if err != nil {
		log.Fatalf("[EXCHANGE] rule ownership init: %v", err)
	}
	liveExchangeRules = ruleManager
	if err := liveExchangeRules.restore(); err != nil {
		log.Fatalf("[EXCHANGE] rule ownership restore: %v", err)
	}
	log.Println("[BOOT]⬡ Loading trust store")
	initTrustStore()
	log.Println("[BOOT]⬡ Trust store ready")

	// ─────────────────────────────────────────────
	// 7. BACKGROUND WORKERS + TRAPS
	// ─────────────────────────────────────────────
	log.Println("[BOOT]⬡ Starting background workers")
	shutdown := make(chan struct{})
	go startRingbufReader(shutdown)
	go startLogWorker(shutdown)
	go startDBWriter(shutdown)
	go startTelemetryMonitor(shutdown)
	go startScanCleanup(shutdown)
	go startBanCleanup(shutdown)
	go startJA3Cleanup(shutdown)
	go startRemoteBanCleanup(shutdown)
	go startTrustCleanup(shutdown)
	go startExchangeSyncLoop(shutdown)
	go startWatchdogLoop(shutdown)
	go startMarketplaceLicenseRefresh(shutdown)
	startTraps()
	log.Println("[BOOT]⬡ Background workers running")

	// ─────────────────────────────────────────────
	// 8. ADMIN TOKEN + BIND IP FALLBACK
	// ─────────────────────────────────────────────
	if config.AdminToken == "" {
		token, err := generateAdminToken()
		if err != nil {
			log.Fatalf("[BOOT]⬡ Failed to generate admin token: %v", err)
		}
		config.AdminToken = token
		if !saveConfig() {
			log.Fatal("[BOOT]⬡ Could not save generated admin token")
		}
		log.Printf("[BOOT]⬡ Generated and saved admin token")
	}
	if config.BindIP == "" {
		ips := getAvailableIPs()
		if len(ips) > 0 {
			config.BindIP = ips[0]
		} else {
			config.BindIP = "0.0.0.0"
		}
	}

	// ─────────────────────────────────────────────
	// 9. MESH FEDERATION
	// ─────────────────────────────────────────────
	log.Println("[HoneyMesh][Mesh] Starting trusted network controller...")

	mPort, _ := strconv.Atoi(config.MeshPort)
	if mPort == 0 {
		mPort = 9000
	}
	log.Printf("[MESH] Controller listening at %s:%d", config.BindIP, mPort)

	tlsCfg, clientTLS, err := meshTLSConfigs(config.TrustedMeshNetworkEnabled, advertiseAddr())
	if err != nil {
		log.Fatalf("[Mesh] TLS setup failed: %v", err)
	}

	statsFn := func() mesh.HeartbeatStats {
		s := localSurfaceStats()
		return mesh.HeartbeatStats{
			Traps:   s.Traps,
			Ifaces:  s.Ifaces,
			Surface: s.Surface,
			IPs:     localIfaceIPs(),
		}
	}
	strictHB := config.Security.StrictHeartbeatAddr != nil && *config.Security.StrictHeartbeatAddr
	scp, err = mesh.StartMeshServer(config.BindIP, advertiseAddr(), mPort, tlsCfg, clientTLS, handleRemoteBan, handleRemoteAllow, addPeer, statsFn, strictHB, config.Mesh.RevokedPeerCerts...)
	if err != nil {
		log.Fatalf("[MESH] Startup failed: %v", err)
	}

	if trustedMeshNetworkEnabled() {
		for _, peer := range activeMeshPeers() {
			if peer != config.BindIP && !strings.HasPrefix(peer, config.BindIP+":") {
				go scp.ConnectToPeer(peer)
			}
		}
	}
	go startMeshReconnectLoop(shutdown)

	// ─────────────────────────────────────────────
	// 10. RESTORE STATE + ATTACH INTERFACES
	// ─────────────────────────────────────────────
	// Startup defaults to TEST. Stored local bans remain pending until an
	// operator enters ENFORCE; that transition reconciles them for every tier.

	if len(config.Ifaces) > 0 {
		log.Printf("[BOOT] Attaching interfaces (%d)...", len(config.Ifaces))
	}
	for _, ifName := range config.Ifaces {
		if err := applyInterfaceMode(ifName, IfaceEnforce); err != nil {
			log.Fatalf("[BOOT] Interface attach failed: %v", err)
		}
	}
	if len(config.Ifaces) > 0 {
		log.Print("[BOOT] Interface attach complete")
	}

	// ─────────────────────────────────────────────
	// 11. DASHBOARD
	// ─────────────────────────────────────────────
	waitForTrapStartup(5 * time.Second)
	waitForRingbufStartup(5 * time.Second)
	var dashboardServer *http.Server
	if strings.ToLower(config.UIMode) == "tui" {
		// Keep logs from breaking the TUI layout.
		if f, err := os.OpenFile("tui.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
			log.SetOutput(f)
		}
		log.Print("[BOOT]⬡ Admin token available in the private configuration")
		printStartupBanner()
		go startTUI(shutdown)
	} else {
		var err error
		dashboardServer, err = startSecureDashboard(config.WebPort)
		if err != nil {
			log.Fatalf("[DASHBOARD] Startup failed: %v", err)
		}
		log.Printf("[DASHBOARD] SOC Console running on https://%s:%s", config.BindIP, config.WebPort)
		log.Print("[BOOT]⬡ Admin token available in the private configuration")
		printStartupBanner()
	}

	// ─────────────────────────────────────────────
	if err := startNodeEdgeBridge(shutdown); err != nil {
		log.Fatalf("[NODE_EDGE] bridge startup: %v", err)
	}

	// 12. GRACEFUL SHUTDOWN
	// ─────────────────────────────────────────────
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[HoneyMesh] Shutdown signal received...")
	close(shutdown)
	if scp != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = scp.Shutdown(ctx)
		cancel()
	}
	if dashboardServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = dashboardServer.Shutdown(ctx)
		cancel()
	}
	time.Sleep(200 * time.Millisecond)
	detachFirewall()
	if db != nil {
		db.Close()
	}
	os.Exit(0)
}

func init() {
	mesh.ValidateJoinToken = validateAndUseJoinToken
	mesh.MaxNodesAllowed = meshMaxNodesAllowed
	mesh.PeerConfigured = activeMeshPeerConfigured
	mesh.SharingEnabled = trustedMeshNetworkEnabled
	mesh.LocalPeerCapability = currentPeerCapability
	mesh.ValidatePeerCapability = validatePeerCapability
	mesh.ValidateBanSignal = validateTrustedNetworkSignal
	mesh.PeerCapabilityObserved = applyTrustedMeshNetworkPolicy
	mesh.PeerCount = func() int {
		return meshPeerCount()
	}
}

func meshPeerCount() int {
	seen := make(map[string]struct{})
	for _, p := range config.Mesh.Peers {
		peer := normalizePeerAddr(p)
		if peer == "" {
			continue
		}
		seen[peer] = struct{}{}
	}
	return len(seen)
}

// activeMeshPeers preserves configured order. Existing settings are retained
// after a tier change, but only peers within the current limit reconnect.
func activeMeshPeers() []string {
	max := meshMaxNodesAllowed()
	limit := max - 1
	peers := make([]string, 0, len(config.Mesh.Peers))
	seen := make(map[string]struct{}, len(config.Mesh.Peers))
	for _, raw := range config.Mesh.Peers {
		peer := normalizePeerAddr(raw)
		if peer == "" {
			continue
		}
		if _, ok := seen[peer]; ok {
			continue
		}
		if max > 0 && len(peers) >= limit {
			break
		}
		seen[peer] = struct{}{}
		peers = append(peers, peer)
	}
	return peers
}

func activeMeshPeerConfigured(peer string) bool {
	peer = normalizePeerAddr(peer)
	for _, configured := range activeMeshPeers() {
		if configured == peer {
			return true
		}
	}
	return false
}

func handleRemoteBan(peer string, signal mesh.BanSignal, observedAt time.Time) {
	emitRemoteMeshSignal(peer, signal, observedAt)
	handleRemoteReport(peer, signal, observedAt)
}

func handleRemoteAllow(peer, ip, reason string, observedAt time.Time, ttl time.Duration) {
	handleRemoteAllowReport(peer, ip, reason, observedAt, ttl)
}

func addPeer(peer string) {
	if peer == "" {
		return
	}
	if !activeMeshPeerConfigured(peer) {
		if max := meshMaxNodesAllowed(); max > 0 && 1+meshPeerCount() >= max {
			log.Printf("[MESH] Direct peer not added: node limit reached (%d direct peers)", max-1)
			return
		}
		config.Mesh.Peers = append(config.Mesh.Peers, peer)
		saveConfig()
	}
	// Auto-trust only peers that the local node can actually use.
	if host, _, err := net.SplitHostPort(peer); err == nil {
		addTrustedPeerIP(host)
	}
	broadcastPeers()
}

func removePeer(peer string) {
	if peer == "" {
		return
	}
	out := make([]string, 0, len(config.Mesh.Peers))
	for _, p := range config.Mesh.Peers {
		if p != peer {
			out = append(out, p)
		}
	}
	config.Mesh.Peers = out
	saveConfig()
}
