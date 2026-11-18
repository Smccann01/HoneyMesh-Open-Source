package main

import (
	"database/sql"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/link"
	"honeymesh/internal/mesh"
)

// ────────────────────────────────────────────────
// TYPES
// ────────────────────────────────────────────────

type Config struct {
	NodeName                     string                `json:"node_name"`
	BindIP                       string                `json:"bind_ip"`
	WebPort                      string                `json:"web_port"`
	UIMode                       string                `json:"ui_mode"`
	MeshPort                     string                `json:"mesh_port"`
	MeshSecret                   string                `json:"mesh_secret"`
	Ifaces                       []string              `json:"interfaces"`
	Traps                        map[string]*TrapState `json:"traps"`
	AdminToken                   string                `json:"admin_token"`
	MaxTrapConcurrency           int                   `json:"max_trap_concurrency"`
	DropPrivileges               bool                  `json:"drop_privileges"`
	DropUser                     string                `json:"drop_user"`
	DropGroup                    string                `json:"drop_group"`
	LicenseTier                  string                `json:"license_tier"`
	Marketplace                  MarketplaceConfig     `json:"marketplace"`
	TrustedNetworkSharingEnabled bool                  `json:"trusted_network_sharing_enabled"`
	TrustedMeshNetworkEnabled    bool                  `json:"trusted_mesh_network_enabled"`

	Mesh      MeshConfig     `json:"mesh"`
	Exchange  ExchangeConfig `json:"exchange"`
	Security  SecurityConfig `json:"security"`
	GeoPolicy GeoPolicy      `json:"geo_policy"`
}

type MarketplaceConfig struct {
	RefreshURL string `json:"refresh_url"`
	NodeToken  string `json:"node_token"`
}

type MeshConfig struct {
	Peers              []string             `json:"peers"`
	TLS                MeshTLSConfig        `json:"tls"`
	Quorum             float64              `json:"quorum"`
	MinPeers           int                  `json:"min_peers"`
	AuthoritativePeers []string             `json:"authoritative_peers"`
	TrustedNetworks    []TrustedMeshNetwork `json:"trusted_networks"`
	RevokedPeerCerts   []string             `json:"revoked_peer_certs,omitempty"`
}

type MeshTLSConfig struct {
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	PeerCAFile   string `json:"peer_ca_file"`
	ClientCAFile string `json:"client_ca_file"`
}

type TrustedMeshNetwork struct {
	ClusterID  string `json:"cluster_id"`
	TrustLevel int    `json:"trust_level"`
}

type ExchangeConfig struct {
	Enabled          bool     `json:"enabled"`
	BaseURL          string   `json:"base_url"`
	NodeID           string   `json:"node_id"`
	TenantID         string   `json:"tenant_id"`
	SharedSecret     string   `json:"shared_secret"`
	TrustedClusters  []string `json:"trusted_clusters"`
	PullIntervalS    int      `json:"pull_interval_s"`
	PushLocalBans    bool     `json:"push_local_bans"`
	PullSharedFeed   bool     `json:"pull_shared_feed"`
	TrustThreshold   int      `json:"trust_threshold"`
	FeedCursor       string   `json:"feed_cursor"`
	RetractionCursor int64    `json:"retraction_cursor"`
	LastRegistered   string   `json:"last_registered_at"`
}

type SecurityConfig struct {
	CACert                   string            `json:"ca_cert"`
	CertFile                 string            `json:"cert_file"`
	KeyFile                  string            `json:"key_file"`
	AllowlistBase            *bool             `json:"allowlist_base"`
	Whitelist                []string          `json:"whitelist"`
	TrustedPeers             []string          `json:"trusted_peers"`
	JA4Blacklist             []string          `json:"ja4_blacklist"`
	JA4Labels                map[string]string `json:"ja4_labels"`
	JA3Blacklist             []string          `json:"ja3_blacklist"`
	JA3Labels                map[string]string `json:"ja3_labels"`
	JA3Ports                 []string          `json:"ja3_ports"`
	JA3MaxBytes              int               `json:"ja3_max_bytes"`
	JA3TimeoutMs             int               `json:"ja3_timeout_ms"`
	EventSampleN             int               `json:"event_sample_n"`
	MeshEventRateLimitPerMin int               `json:"mesh_event_rate_limit_per_min"`
	MeshEventBurst           int               `json:"mesh_event_burst"`
	MeshReplayWindowS        int               `json:"mesh_replay_window_s"`
	MeshDataClassification   string            `json:"mesh_data_classification"`
	ScanPorts                int               `json:"scan_ports"`
	ScanWindowS              int               `json:"scan_window_s"`
	StrictHeartbeatAddr      *bool             `json:"strict_heartbeat_addr"`
	TrapBanHits              int               `json:"trap_ban_hits"`
	TrapBanWindowS           int               `json:"trap_ban_window_s"`
}

type GeoPolicy struct {
	Enabled   bool     `json:"enabled"`
	Mode      string   `json:"mode"`
	Countries []string `json:"countries"`
}

// ────────────────────────────────────────────────
// TRAPS + EVENTS
// ────────────────────────────────────────────────

type TrapState struct {
	Enabled     bool   `json:"enabled"`
	Watchdog    bool   `json:"watchdog"`
	Tarpit      bool   `json:"tarpit"`
	TarpitDelay string `json:"tarpit_delay"`
	Banner      string `json:"banner"`
	Proto       string `json:"proto"`
	MaxConns    int    `json:"max_conns"`

	// runtime
	IsRunning bool          `json:"-"`
	stopChan  chan struct{} `json:"-"`
	listeners []io.Closer   `json:"-"`
	mu        sync.Mutex    `json:"-"`
	connSem   chan struct{} `json:"-"`
}

type trapRuntime struct {
	Running        bool
	LastError      string
	WatchdogActive bool
}

type Event struct {
	Timestamp                string  `json:"timestamp"`
	Attacker                 string  `json:"attacker"`
	TargetIP                 string  `json:"target_ip"`
	Target                   string  `json:"target"`
	Service                  string  `json:"service"`
	Node                     string  `json:"node"`
	Type                     string  `json:"type"`
	Payload                  string  `json:"payload"`
	Entropy                  float64 `json:"entropy"`
	Interface                string  `json:"interface"`
	JA4                      string  `json:"ja4"`
	JA3                      string  `json:"ja3"`
	TLSFingerprintFamily     string  `json:"tls_fingerprint_family"`
	TLSFingerprintVersion    string  `json:"tls_fingerprint_version"`
	TLSFingerprintConfidence int     `json:"tls_fingerprint_confidence"`
}

type BanMeta struct {
	JA4      string `json:"ja4"`
	JA3      string `json:"ja3"`
	Reason   string `json:"reason"`
	Category string `json:"category"`
}

// ────────────────────────────────────────────────
// MODE
// ────────────────────────────────────────────────

type ModeType int

const (
	ModeTest     ModeType = 0
	ModeEnforce  ModeType = 1
	ModeLockdown ModeType = 2
)

func (m ModeType) String() string {
	switch m {
	case ModeTest:
		return "TEST"
	case ModeEnforce:
		return "ENFORCE"
	case ModeLockdown:
		return "LOCKDOWN"
	default:
		return "UNKNOWN"
	}
}

// ────────────────────────────────────────────────
// INTERFACE MODES
// ────────────────────────────────────────────────

type IfaceMode string

const (
	IfaceOff     IfaceMode = "off"
	IfaceMonitor IfaceMode = "monitor"
	IfaceEnforce IfaceMode = "enforce"
	IfaceIsolate IfaceMode = "isolate"
)

var IfaceStates = struct {
	M map[string]IfaceMode
	sync.RWMutex
}{
	M: make(map[string]IfaceMode),
}

func GetIfaceMode(iface string) IfaceMode {
	IfaceStates.RLock()
	defer IfaceStates.RUnlock()
	return IfaceStates.M[iface]
}

func SetIfaceMode(iface string, mode IfaceMode) {
	IfaceStates.Lock()
	IfaceStates.M[iface] = mode
	IfaceStates.Unlock()
}

// ────────────────────────────────────────────────
// GLOBALS
// ────────────────────────────────────────────────

var (
	configFile string
	stateDir   string
	configDir  string
	config     Config

	db *sql.DB

	bpfObjs bpfObjects

	banExpirations map[string]time.Time
	banMeta        map[string]BanMeta
	lastJA4ByIP    map[string]string
	lastJA3ByIP    map[string]string
	scanCounts     map[string]map[string]time.Time
	trapHitCounts  map[string][]time.Time
	ja4Blacklist   map[string]time.Time
	ja3Blacklist   map[string]time.Time

	xdpLinks map[string]link.Link

	logChan  chan Event
	eventLog []Event
	eventIdx int
	eventCnt int

	banMutex  sync.Mutex
	banMetaMu sync.Mutex
	ja4IPMu   sync.Mutex
	ja3IPMu   sync.Mutex
	scanMu    sync.Mutex
	trapMu    sync.Mutex
	ja4Mu     sync.Mutex
	ja3Mu     sync.Mutex
	logMutex  sync.Mutex

	ModeMu           sync.RWMutex
	modeTransitionMu sync.Mutex
	GlobalMode       ModeType = ModeTest

	droppedTelemetry atomic.Int64
	droppedDB        atomic.Int64

	scp *mesh.Server

	allowCIDRs     []*net.IPNet
	whitelistCIDRs []*net.IPNet
	trustedCIDRs   []*net.IPNet
	whitelistMu    sync.RWMutex

	trapSem chan struct{}

	remoteBanCache   map[string]time.Time
	remoteBanMu      sync.Mutex
	remoteAllowCache map[string]time.Time
	remoteAllowMu    sync.Mutex
	remoteBanSources map[string]map[string]struct{}

	meshThreats  atomic.Uint64
	localThreats atomic.Uint64

	storeChan chan Event

	trapStatusMu sync.Mutex
	trapStatus   map[string]trapRuntime

	trapStartupExpected int32
	trapStartupCount    int32
	trapStartupOnce     sync.Once
	trapStartupDone     = make(chan struct{})

	ringbufStartupOnce sync.Once
	ringbufStartupDone = make(chan struct{})

	nodeID string

	exchangeStatusMu         sync.Mutex
	exchangeStatusText       string
	exchangeLastPush         time.Time
	exchangeLastPull         time.Time
	exchangeLastHeartbeat    time.Time
	exchangePublished        map[string]time.Time
	exchangeSeenFeed         map[string]time.Time
	exchangeObservedClusters map[string]time.Time

	startTime = time.Now()
)

// ────────────────────────────────────────────────
// HELPERS
// ────────────────────────────────────────────────

func Mode() ModeType {
	ModeMu.RLock()
	defer ModeMu.RUnlock()
	return GlobalMode
}

func SetMode(m ModeType) error {
	modeTransitionMu.Lock()
	defer modeTransitionMu.Unlock()
	banMutex.Lock()
	from := Mode()
	var err error
	if liveUEE != nil {
		err = liveUEE.SetEnabled(m != ModeTest, time.Now())
	} else {
		err = reconcileLegacyBansForMode(from, m)
	}
	if err != nil {
		banMutex.Unlock()
		return err
	}
	ModeMu.Lock()
	GlobalMode = m
	ModeMu.Unlock()
	banMutex.Unlock()
	if liveUEE != nil {
		banMutex.Lock()
		err := refreshLegacyBanView(time.Now())
		banMutex.Unlock()
		if err != nil {
			return err
		}
	}
	if m != ModeEnforce {
		if err := releaseNodeEdgeBlocks("mode_change"); err != nil {
			return err
		}
		if liveExchangeRules != nil {
			return liveExchangeRules.releaseAll()
		}
	}
	return nil
}
