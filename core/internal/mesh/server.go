package mesh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type BanSignal struct {
	SchemaVersion      string         `json:"schema_version"`
	EventID            string         `json:"event_id"`
	PublisherNodeID    string         `json:"publisher_node_id"`
	PublishedAt        string         `json:"published_at"`
	DataClassification string         `json:"data_classification"`
	Signature          string         `json:"signature"`
	Capability         PeerCapability `json:"capability"`
	IP                 string         `json:"ip"`
	Reason             string         `json:"reason"`
	JA4                string         `json:"ja4"`
	JA3                string         `json:"ja3"`
	TargetIP           string         `json:"target_ip"`
	Target             string         `json:"target"`
	Service            string         `json:"service"`
	Category           string         `json:"category"`
	EventType          string         `json:"event_type"`
	Interface          string         `json:"interface"`
	Payload            string         `json:"payload"`
}

type BanHandler func(peer string, signal BanSignal, observedAt time.Time)
type AllowHandler func(peer, ip, reason string, observedAt time.Time, ttl time.Duration)
type PeerHandler func(peer string)

type PeerCapability struct {
	SchemaVersion         string   `json:"schema_version"`
	NodeID                string   `json:"node_id"`
	TenantID              string   `json:"tenant_id"`
	ClusterID             string   `json:"cluster_id"`
	LicenseTier           string   `json:"license_tier"`
	LicenseExpiresAt      string   `json:"license_expires_at"`
	LicenseMaxNodes       int      `json:"license_max_nodes"`
	LicenseSignature      string   `json:"license_signature"`
	TrustedNetworkSharing bool     `json:"trusted_network_sharing"`
	PublicKey             string   `json:"public_key"`
	Capabilities          []string `json:"capabilities"`
}

type HeartbeatStats struct {
	Traps   int      `json:"traps"`
	Ifaces  int      `json:"ifaces"`
	Surface int      `json:"surface"`
	IPs     []string `json:"ips"`
}

type PeerStats struct {
	LastSeen time.Time
	Stats    HeartbeatStats
}

const peerStaleTTL = 80 * time.Second

// Server represents a HoneyMesh federation node.
type Server struct {
	httpServer          *http.Server
	bindIP              string
	advIP               string
	port                int
	tlsCfg              *tls.Config
	client              *http.Client
	onBan               BanHandler
	onAllow             AllowHandler
	onPeer              PeerHandler
	statsFn             func() HeartbeatStats
	strictHeartbeatAddr bool
	admissionMu         sync.Mutex

	mu           sync.Mutex
	peers        map[string]time.Time
	peersKnown   map[string]time.Time
	stats        map[string]PeerStats
	caps         map[string]PeerCapability
	peerCerts    map[string]string
	revokedCerts map[string]struct{}
}

// NewTrustRegistry returns a stub trust registry
func NewTrustRegistry() *TrustRegistry {
	return &TrustRegistry{}
}

// TrustRegistry is a placeholder for peer trust validation
type TrustRegistry struct{}

// StartMeshServer starts the mesh server and returns a controller.
func StartMeshServer(bindIP string, advIP string, port int, tlsCfg *tls.Config, clientTLS *tls.Config, onBan BanHandler, onAllow AllowHandler, onPeer PeerHandler, statsFn func() HeartbeatStats, strictHeartbeatAddr bool, revokedFingerprints ...string) (*Server, error) {
	if tlsCfg == nil || clientTLS == nil {
		return nil, fmt.Errorf("mesh TLS configuration is required")
	}
	s := &Server{
		bindIP: bindIP,
		advIP:  advIP,
		port:   port,
		tlsCfg: tlsCfg,
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: clientTLS,
			},
		},
		onBan:               onBan,
		onAllow:             onAllow,
		onPeer:              onPeer,
		statsFn:             statsFn,
		strictHeartbeatAddr: strictHeartbeatAddr,
		peers:               make(map[string]time.Time),
		peersKnown:          make(map[string]time.Time),
		stats:               make(map[string]PeerStats),
		caps:                make(map[string]PeerCapability),
		peerCerts:           make(map[string]string),
		revokedCerts:        make(map[string]struct{}),
	}
	for _, fingerprint := range revokedFingerprints {
		if fingerprint != "" {
			s.revokedCerts[fingerprint] = struct{}{}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mesh/join", s.handleJoin)
	mux.HandleFunc("/mesh/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/mesh/peers", s.handlePeers)
	mux.HandleFunc("/mesh/ban", s.handleBan)
	mux.HandleFunc("/mesh/allow", s.handleAllow)

	addr := net.JoinHostPort(bindIP, fmt.Sprintf("%d", port))
	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.isRevokedCertificate(r) {
				http.Error(w, "peer certificate revoked", http.StatusForbidden)
				return
			}
			mux.ServeHTTP(w, r)
		}),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on mesh address %s: %w", addr, err)
	}
	s.httpServer = srv

	go func() {
		if err := srv.Serve(tls.NewListener(listener, tlsCfg)); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[MESH] Server failed: %v", err)
		}
	}()

	return s, nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

// ConnectToPeer establishes a heartbeat loop with a peer.
func (s *Server) ConnectToPeer(peer string) {
	if SharingEnabled != nil && !SharingEnabled() {
		return
	}
	if MaxNodesAllowed != nil && MaxNodesAllowed() > 0 && PeerConfigured != nil && !PeerConfigured(peer) {
		return
	}
	if peer == "" {
		return
	}
	if _, err := meshPeerURL(peer, "/mesh/heartbeat"); err != nil {
		return
	}
	if normalizePeer(peer) == s.selfAddr() {
		return
	}
	s.addKnownPeer(peer, time.Now())
	go s.heartbeatLoop(peer)
}

// BroadcastBan sends a ban to all peers.
func (s *Server) BroadcastBan(signal BanSignal) {
	if SharingEnabled != nil && !SharingEnabled() {
		return
	}
	s.mu.Lock()
	peers := make([]string, 0, len(s.peers))
	for p := range s.peers {
		if MaxNodesAllowed != nil && MaxNodesAllowed() > 0 && PeerConfigured != nil && !PeerConfigured(p) {
			continue
		}
		peers = append(peers, p)
	}
	s.mu.Unlock()

	for _, p := range peers {
		go s.sendBan(p, signal)
	}
}

// BroadcastAllow sends an allow to all peers.
func (s *Server) BroadcastAllow(ip string, reason string, ttl time.Duration) {
	if SharingEnabled != nil && !SharingEnabled() {
		return
	}
	s.mu.Lock()
	peers := make([]string, 0, len(s.peers))
	for p := range s.peers {
		if MaxNodesAllowed != nil && MaxNodesAllowed() > 0 && PeerConfigured != nil && !PeerConfigured(p) {
			continue
		}
		peers = append(peers, p)
	}
	s.mu.Unlock()

	for _, p := range peers {
		go s.sendAllow(p, ip, reason, ttl)
	}
}

// PeerCount returns the number of peers seen recently.
func (s *Server) PeerCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupPeersLocked()
	return len(s.peers)
}

// KnownPeerCount returns the number of peers known (online or offline).
func (s *Server) KnownPeerCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.peersKnown)
}

// PeerStats returns peer address and last-seen timestamp.
func (s *Server) PeerStats() map[string]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupPeersLocked()
	out := make(map[string]time.Time, len(s.peers))
	for p, ts := range s.peers {
		out[p] = ts
	}
	return out
}

// KnownPeers returns a list of known peer addresses.
func (s *Server) KnownPeers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.peersKnown))
	for p := range s.peersKnown {
		out = append(out, p)
	}
	return out
}

// KnownPeerStats returns discovery timestamps for known peers.
func (s *Server) KnownPeerStats() map[string]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]time.Time, len(s.peersKnown))
	for p, ts := range s.peersKnown {
		out[p] = ts
	}
	return out
}

// RemovePeer deletes a peer from the set.
func (s *Server) RemovePeer(peer string) {
	p := normalizePeer(peer)
	s.mu.Lock()
	delete(s.peers, p)
	delete(s.peersKnown, p)
	delete(s.stats, p)
	delete(s.caps, p)
	delete(s.peerCerts, p)
	s.mu.Unlock()
}

// RevokePeer denies all future requests made with an enrolled peer's certificate.
// The returned fingerprint must be persisted by the caller before success is reported.
func (s *Server) RevokePeer(peer string) (string, bool) {
	p := normalizePeer(peer)
	s.mu.Lock()
	defer s.mu.Unlock()
	fingerprint := s.peerCerts[p]
	if fingerprint == "" {
		return "", false
	}
	s.revokedCerts[fingerprint] = struct{}{}
	delete(s.peers, p)
	delete(s.peersKnown, p)
	delete(s.stats, p)
	delete(s.caps, p)
	delete(s.peerCerts, p)
	return fingerprint, true
}

func peerCertificateFingerprint(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:])
}

func (s *Server) isRevokedCertificate(r *http.Request) bool {
	fingerprint := peerCertificateFingerprint(r)
	if fingerprint == "" {
		return false
	}
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	s.mu.Lock()
	_, revoked := s.revokedCerts[fingerprint]
	s.mu.Unlock()
	return revoked
}

func (s *Server) recordPeerCertificate(peer string, r *http.Request) {
	if fingerprint := peerCertificateFingerprint(r); fingerprint != "" {
		s.mu.Lock()
		s.peerCerts[normalizePeer(peer)] = fingerprint
		s.mu.Unlock()
	}
}

// A finite direct-peer limit also gates intelligence and discovery requests.
// The mTLS certificate must belong to one of this node's admitted peers.
func (s *Server) admittedDirectPeerRequest(r *http.Request) bool {
	if MaxNodesAllowed == nil || MaxNodesAllowed() <= 0 || PeerConfigured == nil {
		return true
	}
	fingerprint := peerCertificateFingerprint(r)
	if fingerprint == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for peer, known := range s.peerCerts {
		if known == fingerprint && PeerConfigured(peer) {
			return true
		}
	}
	return false
}

// Join sends a join request to a peer.
func (s *Server) Join(peer string, token string, addr string) error {
	payload := struct {
		Token      string         `json:"token"`
		Addr       string         `json:"addr"`
		Capability PeerCapability `json:"capability"`
	}{
		Token:      token,
		Addr:       addr,
		Capability: localCapability(),
	}
	body, _ := json.Marshal(payload)
	url, err := meshPeerURL(peer, "/mesh/join")
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("join rejected: %s", resp.Status)
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		fingerprint := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
		s.mu.Lock()
		if s.peerCerts == nil {
			s.peerCerts = make(map[string]string)
		}
		s.peerCerts[normalizePeer(peer)] = hex.EncodeToString(fingerprint[:])
		s.mu.Unlock()
	}
	var out struct {
		Peers []string `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err == nil {
		for _, p := range out.Peers {
			s.addKnownPeer(p, time.Time{})
		}
	}
	return nil
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	if SharingEnabled != nil && !SharingEnabled() {
		http.Error(w, "trusted network sharing disabled", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token      string         `json:"token"`
		Addr       string         `json:"addr"`
		Capability PeerCapability `json:"capability"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Token == "" || req.Addr == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := validateCapability(req.Capability); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if ValidateJoinToken == nil || !ValidateJoinToken(req.Token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	addr := normalizeAddrFromReq(req.Addr, r.RemoteAddr)
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	if !s.reserveDirectPeer(addr, false) {
		http.Error(w, "direct peer limit reached", http.StatusForbidden)
		return
	}
	s.setPeer(addr, time.Now())
	s.recordPeerCertificate(addr, r)
	s.setCapability(addr, req.Capability)
	s.addKnownPeer(addr, time.Now())
	if s.onPeer != nil {
		s.onPeer(addr)
	}
	peers := s.peerList()
	_ = json.NewEncoder(w).Encode(map[string][]string{"peers": peers})
}

// ValidateJoinToken is set by the main package.
var ValidateJoinToken func(token string) bool

// MaxNodesAllowed returns the license max node count.
var MaxNodesAllowed func() int

// PeerCount returns current peer count.
var PeerCount func() int

// PeerConfigured reports whether this address is among the currently selected
// direct peers. A Community downgrade retains, but does not connect, extras.
var PeerConfigured func(peer string) bool

// reserveDirectPeer serializes admission with the caller's onPeer callback.
// An active slot is reserved before the configured peer list is updated.
func (s *Server) reserveDirectPeer(peer string, requireConfigured bool) bool {
	max := 0
	if MaxNodesAllowed != nil {
		max = MaxNodesAllowed()
	}
	if max <= 0 {
		return true
	}
	p := normalizePeer(peer)
	if requireConfigured && PeerConfigured != nil && !PeerConfigured(p) {
		return false // a heartbeat cannot replace an operator-approved join
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if PeerConfigured != nil && PeerConfigured(p) {
		return true
	}
	configured := 0
	if PeerCount != nil {
		configured = PeerCount()
	}
	// After a downgrade, a previously active extra peer must not retain a
	// slot merely because it remains in memory.
	if configured >= max-1 {
		return false
	}
	if _, active := s.peers[p]; !active && len(s.peers) >= max-1 {
		return false
	}
	if s.peers == nil {
		s.peers = make(map[string]time.Time)
	}
	s.peers[p] = time.Now()
	return true
}

// SharingEnabled reports whether trusted network participation is active.
var SharingEnabled func() bool

// PeerCapabilityObserved is set by the main package.
var PeerCapabilityObserved func(peer string, cap PeerCapability)

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if SharingEnabled != nil && !SharingEnabled() {
		http.Error(w, "trusted network sharing disabled", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Addr       string         `json:"addr"`
		Stats      HeartbeatStats `json:"stats"`
		Capability PeerCapability `json:"capability"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Addr != "" {
		if err := validateCapability(req.Capability); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if s.strictHeartbeatAddr {
			remoteHost := ""
			if rh, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				remoteHost = rh
			}
			addrHost := ""
			if h, _, err := net.SplitHostPort(req.Addr); err == nil {
				addrHost = h
			} else {
				addrHost = req.Addr
			}
			addrHost = strings.TrimSpace(addrHost)
			if addrHost != "" && addrHost != "0.0.0.0" && addrHost != "::" && remoteHost != "" && addrHost != remoteHost {
				log.Printf("[MESH] Heartbeat addr mismatch addr=%s remote=%s", req.Addr, remoteHost)
				return
			}
		}
		addr := normalizeAddrFromReq(req.Addr, r.RemoteAddr)
		s.admissionMu.Lock()
		defer s.admissionMu.Unlock()
		if !s.reserveDirectPeer(addr, true) {
			http.Error(w, "direct peer limit reached", http.StatusForbidden)
			return
		}
		now := time.Now()
		s.setPeer(addr, now)
		s.recordPeerCertificate(addr, r)
		s.setCapability(addr, req.Capability)
		s.addKnownPeer(addr, time.Now())
		s.mu.Lock()
		stats := req.Stats
		if stats.Surface == 0 && stats.Traps > 0 && stats.Ifaces > 0 {
			stats.Surface = stats.Traps * stats.Ifaces
		}
		s.stats[normalizePeer(addr)] = PeerStats{
			LastSeen: now,
			Stats:    stats,
		}
		s.mu.Unlock()
		if s.onPeer != nil {
			s.onPeer(addr)
		}
	}
	s.mu.Lock()
	s.cleanupPeersLocked()
	peers := make(map[string]int64, len(s.peers))
	for p, ts := range s.peers {
		peers[p] = ts.Unix()
	}
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"peers":  peers,
	})
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	if SharingEnabled != nil && !SharingEnabled() {
		http.Error(w, "trusted network sharing disabled", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.admittedDirectPeerRequest(r) {
		http.Error(w, "direct peer not admitted", http.StatusForbidden)
		return
	}
	peers := s.KnownPeers()
	_ = json.NewEncoder(w).Encode(map[string][]string{"peers": peers})
}

func (s *Server) handleBan(w http.ResponseWriter, r *http.Request) {
	if SharingEnabled != nil && !SharingEnabled() {
		http.Error(w, "trusted network sharing disabled", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.admittedDirectPeerRequest(r) {
		http.Error(w, "direct peer not admitted", http.StatusForbidden)
		return
	}
	var req struct {
		BanSignal
		ObservedAt string `json:"observed_at"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.BanSignal.IP == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var observed time.Time
	if req.ObservedAt != "" {
		if ts, err := time.Parse(time.RFC3339, req.ObservedAt); err == nil {
			observed = ts
		}
	}
	if s.onBan != nil {
		peer := normalizePeer(r.RemoteAddr)
		if ValidateBanSignal != nil {
			if err := ValidateBanSignal(peer, req.BanSignal); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
		}
		s.onBan(peer, req.BanSignal, observed)
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleAllow(w http.ResponseWriter, r *http.Request) {
	if SharingEnabled != nil && !SharingEnabled() {
		http.Error(w, "trusted network sharing disabled", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.admittedDirectPeerRequest(r) {
		http.Error(w, "direct peer not admitted", http.StatusForbidden)
		return
	}
	var req struct {
		IP         string `json:"ip"`
		Reason     string `json:"reason"`
		ObservedAt string `json:"observed_at"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var observed time.Time
	if req.ObservedAt != "" {
		if ts, err := time.Parse(time.RFC3339, req.ObservedAt); err == nil {
			observed = ts
		}
	}
	if s.onAllow != nil {
		peer := normalizePeer(r.RemoteAddr)
		var ttl time.Duration
		if req.TTLSeconds > 0 {
			ttl = time.Duration(req.TTLSeconds) * time.Second
		}
		s.onAllow(peer, req.IP, req.Reason, observed, ttl)
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) setPeer(peer string, ts time.Time) {
	p := normalizePeer(peer)
	s.mu.Lock()
	s.peers[p] = ts
	if _, ok := s.peersKnown[p]; !ok {
		s.peersKnown[p] = ts
	}
	if ps, ok := s.stats[p]; ok {
		ps.LastSeen = ts
		s.stats[p] = ps
	}
	s.mu.Unlock()
}

func (s *Server) addKnownPeer(peer string, ts time.Time) {
	p := normalizePeer(peer)
	if p == "" {
		return
	}
	s.mu.Lock()
	if _, ok := s.peersKnown[p]; !ok {
		if ts.IsZero() {
			ts = time.Now()
		}
		s.peersKnown[p] = ts
	}
	s.mu.Unlock()
}

func (s *Server) setCapability(peer string, cap PeerCapability) {
	p := normalizePeer(peer)
	if p == "" {
		return
	}
	s.mu.Lock()
	s.caps[p] = cap
	s.mu.Unlock()
	if PeerCapabilityObserved != nil {
		PeerCapabilityObserved(p, cap)
	}
}

func (s *Server) peerList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.peers))
	for p := range s.peers {
		if MaxNodesAllowed != nil && MaxNodesAllowed() > 0 && PeerConfigured != nil && !PeerConfigured(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// PeerStatsDetailed returns last-seen and latest heartbeat stats.
func (s *Server) PeerStatsDetailed() map[string]PeerStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupPeersLocked()
	out := make(map[string]PeerStats, len(s.stats))
	for p, st := range s.stats {
		out[p] = st
	}
	return out
}

// PeerCapabilities returns the latest advertised capability per peer.
func (s *Server) PeerCapabilities() map[string]PeerCapability {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]PeerCapability, len(s.caps))
	for p, cap := range s.caps {
		out[p] = cap
	}
	return out
}

// SurfaceTotal returns the sum of peer-reported surface values.
func (s *Server) SurfaceTotal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupPeersLocked()
	total := 0
	for _, st := range s.stats {
		if st.Stats.Surface > 0 {
			total += st.Stats.Surface
			continue
		}
		if st.Stats.Traps > 0 && st.Stats.Ifaces > 0 {
			total += st.Stats.Traps * st.Stats.Ifaces
		}
	}
	return total
}

func (s *Server) cleanupPeersLocked() {
	if len(s.peers) == 0 {
		// still clean known peers
	}
	now := time.Now()
	for p, ts := range s.peers {
		if now.Sub(ts) > peerStaleTTL {
			delete(s.peers, p)
			delete(s.stats, p)
		}
	}
	for p, ts := range s.peersKnown {
		if _, ok := s.peers[p]; ok {
			continue
		}
		if ts.IsZero() {
			continue
		}
		if now.Sub(ts) > peerStaleTTL {
			delete(s.peersKnown, p)
		}
	}
}

func (s *Server) heartbeatLoop(peer string) {
	heartbeatURL, err := meshPeerURL(peer, "/mesh/heartbeat")
	if err != nil {
		return
	}
	peersURL, err := meshPeerURL(peer, "/mesh/peers")
	if err != nil {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if SharingEnabled != nil && !SharingEnabled() {
			continue
		}
		if MaxNodesAllowed != nil && MaxNodesAllowed() > 0 && PeerConfigured != nil && !PeerConfigured(peer) {
			return
		}
		payload := map[string]interface{}{
			"addr":       s.selfAddr(),
			"capability": localCapability(),
		}
		if s.statsFn != nil {
			payload["stats"] = s.statsFn()
		}
		body, _ := json.Marshal(payload)
		req, err := http.NewRequest("POST", heartbeatURL, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		func() {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			var out struct {
				Peers map[string]int64 `json:"peers"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&out); err == nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
		}()

		go func() {
			reqPeers, err := http.NewRequest("GET", peersURL, nil)
			if err != nil {
				return
			}
			respPeers, err := s.client.Do(reqPeers)
			if err != nil {
				return
			}
			defer respPeers.Body.Close()
			if respPeers.StatusCode != http.StatusOK {
				return
			}
			var outPeers struct {
				Peers []string `json:"peers"`
			}
			if err := json.NewDecoder(respPeers.Body).Decode(&outPeers); err != nil {
				return
			}
			for _, p := range outPeers.Peers {
				if p == "" {
					continue
				}
				s.addKnownPeer(p, time.Time{})
			}
		}()
	}
}

func (s *Server) sendBan(peer string, signal BanSignal) {
	if SharingEnabled != nil && !SharingEnabled() {
		return
	}
	body, _ := json.Marshal(struct {
		BanSignal
		ObservedAt string `json:"observed_at"`
	}{
		BanSignal:  signal,
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
	})
	url, err := meshPeerURL(peer, "/mesh/ban")
	if err != nil {
		log.Printf("[MESH] Ban broadcast skipped invalid peer=%q", peer)
		return
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("[MESH] Ban broadcast failed peer=%s ip=%s err=%v", peer, signal.IP, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[MESH] Ban broadcast rejected peer=%s ip=%s status=%s", peer, signal.IP, resp.Status)
	}
}

func (s *Server) sendAllow(peer, ip, reason string, ttl time.Duration) {
	if SharingEnabled != nil && !SharingEnabled() {
		return
	}
	ttlSeconds := 0
	if ttl > 0 {
		ttlSeconds = int(ttl.Seconds())
	}
	body, _ := json.Marshal(map[string]string{
		"ip":          ip,
		"reason":      reason,
		"observed_at": time.Now().UTC().Format(time.RFC3339),
	})
	if ttlSeconds > 0 {
		body, _ = json.Marshal(map[string]interface{}{
			"ip":          ip,
			"reason":      reason,
			"observed_at": time.Now().UTC().Format(time.RFC3339),
			"ttl_seconds": ttlSeconds,
		})
	}
	url, err := meshPeerURL(peer, "/mesh/allow")
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func (s *Server) selfAddr() string {
	ip := s.bindIP
	if s.advIP != "" && s.advIP != "0.0.0.0" && s.advIP != "::" {
		ip = s.advIP
	}
	return normalizePeer(fmt.Sprintf("%s:%d", ip, s.port))
}

func (s *Server) ClearPeerState() {
	s.mu.Lock()
	s.peers = make(map[string]time.Time)
	s.peersKnown = make(map[string]time.Time)
	s.stats = make(map[string]PeerStats)
	s.caps = make(map[string]PeerCapability)
	s.mu.Unlock()
}

// LocalPeerCapability is set by the main package.
var LocalPeerCapability func() PeerCapability

// ValidatePeerCapability is set by the main package.
var ValidatePeerCapability func(PeerCapability) error

// ValidateBanSignal is set by the main package.
var ValidateBanSignal func(peer string, signal BanSignal) error

func localCapability() PeerCapability {
	if LocalPeerCapability == nil {
		return PeerCapability{}
	}
	return LocalPeerCapability()
}

func validateCapability(cap PeerCapability) error {
	if ValidatePeerCapability == nil {
		return nil
	}
	return ValidatePeerCapability(cap)
}

func normalizePeer(p string) string {
	p = strings.TrimSpace(p)
	if h, _, err := net.SplitHostPort(p); err == nil {
		p = h
	}
	if !strings.Contains(p, ":") {
		return p + ":9000"
	}
	return p
}

// meshPeerURL accepts only an IP literal and an optional port. Mesh peers may
// use private IPs, so TLS authentication and the explicit join token remain
// required; rejecting URLs and hostnames prevents authority injection and DNS rebinding.
func meshPeerURL(peer, path string) (string, error) {
	peer = strings.TrimSpace(peer)
	addrPort, err := netip.ParseAddrPort(peer)
	if err != nil {
		addr, parseErr := netip.ParseAddr(peer)
		if parseErr != nil {
			return "", fmt.Errorf("mesh peer must be an IP address with an optional port")
		}
		addrPort = netip.AddrPortFrom(addr, 9000)
	}
	addr := addrPort.Addr()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.Zone() != "" || addrPort.Port() == 0 {
		return "", fmt.Errorf("invalid mesh peer address")
	}
	return "https://" + addrPort.String() + path, nil
}

func normalizeAddrFromReq(addr string, remoteAddr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "9000"
	}
	if host == "0.0.0.0" || host == "::" || host == "" {
		if rh, _, err := net.SplitHostPort(remoteAddr); err == nil && rh != "" {
			host = rh
		}
	}
	return normalizePeer(fmt.Sprintf("%s:%s", host, port))
}
