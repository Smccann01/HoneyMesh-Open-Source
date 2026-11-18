package mesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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

	mu         sync.Mutex
	peers      map[string]time.Time
	peersKnown map[string]time.Time
	stats      map[string]PeerStats
	caps       map[string]PeerCapability
}

// NewTrustRegistry returns a stub trust registry
func NewTrustRegistry() *TrustRegistry {
	return &TrustRegistry{}
}

// TrustRegistry is a placeholder for peer trust validation
type TrustRegistry struct{}

// StartMeshServer starts the mesh server and returns a controller.
func StartMeshServer(bindIP string, advIP string, port int, tlsCfg *tls.Config, clientTLS *tls.Config, onBan BanHandler, onAllow AllowHandler, onPeer PeerHandler, statsFn func() HeartbeatStats, strictHeartbeatAddr bool) (*Server, error) {
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
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mesh/join", s.handleJoin)
	mux.HandleFunc("/mesh/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/mesh/peers", s.handlePeers)
	mux.HandleFunc("/mesh/ban", s.handleBan)
	mux.HandleFunc("/mesh/allow", s.handleAllow)

	addr := net.JoinHostPort(bindIP, fmt.Sprintf("%d", port))
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
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
	if peer == "" {
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
	s.mu.Unlock()
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
	url := fmt.Sprintf("https://%s/mesh/join", peer)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("join rejected: %s", resp.Status)
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
	if MaxNodesAllowed != nil && PeerCount != nil {
		max := MaxNodesAllowed()
		if max > 0 && (1+PeerCount()) >= max {
			http.Error(w, "max nodes reached", http.StatusForbidden)
			return
		}
	}
	s.setPeer(addr, time.Now())
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
		now := time.Now()
		s.setPeer(addr, now)
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
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if SharingEnabled != nil && !SharingEnabled() {
			continue
		}
		payload := map[string]interface{}{
			"addr":       s.selfAddr(),
			"capability": localCapability(),
		}
		if s.statsFn != nil {
			payload["stats"] = s.statsFn()
		}
		body, _ := json.Marshal(payload)
		url := fmt.Sprintf("https://%s/mesh/heartbeat", normalizePeer(peer))
		req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
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
			urlPeers := fmt.Sprintf("https://%s/mesh/peers", normalizePeer(peer))
			reqPeers, _ := http.NewRequest("GET", urlPeers, nil)
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
	url := fmt.Sprintf("https://%s/mesh/ban", normalizePeer(peer))
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
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
	url := fmt.Sprintf("https://%s/mesh/allow", normalizePeer(peer))
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	_, _ = s.client.Do(req)
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
