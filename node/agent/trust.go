package main

import (
	"errors"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	"honeymesh/internal/mesh"
)

const (
	trustLevel0 = 0
	trustLevel1 = 1
	trustLevel2 = 2
	trustLevel3 = 3
)

const (
	trustDecayK           = 0.03
	trustSecondOpinionTTL = 10 * time.Minute
	defaultAllowTTL       = 24 * time.Hour
)

type peerTrust struct {
	Peer       string
	Score      float64
	Total      int
	Valid      int
	Invalid    int
	LastReport time.Time
}

type pendingBan struct {
	IP        string
	Reason    string
	JA4       string
	JA3       string
	FirstSeen time.Time
	Sources   map[string]time.Time
}

var (
	trustMu       sync.Mutex
	trustByPeer   map[string]*peerTrust
	pendingMu     sync.Mutex
	pendingByIP   map[string]*pendingBan
	trustInitOnce sync.Once
)

func initTrustStore() {
	trustInitOnce.Do(func() {
		trustByPeer = make(map[string]*peerTrust)
		pendingByIP = make(map[string]*pendingBan)
		loadPeerTrustFromDB()
	})
}

func isAuthoritativePeer(peer string) bool {
	peer = normalizePeerAddr(peer)
	for _, p := range config.Mesh.AuthoritativePeers {
		if normalizePeerAddr(p) == peer {
			return true
		}
	}
	return false
}

func normalizePeerAddr(peer string) string {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return peer
	}
	if strings.HasPrefix(peer, "https://") {
		peer = strings.TrimPrefix(peer, "https://")
	}
	if idx := strings.Index(peer, "/"); idx >= 0 {
		peer = peer[:idx]
	}
	if !strings.Contains(peer, ":") {
		peer = peer + ":9000"
	}
	return peer
}

func getOrCreateTrust(peer string) *peerTrust {
	peer = normalizePeerAddr(peer)
	trustMu.Lock()
	defer trustMu.Unlock()
	if t, ok := trustByPeer[peer]; ok {
		return t
	}
	// seed trust for configured peers a bit higher
	score := 10.0
	for _, p := range snapshotMeshPeers() {
		if normalizePeerAddr(p) == peer {
			score = 35.0
			break
		}
	}
	t := &peerTrust{Peer: peer, Score: score}
	trustByPeer[peer] = t
	persistPeerTrust(t)
	return t
}

func trustLevel(t *peerTrust) int {
	if isAuthoritativePeer(t.Peer) {
		return trustLevel3
	}
	s := t.Score
	switch {
	case s >= 50:
		return trustLevel2
	case s >= 25:
		return trustLevel1
	default:
		return trustLevel0
	}
}

func trustLevelName(level int) string {
	switch level {
	case trustLevel3:
		return "AUTHORITATIVE"
	case trustLevel2:
		return "TRUSTED"
	case trustLevel1:
		return "FEDERATED"
	default:
		return "UNTRUSTED"
	}
}

func applyDecay(t *peerTrust, now time.Time) {
	if t.LastReport.IsZero() {
		return
	}
	days := now.Sub(t.LastReport).Hours() / 24.0
	if days <= 0 {
		return
	}
	decay := math.Exp(-trustDecayK * days)
	t.Score = t.Score * decay
}

func accuracyRatio(t *peerTrust) float64 {
	if t.Total <= 0 {
		return 0.5
	}
	return float64(t.Valid) / float64(t.Total)
}

func updateTrustOnReport(peer string, latencyScore float64) {
	now := time.Now()
	t := getOrCreateTrust(peer)
	trustMu.Lock()
	applyDecay(t, now)
	t.Total++
	base := 100.0 * accuracyRatio(t)
	t.Score = (t.Score * 0.8) + (base * 0.2)
	t.Score = t.Score * latencyScore
	if t.Score < 0 {
		t.Score = 0
	}
	if t.Score > 100 {
		t.Score = 100
	}
	t.LastReport = now
	persistPeerTrust(t)
	trustMu.Unlock()
}

func updateTrustOnValidity(peers []string, valid bool) {
	if len(peers) == 0 {
		return
	}
	now := time.Now()
	for _, p := range peers {
		t := getOrCreateTrust(p)
		trustMu.Lock()
		applyDecay(t, now)
		if valid {
			t.Valid++
		} else {
			t.Invalid++
		}
		base := 100.0 * accuracyRatio(t)
		t.Score = (t.Score * 0.8) + (base * 0.2)
		if t.Score < 0 {
			t.Score = 0
		}
		if t.Score > 100 {
			t.Score = 100
		}
		t.LastReport = now
		persistPeerTrust(t)
		trustMu.Unlock()
	}
}

func latencyScore(observed time.Time) float64 {
	if observed.IsZero() {
		return 1.0
	}
	d := time.Since(observed)
	switch {
	case d <= 100*time.Millisecond:
		return 1.1
	case d <= time.Second:
		return 1.0
	default:
		return 0.9
	}
}

func handleRemoteReport(peer string, signal mesh.BanSignal, observed time.Time) {
	initTrustStore()
	peer = normalizePeerAddr(peer)
	ip := normalizeIPKey(signal.IP)
	if ip == "" {
		return
	}
	reason := signal.Reason
	ja4 := signal.JA4
	ja3 := signal.JA3
	meshThreats.Add(1)
	updateTrustOnReport(peer, latencyScore(observed))
	t := getOrCreateTrust(peer)
	lvl := trustLevel(t)
	if lvl == trustLevel3 {
		peers := mergePeers([]string{peer}, pendingPeers(ip))
		applyRemoteBan(ip, reason, peers, ja4, ja3)
		removePending(ip)
		return
	}
	if lvl == trustLevel2 {
		peers := mergePeers([]string{peer}, pendingPeers(ip))
		applyRemoteBan(ip, reason, peers, ja4, ja3)
		removePending(ip)
		return
	}
	if lvl == trustLevel1 {
		pendingMu.Lock()
		p := pendingByIP[ip]
		if p == nil {
			p = &pendingBan{IP: ip, Reason: reason, JA4: ja4, JA3: ja3, FirstSeen: time.Now(), Sources: make(map[string]time.Time)}
			pendingByIP[ip] = p
		}
		if p.JA4 == "" {
			p.JA4 = ja4
		}
		if p.JA3 == "" {
			p.JA3 = ja3
		}
		p.Sources[peer] = time.Now()
		pendingMu.Unlock()
		if corroborated(ip) {
			pendingMu.Lock()
			p = pendingByIP[ip]
			pendingMu.Unlock()
			peers := pendingPeers(ip)
			if p != nil {
				applyRemoteBan(ip, reason, peers, p.JA4, p.JA3)
			} else {
				applyRemoteBan(ip, reason, peers, ja4, ja3)
			}
			removePending(ip)
		}
		return
	}
	// Level 0: observation only
	log.Printf("[MESH][BTL] L0 observe only peer=%s ip=%s", peer, ip)
}

func handleRemoteAllowReport(peer, ip, reason string, observed time.Time, ttl time.Duration) {
	initTrustStore()
	peer = normalizePeerAddr(peer)
	ip = normalizeIPKey(ip)
	if ip == "" {
		return
	}
	updateTrustOnReport(peer, latencyScore(observed))
	t := getOrCreateTrust(peer)
	if trustLevel(t) != trustLevel3 {
		log.Printf("[MESH][BTL] ignore allow from non-authoritative peer=%s ip=%s", peer, ip)
		return
	}
	allowIP(ip, reason, ttl, false)
	updateTrustOnValidity([]string{peer}, true)
}

func corroborated(ip string) bool {
	pendingMu.Lock()
	p := pendingByIP[ip]
	pendingMu.Unlock()
	if p == nil {
		return false
	}
	count := 0
	for peer := range p.Sources {
		t := getOrCreateTrust(peer)
		if trustLevel(t) >= trustLevel1 {
			count++
		}
	}
	return count >= 2
}

func pendingPeers(ip string) []string {
	pendingMu.Lock()
	p := pendingByIP[ip]
	pendingMu.Unlock()
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.Sources))
	for peer := range p.Sources {
		out = append(out, peer)
	}
	return out
}

func mergePeers(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	set := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, p := range a {
		if _, ok := set[p]; ok {
			continue
		}
		set[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range b {
		if _, ok := set[p]; ok {
			continue
		}
		set[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func removePending(ip string) {
	pendingMu.Lock()
	delete(pendingByIP, ip)
	pendingMu.Unlock()
}

func applyRemoteBan(ip, reason string, peers []string, ja4 string, ja3 string) {
	applyRemoteBanWithTTL(ip, reason, peers, ja4, ja3, getBanDuration(), "REMOTE_MESH")
}

func applyRemoteBanWithTTL(ip, reason string, peers []string, ja4 string, ja3 string, ttl time.Duration, category string) {
	applyRemoteBanWithIdentity(ip, reason, peers, ja4, ja3, ttl, category, "")
}

func applyRemoteBanWithIdentity(ip, reason string, peers []string, ja4 string, ja3 string, ttl time.Duration, category, originID string) {
	ip = normalizeIPKey(ip)
	if ip == "" {
		return
	}
	if ttl <= 0 {
		ttl = getBanDuration()
	}
	banMutex.Lock()
	if Mode() == ModeTest {
		banMutex.Unlock()
		updateTrustOnValidity(peers, true)
		log.Printf("[MESH][BTL] remote ban observed in TEST ip=%s", ip)
		return
	}
	exp := time.Now().Add(ttl)
	effectiveExp := exp
	if liveUEE != nil {
		decision, err := ueeRemoteGrant(ip, category, originID, reason, peers, exp)
		if err != nil {
			banMutex.Unlock()
			log.Printf("[UEE] remote grant rejected ip=%s: %v", ip, err)
			return
		}
		effectiveExp = decision.ExpiresAt
	}
	remoteBanMu.Lock()
	remoteBanCache[ip] = exp
	if remoteBanSources == nil {
		remoteBanSources = make(map[string]map[string]struct{})
	}
	if len(peers) > 0 {
		set := make(map[string]struct{}, len(peers))
		for _, p := range peers {
			p = normalizePeerAddr(p)
			if p == "" {
				continue
			}
			set[p] = struct{}{}
		}
		if len(set) > 0 {
			remoteBanSources[ip] = set
		}
	}
	remoteBanMu.Unlock()
	if liveExchangeRules != nil && liveUEE == nil {
		if err := liveExchangeRules.clearIP(ip); err != nil {
			log.Printf("[EXCHANGE] clear ownership on mesh ban: %v", err)
		}
	}
	banExpirations[ip] = effectiveExp
	banMetaMu.Lock()
	banMeta[ip] = BanMeta{
		JA4:      normalizeJA4(ja4),
		JA3:      normalizeJA3Key(ja3),
		Reason:   reason,
		Category: category,
	}
	banMetaMu.Unlock()
	if liveUEE == nil {
		applyRemoteBanKernelOnly(ip)
	}
	banMutex.Unlock()
	if ja4 != "" {
		addJA4Blacklist(ja4, ttl)
	}
	if ja3 != "" {
		addJA3Blacklist(ja3, ttl)
	}

	broadcastBans()
	updateTrustOnValidity(peers, true)
	log.Printf("[MESH][BTL] remote ban applied ip=%s reason=%s", ip, reason)
}

func allowIP(ip, reason string, ttl time.Duration, broadcast bool) error {
	ip = normalizeIPKey(ip)
	if strings.TrimSpace(ip) == "" {
		log.Printf("[MESH][BTL] allow override ignored (empty ip)")
		return errors.New("empty source IP")
	}
	if ttl <= 0 {
		ttl = defaultAllowTTL
	}
	if liveUEE != nil {
		if strings.TrimSpace(reason) == "" {
			reason = "operator allow"
		}
		actor := "trusted-mesh"
		if broadcast {
			actor = "local-admin"
		}
		if _, err := liveUEE.SetOverride(ip, actor, reason, ttl, time.Now()); err != nil {
			return err
		}
		banMutex.Lock()
		err := refreshLegacyBanView(time.Now())
		banMutex.Unlock()
		if err != nil {
			return err
		}
		remoteAllowMu.Lock()
		remoteAllowCache[ip] = time.Now().Add(ttl)
		remoteAllowMu.Unlock()
		if broadcast && scp != nil {
			scp.BroadcastAllow(ip, reason, ttl)
		}
		broadcastBans()
		return nil
	}
	exp := time.Now().Add(ttl)
	remoteAllowMu.Lock()
	remoteAllowCache[ip] = exp
	remoteAllowMu.Unlock()

	removed := false
	banMutex.Lock()
	if liveExchangeRules != nil {
		if err := liveExchangeRules.clearIP(ip); err != nil {
			log.Printf("[EXCHANGE] allow override ownership clear failed ip=%s: %v", ip, err)
		}
	}
	for k := range banExpirations {
		if normalizeIPKey(k) == ip {
			delete(banExpirations, k)
			removed = true
		}
	}
	banMutex.Unlock()

	remoteBanMu.Lock()
	for k := range remoteBanCache {
		if normalizeIPKey(k) == ip {
			delete(remoteBanCache, k)
			if remoteBanSources != nil {
				delete(remoteBanSources, k)
			}
		}
	}
	if remoteBanSources != nil {
		for k := range remoteBanSources {
			if normalizeIPKey(k) == ip {
				delete(remoteBanSources, k)
			}
		}
	}
	remoteBanMu.Unlock()

	unbanIP(ip)
	markNodeEdgeReleased(ip, "operator_allow")
	removeBan(ip)
	broadcastBans()

	if broadcast && scp != nil {
		scp.BroadcastAllow(ip, reason, ttl)
	}

	log.Printf("[MESH][BTL] allow override applied ip=%s reason=%s removed_from_memory=%v", ip, reason, removed)
	return nil
}

func isLocalAuthoritative() bool {
	self := normalizePeerAddr(config.BindIP + ":" + config.MeshPort)
	return isAuthoritativePeer(self)
}

func startTrustCleanup(shutdown chan struct{}) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			expirePending()
		case <-shutdown:
			return
		}
	}
}

func expirePending() {
	now := time.Now()
	var expiredPeers []string
	pendingMu.Lock()
	for ip, p := range pendingByIP {
		if now.Sub(p.FirstSeen) > trustSecondOpinionTTL {
			for peer := range p.Sources {
				expiredPeers = append(expiredPeers, peer)
			}
			delete(pendingByIP, ip)
		}
	}
	pendingMu.Unlock()
	if len(expiredPeers) > 0 {
		updateTrustOnValidity(expiredPeers, false)
	}
}

type trustView struct {
	Peer       string  `json:"peer"`
	Score      float64 `json:"score"`
	Level      string  `json:"level"`
	Total      int     `json:"total"`
	Valid      int     `json:"valid"`
	Invalid    int     `json:"invalid"`
	LastReport string  `json:"last_report"`
}

func trustSnapshot() []trustView {
	initTrustStore()
	seedTrustPeers()
	trustMu.Lock()
	defer trustMu.Unlock()
	out := make([]trustView, 0, len(trustByPeer))
	for _, t := range trustByPeer {
		last := ""
		if !t.LastReport.IsZero() {
			last = t.LastReport.Format(time.RFC3339)
		}
		out = append(out, trustView{
			Peer:       t.Peer,
			Score:      t.Score,
			Level:      trustLevelName(trustLevel(t)),
			Total:      t.Total,
			Valid:      t.Valid,
			Invalid:    t.Invalid,
			LastReport: last,
		})
	}
	return out
}

func seedTrustPeers() {
	peers := snapshotMeshPeers()
	if scp != nil {
		for p := range scp.PeerStats() {
			peers = append(peers, p)
		}
	}
	for _, p := range peers {
		if p == "" {
			continue
		}
		_ = getOrCreateTrust(p)
	}
}

func penalizePeer(peer string) {
	updateTrustOnValidity([]string{peer}, false)
}

func setTrustLevel(peer string, level int) {
	peer = normalizePeerAddr(peer)
	if peer == "" {
		return
	}
	t := getOrCreateTrust(peer)
	switch level {
	case trustLevel0:
		t.Score = 0
	case trustLevel1:
		t.Score = 30
	case trustLevel2:
		t.Score = 60
	case trustLevel3:
		t.Score = 100
	}
	t.LastReport = time.Now()
	persistPeerTrust(t)
}

func addAuthoritativePeer(peer string) {
	peer = normalizePeerAddr(peer)
	if peer == "" {
		return
	}
	for _, p := range config.Mesh.AuthoritativePeers {
		if normalizePeerAddr(p) == peer {
			return
		}
	}
	config.Mesh.AuthoritativePeers = append(config.Mesh.AuthoritativePeers, peer)
	saveConfig()
}

func removeAuthoritativePeer(peer string) {
	peer = normalizePeerAddr(peer)
	if peer == "" {
		return
	}
	if len(config.Mesh.AuthoritativePeers) == 0 {
		return
	}
	out := make([]string, 0, len(config.Mesh.AuthoritativePeers))
	for _, p := range config.Mesh.AuthoritativePeers {
		if normalizePeerAddr(p) == peer {
			continue
		}
		out = append(out, p)
	}
	config.Mesh.AuthoritativePeers = out
	saveConfig()
}
