package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"honeymesh/internal/mesh"
)

const (
	defaultScanWindowS = 60
	defaultScanPorts   = 10
	defaultTrapWindowS = 60
	defaultTrapHits    = 1
	trapConnTimeout    = 15 * time.Second
)

// ─────────────────────────────────────────────
// EVENT INGESTION
// ─────────────────────────────────────────────

func emitEvent(e Event) {
	select {
	case logChan <- e:
	default:
		droppedTelemetry.Add(1)
	}
}

// ─────────────────────────────────────────────
// LOG WORKER
// ─────────────────────────────────────────────

func startLogWorker(shutdown chan struct{}) {
	log.Println("[RUNTIME] Log worker started")

	for {
		select {
		case e := <-logChan:
			processEvent(e)
		case <-shutdown:
			log.Println("[RUNTIME] Log worker stopping")
			return
		}
	}
}

func addEvent(e Event) {
	logMutex.Lock()
	defer logMutex.Unlock()
	if eventLog == nil {
		eventLog = make([]Event, 10000)
	}
	eventLog[eventIdx] = e
	eventIdx = (eventIdx + 1) % len(eventLog)
	if eventCnt < len(eventLog) {
		eventCnt++
	}
}

func snapshotEvents(limit int) []Event {
	logMutex.Lock()
	defer logMutex.Unlock()
	if eventCnt == 0 {
		return nil
	}
	n := eventCnt
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]Event, 0, n)
	start := eventIdx - n
	if start < 0 {
		start += len(eventLog)
	}
	for i := 0; i < n; i++ {
		idx := (start + i) % len(eventLog)
		out = append(out, eventLog[idx])
	}
	return out
}

func eventCount() int {
	logMutex.Lock()
	defer logMutex.Unlock()
	return eventCnt
}

func queueEventForStore(e Event) {
	select {
	case storeChan <- e:
	default:
		droppedDB.Add(1)
	}
}

// ─────────────────────────────────────────────
// EVENT PROCESSING PIPELINE
// ─────────────────────────────────────────────

func processEvent(e Event) {
	// Suppress local/whitelisted telemetry noise (e.g., 127.0.0.1).
	if isWhitelisted(e.Attacker) {
		return
	}

	if e.JA3 != "" {
		ja3 := normalizeJA3Key(e.JA3)
		if ja3 != "" {
			ip := normalizeIPKey(e.Attacker)
			if ip != "" {
				ja3IPMu.Lock()
				lastJA3ByIP[ip] = ja3
				ja3IPMu.Unlock()
			}
		}
	}
	if e.JA4 != "" {
		ja4 := normalizeJA4(e.JA4)
		if ja4 != "" {
			ip := normalizeIPKey(e.Attacker)
			if ip != "" {
				ja4IPMu.Lock()
				lastJA4ByIP[ip] = ja4
				ja4IPMu.Unlock()
			}
		}
	}

	addEvent(e)
	broadcastEvent(e)
	queueEventForStore(e)
	analyzeEvent(e)
}

// ─────────────────────────────────────────────
// DETECTION ENGINE
// ─────────────────────────────────────────────

func analyzeEvent(e Event) {
	if isWhitelisted(e.Attacker) {
		return
	}

	// Watchdog traps: immediate ban when traffic hits the port (even if trap listener is off).
	if t, ok := config.Traps[e.Target]; ok && t.Watchdog {
		policyBan(e.Attacker, e.TargetIP, e.Target, e.Service, "WATCHDOG", "watchdog trap hit", e.Entropy, 3, e.Interface, getAutomaticBanDuration())
		return
	}

	if e.Type == "TRAP" {
		if recordTrapHit(e.Attacker) {
			policyBan(e.Attacker, e.TargetIP, e.Target, e.Service, "TRAP_HIT", "honeypot trigger", e.Entropy, 2, e.Interface, getAutomaticBanDuration())
		}
		return
	}

	recordScan(e.Attacker, e.Target)

	if e.Entropy > 4.5 {
		policyBan(e.Attacker, e.TargetIP, e.Target, e.Service, "HIGH_ENTROPY", "payload anomaly", e.Entropy, 1, e.Interface, getAutomaticBanDuration())
		return
	}

	if e.JA4 != "" && isJA4Blacklisted(e.JA4) {
		log.Printf("[JA4] matched ip=%s ja4=%s", e.Attacker, e.JA4)
		policyBan(e.Attacker, e.TargetIP, e.Target, e.Service, "JA4_MATCH", "blacklisted tls fingerprint", e.Entropy, 2, e.Interface, getAutomaticBanDuration())
		return
	}

	if e.JA3 != "" && isJA3Blacklisted(e.JA3) {
		log.Printf("[JA3] matched ip=%s ja3=%s", e.Attacker, e.JA3)
		policyBan(e.Attacker, e.TargetIP, e.Target, e.Service, "JA3_MATCH", "legacy blacklisted tls fingerprint", e.Entropy, 2, e.Interface, getAutomaticBanDuration())
		return
	}
}

// ─────────────────────────────────────────────
// SCAN / TRAP TRACKING
// ─────────────────────────────────────────────

func recordScan(ip string, port string) {
	ip = normalizeIPKey(ip)
	if ip == "" || port == "" {
		return
	}
	if isCurrentlyBanned(ip) {
		return
	}

	now := time.Now()
	window := scanWindowSeconds()
	threshold := scanThreshold()

	scanMu.Lock()
	defer scanMu.Unlock()

	if _, ok := scanCounts[ip]; !ok {
		scanCounts[ip] = make(map[string]time.Time)
	}

	scanCounts[ip][port] = now

	cutoff := now.Add(-time.Duration(window) * time.Second)
	for p, ts := range scanCounts[ip] {
		if ts.Before(cutoff) {
			delete(scanCounts[ip], p)
		}
	}

	if len(scanCounts[ip]) >= threshold {
		policyBan(ip, config.BindIP, "multi-port", "tcp", "PORT_SCAN", "multi-port scan", 0, 2, "kernel", getAutomaticBanDuration())
	}
}

func recordTrapHit(ip string) bool {
	ip = normalizeIPKey(ip)
	if ip == "" {
		return false
	}
	window := trapWindowSeconds()
	threshold := trapThreshold()

	now := time.Now()
	cutoff := now.Add(-time.Duration(window) * time.Second)

	trapMu.Lock()
	defer trapMu.Unlock()

	list := trapHitCounts[ip]
	out := list[:0]
	for _, ts := range list {
		if ts.After(cutoff) {
			out = append(out, ts)
		}
	}
	out = append(out, now)
	trapHitCounts[ip] = out

	return len(out) >= threshold
}

// ─────────────────────────────────────────────
// BAN ORCHESTRATION
// ─────────────────────────────────────────────

func triggerBan(ip, targetIP, target, service, category, reason string, entropy float64, severity int, iface string, duration time.Duration) error {
	ip = normalizeIPKey(ip)
	if ip == "" || isWhitelisted(ip) {
		return nil
	}

	exp := time.Now().Add(duration)

	meta := BanMeta{
		Reason:   reason,
		Category: category,
	}
	ja4 := lastJA4ForIP(ip)
	if ja4 != "" {
		meta.JA4 = ja4
		addJA4Blacklist(ja4, duration)
	}
	ja3 := lastJA3ForIP(ip)
	if ja3 != "" {
		meta.JA3 = ja3
		addJA3Blacklist(ja3, duration)
	}
	banMutex.Lock()
	// A mode transition may have happened after policyBan checked Mode().
	if Mode() == ModeTest {
		banMutex.Unlock()
		return nil
	}
	if liveUEE != nil {
		decision, err := ueeLocalGrant(ip, category, reason, exp)
		if err != nil {
			banMutex.Unlock()
			log.Printf("[UEE] local grant failed ip=%s category=%s: %v", ip, category, err)
			return err
		}
		exp = decision.ExpiresAt
	} else {
		banIP(ip)
	}
	banExpirations[ip] = exp
	banMetaMu.Lock()
	banMeta[ip] = meta
	banMetaMu.Unlock()
	banMutex.Unlock()
	if liveUEE == nil {
		persistBan(ip, exp)
	}

	if meta.JA4 != "" {
		log.Printf("[BAN] %s blocked (%s) reason=%s ja4=%s ja3=%s", ip, category, reason, meta.JA4, meta.JA3)
	} else if meta.JA3 != "" {
		log.Printf("[BAN] %s blocked (%s) reason=%s ja3=%s", ip, category, reason, meta.JA3)
	} else {
		log.Printf("[BAN] %s blocked (%s) reason=%s", ip, category, reason)
	}

	broadcastBans()

	if scp != nil {
		signal, err := prepareTrustedNetworkSignal(mesh.BanSignal{
			IP:        ip,
			Reason:    reason,
			JA4:       meta.JA4,
			JA3:       meta.JA3,
			TargetIP:  targetIP,
			Target:    target,
			Service:   service,
			Category:  category,
			EventType: "MESH_INTEL",
			Interface: iface,
			Payload:   sanitizePayload([]byte(reason), 200),
		})
		if err != nil {
			log.Printf("[MESH] Skipping trusted network publish ip=%s err=%v", ip, err)
			return nil
		}
		go scp.BroadcastBan(signal)
	}
	go publishNetToolsBan(ip, targetIP, target, service, category, reason, meta, duration)
	return nil
}

// ─────────────────────────────────────────────
// TLS FINGERPRINT MANAGEMENT
// ─────────────────────────────────────────────

func isJA4Blacklisted(value string) bool {
	value = normalizeJA4(value)
	if value == "" {
		return false
	}
	ja4Mu.Lock()
	defer ja4Mu.Unlock()

	exp, ok := ja4Blacklist[value]
	if !ok {
		return false
	}
	return time.Now().Before(exp)
}

func addJA4Blacklist(value string, ttl time.Duration) {
	value = normalizeJA4(value)
	if value == "" {
		return
	}
	if ttl <= 0 {
		ttl = getBanDuration()
	}
	ja4Mu.Lock()
	ja4Blacklist[value] = time.Now().Add(ttl)
	ja4Mu.Unlock()
}

func isJA3Blacklisted(hash string) bool {
	if hash == "" {
		return false
	}
	hash = normalizeJA3Key(hash)
	if hash == "" {
		return false
	}
	ja3Mu.Lock()
	defer ja3Mu.Unlock()

	exp, ok := ja3Blacklist[hash]
	if !ok {
		return false
	}
	return time.Now().Before(exp)
}

func addJA3Blacklist(hash string, ttl time.Duration) {
	hash = normalizeJA3Key(hash)
	if hash == "" {
		return
	}
	if ttl <= 0 {
		ttl = getBanDuration()
	}
	ja3Mu.Lock()
	ja3Blacklist[hash] = time.Now().Add(ttl)
	ja3Mu.Unlock()
}

func normalizeJA3Key(hash string) string {
	if hash == "" {
		return ""
	}
	hash = normalizeJA3(hash)
	if hash == "" {
		return ""
	}
	if strings.Contains(hash, ",") || (len(hash) != 32 || !isHex(hash)) {
		hash = ja3HashFromString(hash)
	}
	return strings.ToLower(hash)
}

func lastJA3ForIP(ip string) string {
	ip = normalizeIPKey(ip)
	if ip == "" {
		return ""
	}
	ja3IPMu.Lock()
	defer ja3IPMu.Unlock()
	return lastJA3ByIP[ip]
}

func lastJA4ForIP(ip string) string {
	ip = normalizeIPKey(ip)
	if ip == "" {
		return ""
	}
	ja4IPMu.Lock()
	defer ja4IPMu.Unlock()
	return lastJA4ByIP[ip]
}

// ─────────────────────────────────────────────
// CLEANUP WORKERS
// ─────────────────────────────────────────────

func startBanCleanup(shutdown chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cleanupBans()
		case <-shutdown:
			return
		}
	}
}

func cleanupBans() {
	now := time.Now()
	changed := false

	banMutex.Lock()
	if liveUEE != nil {
		if err := liveUEE.Sweep(now); err != nil {
			log.Printf("[UEE] expiry reconcile failed: %v", err)
		}
		if err := liveUEE.RetryFailed(now); err != nil {
			log.Printf("[UEE] retry reconcile failed: %v", err)
		}
		if err := refreshLegacyBanView(now); err != nil {
			log.Printf("[UEE] compatibility view refresh failed: %v", err)
		} else {
			changed = true
		}
		banMutex.Unlock()
		if changed {
			broadcastBans()
		}
		return
	}
	for ip, exp := range banExpirations {
		if !now.Before(exp) {
			unbanIP(ip)
			removeBan(ip)
			delete(banExpirations, ip)
			changed = true
			banMetaMu.Lock()
			delete(banMeta, ip)
			banMetaMu.Unlock()
		}
	}
	banMutex.Unlock()
	if changed {
		broadcastBans()
	}
}

func startScanCleanup(shutdown chan struct{}) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cleanupScans()
		case <-shutdown:
			return
		}
	}
}

func cleanupScans() {
	window := scanWindowSeconds()
	cutoff := time.Now().Add(-time.Duration(window) * time.Second)

	scanMu.Lock()
	defer scanMu.Unlock()

	for ip, ports := range scanCounts {
		for p, ts := range ports {
			if ts.Before(cutoff) {
				delete(ports, p)
			}
		}
		if len(ports) == 0 {
			delete(scanCounts, ip)
		}
	}
}

func startJA3Cleanup(shutdown chan struct{}) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			ja4Mu.Lock()
			for k, exp := range ja4Blacklist {
				if now.After(exp) {
					delete(ja4Blacklist, k)
				}
			}
			ja4Mu.Unlock()
			ja3Mu.Lock()
			for k, exp := range ja3Blacklist {
				if now.After(exp) {
					delete(ja3Blacklist, k)
				}
			}
			ja3Mu.Unlock()
		case <-shutdown:
			return
		}
	}
}

// ─────────────────────────────────────────────
// TELEMETRY MONITOR
// ─────────────────────────────────────────────

func startTelemetryMonitor(shutdown chan struct{}) {
	log.Println("[RUNTIME] Telemetry monitor started")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// future: metrics export
		case <-shutdown:
			return
		}
	}
}

// ─────────────────────────────────────────────
// REMOTE BAN CACHE CLEANUP
// ─────────────────────────────────────────────

func startRemoteBanCleanup(shutdown chan struct{}) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			remoteBanMu.Lock()
			for ip, exp := range remoteBanCache {
				if now.After(exp) {
					delete(remoteBanCache, ip)
					if remoteBanSources != nil {
						delete(remoteBanSources, ip)
					}
					banMetaMu.Lock()
					if meta, ok := banMeta[ip]; ok && meta.Category == "REMOTE_MESH" {
						delete(banMeta, ip)
					}
					banMetaMu.Unlock()
				}
			}
			remoteBanMu.Unlock()
			remoteAllowMu.Lock()
			for ip, exp := range remoteAllowCache {
				if now.After(exp) {
					delete(remoteAllowCache, ip)
				}
			}
			remoteAllowMu.Unlock()
		case <-shutdown:
			return
		}
	}
}

// ─────────────────────────────────────────────
// WATCHDOG LOOP
// ─────────────────────────────────────────────

func startWatchdogLoop(shutdown chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// future: self-healing / trap health checks
		case <-shutdown:
			return
		}
	}
}

// ─────────────────────────────────────────────
// TRAP SYSTEM
// ─────────────────────────────────────────────

func startTraps() {
	log.Println("[TRAPS] Starting configured traps...")

	enabled := 0
	for _, trap := range config.Traps {
		if trap.Enabled {
			enabled++
		}
	}
	atomic.StoreInt32(&trapStartupExpected, int32(enabled))
	atomic.StoreInt32(&trapStartupCount, 0)
	if enabled == 0 {
		trapStartupOnce.Do(func() {
			close(trapStartupDone)
		})
	}

	for port, trap := range config.Traps {
		if !trap.Enabled {
			continue
		}
		switch strings.ToLower(trap.Proto) {
		case "udp":
			go startUDPTrap(port, trap)
		default:
			go startSingleTrap(port, trap)
		}
	}
}

func markTrapStartup() {
	expected := atomic.LoadInt32(&trapStartupExpected)
	if expected <= 0 {
		return
	}
	count := atomic.AddInt32(&trapStartupCount, 1)
	if count >= expected {
		trapStartupOnce.Do(func() {
			close(trapStartupDone)
		})
	}
}

func waitForTrapStartup(timeout time.Duration) {
	if atomic.LoadInt32(&trapStartupExpected) <= 0 {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-trapStartupDone:
	case <-timer.C:
	}
}

func startSingleTrap(port string, t *TrapState) {
	t.mu.Lock()
	if t.IsRunning {
		t.mu.Unlock()
		return
	}
	t.stopChan = make(chan struct{})
	t.IsRunning = true
	if t.MaxConns <= 0 {
		t.MaxConns = 64
	}
	if t.connSem == nil {
		t.connSem = make(chan struct{}, t.MaxConns)
	}
	t.mu.Unlock()

	addr := ":" + port

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[TRAP] Failed to bind %s: %v", addr, err)
		setTrapStatus(port, false, err.Error(), t.Watchdog)
		t.mu.Lock()
		t.IsRunning = false
		close(t.stopChan)
		t.stopChan = nil
		t.mu.Unlock()
		markTrapStartup()
		return
	}
	setTrapStatus(port, true, "", t.Watchdog)

	t.mu.Lock()
	t.listeners = append(t.listeners, ln)
	t.mu.Unlock()

	log.Printf("[TRAP] Listening on %s (%s)", addr, t.Proto)
	markTrapStartup()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-t.stopChan:
				return
			default:
				continue
			}
		}

		go handleTrapConnection(conn, port, t)
	}
}

func handleTrapConnection(conn net.Conn, port string, t *TrapState) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(trapConnTimeout))

	var fingerprints tlsFingerprints
	var payloadSample string
	connToUse := net.Conn(conn)
	prefix, fingerprints, payloadSample := readTrapPreamble(conn, port)
	if len(prefix) > 0 {
		mr := io.MultiReader(bytes.NewReader(prefix), conn)
		connToUse = &prefixedConn{Conn: conn, r: mr}
	}

	if t.connSem != nil {
		select {
		case t.connSem <- struct{}{}:
			defer func() { <-t.connSem }()
		default:
			return
		}
	}
	if trapSem != nil {
		trapSem <- struct{}{}
		defer func() { <-trapSem }()
	}

	remote := remoteIP(conn.RemoteAddr().String())

	payload := payloadSample
	if payload == "" {
		payload = trapPayload(t, port)
	}
	emitEvent(Event{
		Timestamp:                time.Now().Format(time.RFC3339),
		Attacker:                 remote,
		TargetIP:                 config.BindIP,
		Target:                   port,
		Service:                  t.Proto,
		Type:                     "TRAP",
		Payload:                  payload,
		Entropy:                  calculateEntropy(payload),
		Interface:                "trap",
		JA4:                      fingerprints.JA4,
		JA3:                      fingerprints.JA3,
		TLSFingerprintFamily:     fingerprints.Family,
		TLSFingerprintVersion:    fingerprints.Version,
		TLSFingerprintConfidence: fingerprints.Confidence,
	})

	handleTCPTrap(port, t, connToUse)
}

func readTrapPreamble(conn net.Conn, port string) ([]byte, tlsFingerprints, string) {
	maxBytes := getJA3ReadMaxBytes()
	timeout := getJA3ReadTimeout()
	if maxBytes <= 0 {
		return nil, tlsFingerprints{}, ""
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	wantJA3 := shouldPeekClientHello(port)
	buf := make([]byte, 0, maxBytes)
	tmp := make([]byte, 4096)
	var fingerprints tlsFingerprints
	var sample string

	for len(buf) < maxBytes {
		n, err := conn.Read(tmp)
		if n > 0 {
			if len(buf)+n > maxBytes {
				n = maxBytes - len(buf)
			}
			buf = append(buf, tmp[:n]...)
			if sample == "" {
				sample = sanitizePayload(buf, 200)
			}
			if wantJA3 {
				if len(buf) >= 5 {
					if buf[0] != 0x16 {
						break
					}
					recLen := int(binary.BigEndian.Uint16(buf[3:5]))
					total := 5 + recLen
					if total > maxBytes {
						break
					}
					if len(buf) >= total {
						fingerprints = computeTLSFingerprintsFromClientHello(buf[:total])
						break
					}
				}
			} else {
				break
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			break
		}
	}

	return buf, fingerprints, sample
}

type prefixedConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixedConn) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

func shouldPeekClientHello(port string) bool {
	_, ok := getJA3PortSet()[port]
	return ok
}

func stopTrap(t *TrapState) {
	t.mu.Lock()
	if !t.IsRunning {
		t.mu.Unlock()
		return
	}
	if t.stopChan != nil {
		close(t.stopChan)
		t.stopChan = nil
	}
	for _, ln := range t.listeners {
		_ = ln.Close()
	}
	t.listeners = nil
	t.IsRunning = false
	t.mu.Unlock()
	setTrapStatusForTrap(t, false, "", t.Watchdog)
}

func armWatchdog(port string, enabled bool) {
	if !enabled {
		return
	}
	log.Printf("[TRAP] Watchdog armed for :%s (no listener)", port)
	setTrapStatus(port, false, "", true)
}

func setTrapStatusForTrap(t *TrapState, running bool, lastErr string, watchdog bool) {
	trapStatusMu.Lock()
	for port, ref := range config.Traps {
		if ref == t {
			trapStatus[port] = trapRuntime{
				Running:        running,
				LastError:      lastErr,
				WatchdogActive: watchdog,
			}
			break
		}
	}
	trapStatusMu.Unlock()
}

func startUDPTrap(port string, t *TrapState) {
	t.mu.Lock()
	if t.IsRunning {
		t.mu.Unlock()
		return
	}
	t.stopChan = make(chan struct{})
	t.IsRunning = true
	t.mu.Unlock()

	addr := ":" + port
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("[TRAP] Failed to bind UDP %s: %v", addr, err)
		setTrapStatus(port, false, err.Error(), t.Watchdog)
		if t.Watchdog {
			log.Printf("[TRAP] Watchdog active for UDP %s via XDP (no socket bind)", addr)
		}
		t.mu.Lock()
		t.IsRunning = false
		close(t.stopChan)
		t.stopChan = nil
		t.mu.Unlock()
		markTrapStartup()
		return
	}
	setTrapStatus(port, true, "", t.Watchdog)

	t.mu.Lock()
	t.listeners = append(t.listeners, pc)
	t.mu.Unlock()

	log.Printf("[TRAP] Listening on %s (%s)", addr, t.Proto)
	markTrapStartup()

	buf := make([]byte, 2048)
	for {
		n, remoteAddr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-t.stopChan:
				return
			default:
				continue
			}
		}
		ra, _ := remoteAddr.(*net.UDPAddr)
		attacker := remoteAddr.String()
		if ra != nil {
			attacker = ra.IP.String()
		}

		payload := sanitizePayload(buf[:n], 200)
		emitEvent(Event{
			Timestamp: time.Now().Format(time.RFC3339),
			Attacker:  attacker,
			TargetIP:  config.BindIP,
			Target:    port,
			Service:   "udp",
			Type:      "TRAP",
			Payload:   payload,
			Entropy:   calculateEntropy(payload),
			Interface: "trap",
		})

		handleUDPTrap(port, t, pc, remoteAddr, buf[:n])
	}
}

func trapPayload(t *TrapState, port string) string {
	if t == nil {
		return "trap hit"
	}
	if t.Banner != "" {
		return t.Banner
	}
	switch port {
	case "21":
		return "ftp connect"
	case "22":
		return "ssh connect"
	case "23":
		return "telnet connect"
	case "25":
		return "smtp connect"
	case "53":
		return "dns query"
	case "80", "8080":
		return "http request"
	case "443":
		return "https request"
	case "445":
		return "smb connect"
	case "3306":
		return "mysql connect"
	case "3389":
		return "rdp connect"
	case "5432":
		return "postgres connect"
	case "6379":
		return "redis connect"
	case "9200":
		return "elastic connect"
	default:
		return "trap hit"
	}
}

func setTrapStatus(port string, running bool, lastErr string, watchdog bool) {
	trapStatusMu.Lock()
	trapStatus[port] = trapRuntime{
		Running:        running,
		LastError:      lastErr,
		WatchdogActive: watchdog,
	}
	trapStatusMu.Unlock()
}

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

func isCurrentlyBanned(ip string) bool {
	ip = normalizeIPKey(ip)
	if ip == "" {
		return false
	}
	banMutex.Lock()
	defer banMutex.Unlock()
	exp, ok := banExpirations[ip]
	return ok && time.Now().Before(exp)
}

func scanWindowSeconds() int {
	if config.Security.ScanWindowS > 0 {
		return config.Security.ScanWindowS
	}
	return defaultScanWindowS
}

func scanThreshold() int {
	if config.Security.ScanPorts > 0 {
		return config.Security.ScanPorts
	}
	return defaultScanPorts
}

func trapWindowSeconds() int {
	if config.Security.TrapBanWindowS > 0 {
		return config.Security.TrapBanWindowS
	}
	return defaultTrapWindowS
}

func trapThreshold() int {
	if config.Security.TrapBanHits > 0 {
		return config.Security.TrapBanHits
	}
	return defaultTrapHits
}
