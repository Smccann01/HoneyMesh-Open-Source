package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"honeymesh/internal/license"
)

// ─────────────────────────────────────────────
// WEBSOCKET GLOBALS
// ─────────────────────────────────────────────

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return isOriginAllowed(r)
	},
}

var (
	clients   = make(map[*websocket.Conn]*sync.Mutex)
	clientsMu sync.Mutex
)

var permanentBanExpiry = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// ─────────────────────────────────────────────
// SERVER START
// ─────────────────────────────────────────────

func startSecureDashboard(port string) (*http.Server, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", serveDashboard)
	staticDir := "web"
	if _, err := os.Stat("/usr/share/honeymesh/web"); err == nil {
		staticDir = "/usr/share/honeymesh/web"
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
	mux.HandleFunc("/api/events", apiEvents)
	mux.HandleFunc("/api/bans", apiBans)
	mux.HandleFunc("/api/bans/meta", apiBansMeta)
	mux.HandleFunc("/api/enforcement/grants", apiEnforcementGrants)
	mux.HandleFunc("/api/enforcement/decision", apiEnforcementDecision)
	mux.HandleFunc("/api/enforcement/history", apiEnforcementHistory)
	mux.HandleFunc("/api/enforcement/preview", apiEnforcementPreview)
	mux.HandleFunc("/api/enforcement/contract", apiEnforcementContract)
	mux.HandleFunc("/api/enforcement/operator-grants", apiOperatorGrants)
	mux.HandleFunc("/api/enforcement/operator-grants/release", apiOperatorGrantRelease)
	mux.HandleFunc("/api/mode", apiMode)
	mux.HandleFunc("/api/health", apiHealth)
	mux.HandleFunc("/api/traps", apiTraps)
	mux.HandleFunc("/api/trap", apiTrapToggle)
	mux.HandleFunc("/api/ifaces", apiIfaces)
	mux.HandleFunc("/api/iface", apiIfaceToggle)
	mux.HandleFunc("/api/peers", apiPeers)
	mux.HandleFunc("/api/trust", apiTrust)
	mux.HandleFunc("/api/trust/penalize", apiTrustPenalize)
	mux.HandleFunc("/api/trust/set", apiTrustSet)
	mux.HandleFunc("/api/allow", apiAllow)
	mux.HandleFunc("/api/ban", apiBan)
	mux.HandleFunc("/api/xdp/drop-totals", apiBanDropTotals)
	mux.HandleFunc("/api/ban/extend", apiBanExtend)
	mux.HandleFunc("/api/ban/release", apiBanRelease)
	mux.HandleFunc("/api/trusted", apiTrusted)
	mux.HandleFunc("/api/mesh/join", apiMeshJoin)
	mux.HandleFunc("/api/mesh/invite", apiMeshInvite)
	mux.HandleFunc("/api/mesh/revoke", apiMeshRevoke)
	mux.HandleFunc("/api/license", apiLicense)
	mux.HandleFunc("/api/license-info", apiLicenseInfo)
	mux.HandleFunc("/api/security", apiSecurity)
	mux.HandleFunc("/api/events.csv", apiEventsCSV)
	mux.HandleFunc("/api/session", apiSession)
	mux.HandleFunc("/ws", wsHandler)

	bindIP := config.BindIP
	if bindIP == "" {
		bindIP = "0.0.0.0"
	}
	addr := net.JoinHostPort(bindIP, port)

	cert, err := tls.LoadX509KeyPair(config.Security.CertFile, config.Security.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load dashboard TLS certificate: %w", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("listen on dashboard address %s: %w", addr, err)
	}
	srv := &http.Server{Addr: addr, Handler: mux, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[DASHBOARD] Failed: %v", err)
		}
	}()
	return srv, nil
}

// ─────────────────────────────────────────────
// UI PAGE
// ─────────────────────────────────────────────

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, dashboardHTML)
}

// ─────────────────────────────────────────────
// WEBSOCKET LIVE STREAM
// ─────────────────────────────────────────────

func wsHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("hm_ws_session")
	if err != nil || !validWSSession(cookie.Value) || !sameOriginHTTPS(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Time{})

	clientsMu.Lock()
	clients[conn] = &sync.Mutex{}
	clientsMu.Unlock()

	sendSnapshot(conn)

	go func() {
		defer func() {
			clientsMu.Lock()
			delete(clients, conn)
			clientsMu.Unlock()
			conn.Close()
		}()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}()
}

func apiSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOriginHTTPS(r) || config.AdminToken == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Honey-Token")), []byte(config.AdminToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	expires := time.Now().Add(15 * time.Minute).Unix()
	payload := fmt.Sprintf("%d.%s", expires, hex.EncodeToString(nonce))
	mac := hmac.New(sha256.New, []byte(config.AdminToken))
	_, _ = mac.Write([]byte(payload))
	value := payload + "." + hex.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{Name: "hm_ws_session", Value: value, Path: "/ws", MaxAge: 900, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func validWSSession(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || config.AdminToken == "" {
		return false
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expires <= time.Now().Unix() || expires > time.Now().Add(15*time.Minute).Unix() {
		return false
	}
	if nonce, err := hex.DecodeString(parts[1]); err != nil || len(nonce) != 16 {
		return false
	}
	got, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(config.AdminToken))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	return hmac.Equal(got, mac.Sum(nil))
}

func sameOriginHTTPS(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	return err == nil && u.Scheme == "https" && u.Host == r.Host && u.User == nil
}

// ─────────────────────────────────────────────
// API HANDLERS
// ─────────────────────────────────────────────

func apiEvents(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, decorateEvents(snapshotEvents(500)))
}

func apiEventsCSV(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	limit := 5000
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		} else {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
	}
	var since time.Time
	var until time.Time
	hasSince := false
	hasUntil := false
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "invalid since", http.StatusBadRequest)
			return
		}
		since = t
		hasSince = true
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "invalid until", http.StatusBadRequest)
			return
		}
		until = t
		hasUntil = true
	}

	rows := snapshotEvents(0)

	filtered := make([]Event, 0, len(rows))
	for _, e := range rows {
		if hasSince || hasUntil {
			ts, err := time.Parse(time.RFC3339, e.Timestamp)
			if err != nil {
				continue
			}
			if hasSince && ts.Before(since) {
				continue
			}
			if hasUntil && ts.After(until) {
				continue
			}
		}
		filtered = append(filtered, e)
	}

	if limit > 0 && len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"honeymesh_events.csv\"")
	csvOut := csv.NewWriter(w)
	_ = csvOut.Write([]string{"DATE", "TIME", "ACTION", "SRC_IP", "DST_IP", "DST_PORT", "SERVICE", "NODE", "INTERFACE", "JA4", "JA3", "BAN_SOURCE", "DETAILS", "PAYLOAD"})
	for _, e := range filtered {
		action := e.Type
		details := ""
		if label := ja4LabelFor(e.JA4); label != "" {
			details = "ja4_label=" + label
		}
		if label := ja3LabelFor(e.JA3); label != "" {
			if details == "" {
				details = "ja3_legacy_label=" + label
			} else {
				details = details + " ja3_legacy_label=" + label
			}
		}
		if e.Interface != "" {
			if details == "" {
				details = "iface=" + e.Interface
			} else {
				details = details + " iface=" + e.Interface
			}
		}
		if e.Entropy > 0 {
			if details == "" {
				details = fmt.Sprintf("entropy=%.2f", e.Entropy)
			} else {
				details = details + fmt.Sprintf(" entropy=%.2f", e.Entropy)
			}
		}
		dateStr := ""
		timeStr := ""
		if ts, err := time.Parse(time.RFC3339, e.Timestamp); err == nil {
			dateStr = ts.Format("2006-01-02")
			timeStr = ts.Format("15:04:05-07:00")
		}
		payloadOut := e.Payload
		if e.Interface == "xdp" && strings.HasPrefix(e.Payload, "action=") {
			if details == "" {
				details = e.Payload
			} else {
				details = details + " " + e.Payload
			}
			payloadOut = ""
		}
		banSource := banSourceForIP(e.Attacker)
		_ = csvOut.Write([]string{csvSafeCell(dateStr), csvSafeCell(timeStr), csvSafeCell(action), csvSafeCell(e.Attacker), csvSafeCell(e.TargetIP), csvSafeCell(e.Target), csvSafeCell(e.Service), csvSafeCell(e.Node), csvSafeCell(e.Interface), csvSafeCell(e.JA4), csvSafeCell(e.JA3), csvSafeCell(banSource), csvSafeCell(details), csvSafeCell(payloadOut)})
	}
	csvOut.Flush()
}

func csvSafeCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "\t" + value
	}
	return value
}

func apiBans(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	banMutex.Lock()
	defer banMutex.Unlock()
	out := make(map[string]time.Time, len(banExpirations))
	remoteAllowMu.Lock()
	for ip, exp := range banExpirations {
		clean := sanitizeIPStr(ip)
		if clean == "" {
			delete(banExpirations, ip)
			continue
		}
		if allowExp, ok := remoteAllowCache[ip]; ok && time.Now().Before(allowExp) {
			continue
		}
		out[clean] = exp
	}
	remoteAllowMu.Unlock()
	writeJSON(w, out)
}

func apiBansMeta(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	banMutex.Lock()
	snapshot := make(map[string]time.Time, len(banExpirations))
	for ip, exp := range banExpirations {
		clean := sanitizeIPStr(ip)
		if clean == "" {
			delete(banExpirations, ip)
			continue
		}
		snapshot[clean] = exp
	}
	banMutex.Unlock()

	remoteAllowMu.Lock()
	for ip, exp := range snapshot {
		if allowExp, ok := remoteAllowCache[ip]; ok && time.Now().Before(allowExp) {
			delete(snapshot, ip)
		}
		if time.Now().After(exp) {
			delete(snapshot, ip)
		}
	}
	remoteAllowMu.Unlock()

	type banMetaPayload struct {
		Expires  time.Time `json:"expires"`
		JA4      string    `json:"ja4"`
		JA4Label string    `json:"ja4_label"`
		JA3      string    `json:"ja3"`
		JA3Label string    `json:"ja3_label"`
		Reason   string    `json:"reason"`
		Category string    `json:"category"`
	}
	out := make(map[string]banMetaPayload, len(snapshot))
	banMetaMu.Lock()
	for ip, exp := range snapshot {
		meta := banMeta[ip]
		out[ip] = banMetaPayload{
			Expires:  exp,
			JA4:      meta.JA4,
			JA4Label: ja4LabelFor(meta.JA4),
			JA3:      meta.JA3,
			JA3Label: ja3LabelFor(meta.JA3),
			Reason:   meta.Reason,
			Category: meta.Category,
		}
	}
	banMetaMu.Unlock()

	writeJSON(w, out)
}

func apiTraps(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, trapSnapshot())
}

func apiTrapToggle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	type req struct {
		Port     string  `json:"port"`
		Enabled  *bool   `json:"enabled,omitempty"`
		Banner   *string `json:"banner,omitempty"`
		Watchdog *bool   `json:"watchdog,omitempty"`
	}
	var m req
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	trap, ok := config.Traps[m.Port]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if m.Banner != nil {
		trap.Banner = *m.Banner
	}
	if m.Watchdog != nil {
		trap.Watchdog = *m.Watchdog
		if trap.Watchdog && !trap.Enabled {
			armWatchdog(m.Port, true)
		}
	}
	if m.Enabled != nil {
		trap.Enabled = *m.Enabled
		if trap.Enabled {
			if strings.ToLower(trap.Proto) == "udp" {
				go startUDPTrap(m.Port, trap)
			} else {
				go startSingleTrap(m.Port, trap)
			}
		} else {
			stopTrap(trap)
		}
	}
	saveConfig()
	broadcastTraps()
	writeJSON(w, map[string]interface{}{"enabled": trap.Enabled, "banner": trap.Banner, "watchdog": trap.Watchdog})
}

type ifaceInfo struct {
	Name  string `json:"name"`
	IPs   string `json:"ips"`
	Mode  string `json:"mode"`
	IsUp  bool   `json:"is_up"`
	IsSet bool   `json:"is_set"`
}

func apiIfaces(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, collectIfaces())
}

func apiIfaceToggle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	type req struct {
		Name   string `json:"name"`
		Enable bool   `json:"enable"`
	}
	var m req
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if m.Name == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if m.Enable {
		if err := applyInterfaceMode(m.Name, IfaceEnforce); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := applyInterfaceMode(m.Name, IfaceOff); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := persistInterfaceSelection(m.Name, m.Enable); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	broadcastIfaces()
	writeJSON(w, map[string]string{"mode": string(GetIfaceMode(m.Name))})
}

func apiPeers(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, peerSnapshot())
}

func apiTrust(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, trustSnapshot())
}

func apiTrustPenalize(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		Peer string `json:"peer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Peer == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	penalizePeer(req.Peer)
	writeJSON(w, map[string]bool{"ok": true})
}

func apiTrustSet(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		Peer  string `json:"peer"`
		Level int    `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Peer == "" || req.Level < 0 || req.Level > 3 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	peer := normalizePeerAddr(req.Peer)
	if peer == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Level == 3 {
		addAuthoritativePeer(peer)
	} else {
		removeAuthoritativePeer(peer)
	}
	setTrustLevel(peer, req.Level)
	writeJSON(w, map[string]bool{"ok": true})
}

func apiAllow(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	body, _ := io.ReadAll(r.Body)
	if len(body) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		IP         string `json:"ip"`
		Reason     string `json:"reason"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("[ALLOW] decode error: %v body=%q", err, string(body))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		log.Printf("[ALLOW] empty ip body=%q", string(body))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.IP = sanitizeIPStr(req.IP)
	req.IP = normalizeIPKey(req.IP)
	if req.IP == "" {
		log.Printf("[ALLOW] empty ip after sanitize body=%q", string(body))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var ttl time.Duration
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if err := allowIP(req.IP, req.Reason, ttl, isLocalAuthoritative()); err != nil {
		http.Error(w, "allow failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	if liveUEE == nil {
		removeBan("\"" + req.IP + "\"")
		banMetaMu.Lock()
		delete(banMeta, req.IP)
		banMetaMu.Unlock()
	}
	log.Printf("[ALLOW] ip=%s allow_request=ok", req.IP)
	writeJSON(w, map[string]bool{"ok": true})
}

func apiBan(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		IP         string `json:"ip"`
		Reason     string `json:"reason"`
		TTLSeconds *int   `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.IP = sanitizeIPStr(req.IP)
	req.IP = normalizeIPKey(req.IP)
	if req.IP == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if Mode() == ModeTest {
		http.Error(w, "manual enforcement is unavailable in TEST mode", http.StatusConflict)
		return
	}
	if isWhitelisted(req.IP) {
		http.Error(w, "source is allowlisted", http.StatusBadRequest)
		return
	}
	duration, err := manualBanDuration(req.TTLSeconds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	alreadyBanned := false
	if liveUEE != nil {
		grants, err := liveUEE.Grants(req.IP, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, grant := range grants {
			if grant.Owner == localOwner("MANUAL") {
				alreadyBanned = true
				break
			}
		}
	} else {
		banMutex.Lock()
		_, alreadyBanned = banExpirations[req.IP]
		banMutex.Unlock()
	}
	if alreadyBanned {
		http.Error(w, "source already has a ban; use extend or release", http.StatusConflict)
		return
	}
	reason := req.Reason
	if reason == "" {
		reason = "manual block"
	}
	if err := triggerBan(req.IP, config.BindIP, "manual", "tcp", "MANUAL", reason, 0, 2, "ui", duration); err != nil {
		http.Error(w, "enforcement failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	banMutex.Lock()
	expires := banExpirations[req.IP]
	banMutex.Unlock()
	writeJSON(w, map[string]interface{}{"ok": true, "expires": expires.Format(time.RFC3339Nano)})
}

func apiBanExtend(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		IP         string `json:"ip"`
		TTLSeconds int    `json:"ttl_seconds"`
		Permanent  bool   `json:"permanent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.IP = sanitizeIPStr(req.IP)
	req.IP = normalizeIPKey(req.IP)
	if req.IP == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if Mode() == ModeTest {
		http.Error(w, "manual enforcement is unavailable in TEST mode", http.StatusConflict)
		return
	}
	if liveUEE != nil && req.Permanent {
		http.Error(w, "permanent bans are unavailable in the bounded enforcement engine", http.StatusBadRequest)
		return
	}
	if liveUEE != nil && req.TTLSeconds != 0 && (req.TTLSeconds < 30 || req.TTLSeconds > 86400) {
		http.Error(w, "ttl_seconds must be between 30 and 86400", http.StatusBadRequest)
		return
	}
	newExp := time.Now().Add(getBanDuration())
	if req.Permanent {
		newExp = permanentBanExpiry
	} else {
		if req.TTLSeconds > 0 {
			newExp = time.Now().Add(time.Duration(req.TTLSeconds) * time.Second)
		}
	}
	banMutex.Lock()
	if liveUEE != nil {
		if Mode() == ModeTest {
			banMutex.Unlock()
			http.Error(w, "manual enforcement is unavailable in TEST mode", http.StatusConflict)
			return
		}
		grants, err := liveUEE.Grants(req.IP, time.Now())
		if err != nil {
			banMutex.Unlock()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		foundManual := false
		for _, grant := range grants {
			if grant.Owner == localOwner("MANUAL") {
				foundManual = true
				if grant.ExpiresAt.After(newExp) {
					newExp = grant.ExpiresAt
				}
			}
		}
		if !foundManual {
			banMutex.Unlock()
			http.Error(w, "no manual ban to extend", http.StatusConflict)
			return
		}
		decision, err := ueeLocalGrant(req.IP, "MANUAL", "operator extension", newExp)
		if err != nil {
			banMutex.Unlock()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		newExp = decision.ExpiresAt
	} else if cur, ok := banExpirations[req.IP]; ok && cur.After(newExp) {
		newExp = cur
	}
	banExpirations[req.IP] = newExp
	banMutex.Unlock()
	if liveUEE == nil {
		persistBan(req.IP, newExp)
	}
	broadcastBans()
	writeJSON(w, map[string]interface{}{"ok": true, "expires": newExp.Format(time.RFC3339)})
}

func apiTrusted(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !trustedMeshNetworkEnabled() {
		http.Error(w, "trusted mesh participation is off", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		Action string `json:"action"`
		IP     string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.IP = sanitizeIPStr(req.IP)
	req.IP = normalizeIPKey(req.IP)
	if req.IP == "" || (req.Action != "add" && req.Action != "remove") {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Action == "add" {
		addTrustedPeerIP(req.IP)
	} else {
		removeTrustedPeerIP(req.IP)
	}
	saveConfig()
	writeJSON(w, map[string]interface{}{"ok": true, "trusted_peers": config.Security.TrustedPeers})
}

func apiMeshJoin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !trustedMeshNetworkEnabled() {
		http.Error(w, "trusted mesh participation is off", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		Peer  string `json:"peer"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Peer == "" || req.Token == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if scp == nil {
		http.Error(w, "mesh not running", http.StatusBadRequest)
		return
	}
	if max := meshMaxNodesAllowed(); max > 0 && !activeMeshPeerConfigured(req.Peer) {
		// Count local node + known peers
		if 1+meshPeerCount() >= max {
			http.Error(w, "max nodes reached", http.StatusForbidden)
			return
		}
	}
	adv := advertiseAddr()
	addr := fmt.Sprintf("%s:%s", adv, config.MeshPort)
	if err := scp.Join(req.Peer, req.Token, addr); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	addPeer(req.Peer)
	broadcastPeers()
	writeJSON(w, map[string]bool{"ok": true})
}

func apiMeshInvite(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !trustedMeshNetworkEnabled() {
		http.Error(w, "trusted mesh participation is off", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		TTLMinutes int `json:"ttl_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ttl := 30 * time.Minute
	if req.TTLMinutes > 0 {
		if req.TTLMinutes > 24*60 {
			req.TTLMinutes = 24 * 60
		}
		ttl = time.Duration(req.TTLMinutes) * time.Minute
	}
	token, expiresAt, err := issueJoinToken(ttl)
	if err != nil {
		http.Error(w, "failed to issue join token", http.StatusInternalServerError)
		return
	}
	peer := advertiseAddr()
	if peer != "" && !strings.Contains(peer, ":") {
		peer = peer + ":" + config.MeshPort
	}
	joinURL := ""
	if peer != "" {
		joinURL = "https://" + peer + "/mesh/join"
	}
	writeJSON(w, map[string]interface{}{
		"ok":          true,
		"token":       token,
		"expires_at":  expiresAt.Format(time.RFC3339),
		"peer":        peer,
		"join_url":    joinURL,
		"join_cmd":    fmt.Sprintf("honeymesh -join %s -t %s", joinURL, token),
		"remote_curl": fmt.Sprintf("curl -k -X POST https://%s/api/mesh/join -H 'X-Honey-Token: <LOCAL_ADMIN_TOKEN>' -H 'Content-Type: application/json' -d '{\"peer\":\"%s\",\"token\":\"%s\"}'", config.BindIP+":"+config.WebPort, peer, token),
	})
}

func apiBanRelease(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.IP = sanitizeIPStr(req.IP)
	req.IP = normalizeIPKey(req.IP)
	if req.IP == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if liveUEE != nil {
		banMutex.Lock()
		err := ueeReleaseLocal(req.IP, "local-admin", time.Now())
		if err == nil {
			_ = refreshLegacyBanView(time.Now())
		}
		banMutex.Unlock()
		if err != nil {
			http.Error(w, "release failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		broadcastBans()
		writeJSON(w, map[string]bool{"ok": true})
		return
	}

	banMutex.Lock()
	if liveExchangeRules != nil {
		if err := liveExchangeRules.clearIP(req.IP); err != nil {
			banMutex.Unlock()
			http.Error(w, "failed to clear shared rule ownership", http.StatusServiceUnavailable)
			return
		}
	}
	delete(banExpirations, req.IP)
	banMutex.Unlock()

	banMetaMu.Lock()
	delete(banMeta, req.IP)
	banMetaMu.Unlock()

	unbanIP(req.IP)
	markNodeEdgeReleased(req.IP, "operator_release")
	removeBan(req.IP)
	broadcastBans()

	log.Printf("[BAN] release ip=%s", req.IP)
	writeJSON(w, map[string]bool{"ok": true})
}

func apiMeshRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		Peer string `json:"peer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Peer == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := revokeMeshPeer(req.Peer); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	broadcastPeers()
	writeJSON(w, map[string]bool{"ok": true})
}

func apiLicense(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !json.Valid(body) {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := os.WriteFile("license.json", body, 0600); err != nil {
		http.Error(w, "failed to write license", http.StatusInternalServerError)
		return
	}
	// Reload license immediately so UI can enable enforcement without restart.
	lf, err := license.Load("license.json")
	if err != nil {
		http.Error(w, "license invalid: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := license.VerifyLicense(lf); err != nil {
		http.Error(w, "license invalid: "+err.Error(), http.StatusBadRequest)
		return
	}
	if lf.ClusterID != "" {
		_ = license.SetClusterID(lf.ClusterID)
	}
	clusterID := license.GetOrGenerateClusterID()
	if err := license.LoadAndVerify("license.json", clusterID); err != nil {
		http.Error(w, "license invalid: "+err.Error(), http.StatusBadRequest)
		return
	}
	handleLicenseRuntimeStateChange()
	writeJSON(w, licenseInfo{
		ClusterID: lf.ClusterID,
		ExpiresAt: lf.ExpiresAt.Format(time.RFC3339),
		MaxNodes:  lf.MaxNodes,
		Tier:      licenseDisplayName(),
		Signature: lf.Signature,
	})
}

func apiMode(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]string{"mode": Mode().String()})
		return
	}

	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

	type req struct {
		Mode string `json:"mode"`
	}
	var m req
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	switch m.Mode {
	case "TEST":
		if err := SetMode(ModeTest); err != nil {
			http.Error(w, "mode reconciliation failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	case "ENFORCE":
		if err := SetMode(ModeEnforce); err != nil {
			http.Error(w, "mode reconciliation failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	case "LOCKDOWN":
		if err := SetMode(ModeLockdown); err != nil {
			http.Error(w, "mode reconciliation failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "invalid mode", http.StatusBadRequest)
		return
	}

	broadcastMode()
	writeJSON(w, map[string]string{"mode": Mode().String()})
}

func apiHealth(w http.ResponseWriter, r *http.Request) {
	stats := localSurfaceStats()

	banMutex.Lock()
	localBans := len(banExpirations)
	banMutex.Unlock()

	remoteBanMu.Lock()
	meshBans := len(remoteBanCache)
	remoteBanMu.Unlock()
	activeLocalBans, activeMeshBans := localBans, meshBans
	pendingBans := 0
	if Mode() == ModeTest {
		activeLocalBans, activeMeshBans = 0, 0
		pendingBans = localBans
	}

	peerTotal := 0
	peerOnline := 0
	peerIfaceOnline := 0
	if scp != nil {
		peerTotal = scp.KnownPeerCount()
		now := time.Now()
		for _, st := range scp.PeerStatsDetailed() {
			if now.Sub(st.LastSeen) <= 60*time.Second {
				peerOnline++
				if len(st.Stats.IPs) > 0 {
					peerIfaceOnline += len(st.Stats.IPs)
				} else {
					peerIfaceOnline++
				}
			}
		}
	}
	// include local node as online
	localIfaces := localSurfaceStats().Ifaces
	peerOnline++
	peerIfaceOnline += localIfaces
	surfaceLocal := stats.Surface
	surfaceMesh := surfaceLocal
	if scp != nil {
		surfaceMesh = surfaceLocal + scp.SurfaceTotal()
	}
	exchangeStatus, exchangeLastPush, exchangeLastPull, exchangeLastHeartbeat := exchangeStatusSnapshot()

	writeJSON(w, map[string]interface{}{
		"status":                              "ok",
		"node":                                config.NodeName,
		"mode":                                Mode().String(),
		"enforce_allowed":                     true,
		"node_identity_established":           nodeIdentityReady(),
		"node_id":                             currentNodeIdentity().NodeID,
		"license_tier":                        effectiveLicenseTier(),
		"license_label":                       licenseDisplayName(),
		"premium_enabled":                     premiumFeaturesEnabled(),
		"trusted_network_sharing_enabled":     trustedNetworkSharingEnabled(),
		"trusted_mesh_network_enabled":        trustedMeshNetworkEnabled(),
		"direct_mesh_peer_limit":              directMeshPeerLimit(),
		"direct_mesh_peer_count":              len(activeMeshPeers()),
		"trusted_network_participation":       trustedMeshNetworkEnabled() && nodeIdentityReady(),
		"nettools_exchange_enabled":           config.Exchange.Enabled,
		"nettools_exchange_configured":        exchangeConfigured(),
		"honeymesh_exchange_connected":        exchangeConnected(),
		"honeymesh_exchange_cluster_id":       license.GetOrGenerateClusterID(),
		"honeymesh_exchange_trusted_clusters": normalizeClusterIDs(config.Exchange.TrustedClusters),
		"honeymesh_exchange_known_clusters":   exchangeClusterSnapshot(),
		"nettools_exchange_status":            exchangeStatus,
		"nettools_exchange_last_push":         exchangeLastPush,
		"nettools_exchange_last_pull":         exchangeLastPull,
		"nettools_exchange_last_heartbeat":    exchangeLastHeartbeat,
		"events":                              eventCount(),
		"bans":                                localBans,
		"pending_bans":                        pendingBans,
		"uptime_s":                            int(time.Since(startTime).Seconds()),
		"peer_total":                          peerTotal,
		"peer_online":                         peerOnline,
		"peer_iface_online":                   peerIfaceOnline,
		"surface_local":                       surfaceLocal,
		"surface_mesh":                        surfaceMesh,
		"blocks_local":                        activeLocalBans,
		"blocks_mesh":                         activeMeshBans,
		"threat_total":                        localThreats.Load(),
		"threat_mesh":                         localThreats.Load() + meshThreats.Load(),
		"mesh_intel_received":                 federationAccepted.Load(),
		"mesh_intel_rejected":                 federationRejected.Load(),
		"mesh_intel_contributed":              federationContributed.Load(),
		"mesh_intel_rejection_reasons":        federationRejectReasonsSnapshot(),
	})
}

type licenseInfo struct {
	ClusterID string `json:"cluster_id"`
	ExpiresAt string `json:"expires_at"`
	MaxNodes  int    `json:"max_nodes"`
	Tier      string `json:"tier"`
	Signature string `json:"signature"`
}

func apiLicenseInfo(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	data, err := os.ReadFile("license.json")
	if err != nil {
		writeJSON(w, licenseInfo{
			ClusterID: license.GetOrGenerateClusterID(),
			Tier:      licenseDisplayName(),
		})
		return
	}
	var li licenseInfo
	if err := json.Unmarshal(data, &li); err != nil {
		http.Error(w, "invalid license", http.StatusBadRequest)
		return
	}
	li.Tier = licenseDisplayName()
	if !premiumFeaturesEnabled() {
		li.ExpiresAt = ""
		li.MaxNodes = 0
	}
	writeJSON(w, li)
}

func normalizeTrustedCIDRs(input []string) ([]string, error) {
	out := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, raw := range input {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			if _, _, err := net.ParseCIDR(s); err != nil {
				return nil, fmt.Errorf("invalid CIDR: %s", s)
			}
		} else {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP: %s", s)
			}
			if ip.To4() != nil {
				s = ip.String() + "/32"
			} else {
				s = ip.String() + "/128"
			}
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, nil
}

type securitySettings struct {
	ScanPorts                    int                   `json:"scan_ports"`
	ScanWindowS                  int                   `json:"scan_window_s"`
	AllowlistBase                bool                  `json:"allowlist_base"`
	TrustedPeers                 []string              `json:"trusted_peers"`
	Whitelist                    []string              `json:"whitelist"`
	ExchangeTrustedClusters      []string              `json:"exchange_trusted_clusters"`
	ExchangeKnownClusters        []exchangeClusterView `json:"exchange_known_clusters"`
	TrustedMeshNetworks          []TrustedMeshNetwork  `json:"trusted_mesh_networks"`
	ExchangeConnected            bool                  `json:"exchange_connected"`
	ExchangeClusterID            string                `json:"exchange_cluster_id"`
	TrustedNetworkSharingEnabled bool                  `json:"trusted_network_sharing_enabled"`
	TrustedMeshNetworkEnabled    bool                  `json:"trusted_mesh_network_enabled"`
	PremiumEnabled               bool                  `json:"premium_enabled"`
	LicenseTier                  string                `json:"license_tier"`
}

func apiSecurity(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, securitySettings{
			ScanPorts:                    config.Security.ScanPorts,
			ScanWindowS:                  config.Security.ScanWindowS,
			AllowlistBase:                config.Security.AllowlistBase != nil && *config.Security.AllowlistBase,
			TrustedPeers:                 config.Security.TrustedPeers,
			Whitelist:                    config.Security.Whitelist,
			ExchangeTrustedClusters:      normalizeClusterIDs(config.Exchange.TrustedClusters),
			ExchangeKnownClusters:        exchangeClusterSnapshot(),
			TrustedMeshNetworks:          normalizeTrustedMeshNetworks(config.Mesh.TrustedNetworks),
			ExchangeConnected:            exchangeConnected(),
			ExchangeClusterID:            license.GetOrGenerateClusterID(),
			TrustedNetworkSharingEnabled: trustedNetworkSharingEnabled(),
			TrustedMeshNetworkEnabled:    trustedMeshNetworkEnabled(),
			PremiumEnabled:               premiumFeaturesEnabled(),
			LicenseTier:                  licenseDisplayName(),
		})
	case http.MethodPost:
		if !isOriginAllowed(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var req securitySettings
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.ScanPorts < 2 || req.ScanPorts > 100 {
			http.Error(w, "scan_ports must be 2-100", http.StatusBadRequest)
			return
		}
		if req.ScanWindowS < 10 || req.ScanWindowS > 600 {
			http.Error(w, "scan_window_s must be 10-600", http.StatusBadRequest)
			return
		}
		if req.TrustedMeshNetworkEnabled && !config.TrustedMeshNetworkEnabled {
			http.Error(w, "configure mesh TLS and enable trusted mesh in the config file, then restart", http.StatusConflict)
			return
		}
		normalized, err := normalizeTrustedCIDRs(req.TrustedPeers)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		normalizedWL, err := normalizeTrustedCIDRs(req.Whitelist)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		config.Security.ScanPorts = req.ScanPorts
		config.Security.ScanWindowS = req.ScanWindowS
		config.Security.AllowlistBase = &req.AllowlistBase
		config.Security.TrustedPeers = normalized
		config.Security.Whitelist = normalizedWL
		config.Exchange.TrustedClusters = normalizeClusterIDs(req.ExchangeTrustedClusters)
		config.Mesh.TrustedNetworks = normalizeTrustedMeshNetworks(req.TrustedMeshNetworks)
		if premiumFeaturesEnabled() && req.TrustedNetworkSharingEnabled && !exchangeConfigured() {
			if err := bootstrapExchangeFromLicense(); err != nil {
				http.Error(w, "nettools bootstrap failed: "+err.Error(), http.StatusBadGateway)
				return
			}
		}
		setTrustedNetworkSharing(req.TrustedNetworkSharingEnabled)
		setTrustedMeshNetwork(req.TrustedMeshNetworkEnabled)
		if req.AllowlistBase {
			initAllowlist(baseAllowlistCIDRs())
		} else {
			initAllowlist(nil)
		}
		refreshTrustedCIDRs(config.Security.TrustedPeers)
		refreshWhitelistCIDRs(config.Security.Whitelist)
		syncWhitelist()
		saveConfig()
		writeJSON(w, securitySettings{
			ScanPorts:                    config.Security.ScanPorts,
			ScanWindowS:                  config.Security.ScanWindowS,
			AllowlistBase:                config.Security.AllowlistBase != nil && *config.Security.AllowlistBase,
			TrustedPeers:                 config.Security.TrustedPeers,
			Whitelist:                    config.Security.Whitelist,
			ExchangeTrustedClusters:      normalizeClusterIDs(config.Exchange.TrustedClusters),
			ExchangeKnownClusters:        exchangeClusterSnapshot(),
			TrustedMeshNetworks:          normalizeTrustedMeshNetworks(config.Mesh.TrustedNetworks),
			ExchangeConnected:            exchangeConnected(),
			ExchangeClusterID:            license.GetOrGenerateClusterID(),
			TrustedNetworkSharingEnabled: trustedNetworkSharingEnabled(),
			TrustedMeshNetworkEnabled:    trustedMeshNetworkEnabled(),
			PremiumEnabled:               premiumFeaturesEnabled(),
			LicenseTier:                  licenseDisplayName(),
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func isOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	reqHost := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		reqHost = h
	}
	if host == reqHost || host == config.BindIP || host == "localhost" || host == "127.0.0.1" {
		return true
	}
	return false
}

func hasAttachedIface() bool {
	for _, i := range collectIfaces() {
		if i.Mode != "" && i.Mode != "off" && i.Mode != "unknown" {
			return true
		}
	}
	return false
}

type wsMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type eventView struct {
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
	JA4Label                 string  `json:"ja4_label"`
	JA3                      string  `json:"ja3"`
	JA3Label                 string  `json:"ja3_label"`
	TLSFingerprintFamily     string  `json:"tls_fingerprint_family"`
	TLSFingerprintVersion    string  `json:"tls_fingerprint_version"`
	TLSFingerprintConfidence int     `json:"tls_fingerprint_confidence"`
}

func decorateEvent(e Event) eventView {
	return eventView{
		Timestamp:                e.Timestamp,
		Attacker:                 e.Attacker,
		TargetIP:                 e.TargetIP,
		Target:                   e.Target,
		Service:                  e.Service,
		Node:                     e.Node,
		Type:                     e.Type,
		Payload:                  e.Payload,
		Entropy:                  e.Entropy,
		Interface:                e.Interface,
		JA4:                      e.JA4,
		JA4Label:                 ja4LabelFor(e.JA4),
		JA3:                      e.JA3,
		JA3Label:                 ja3LabelFor(e.JA3),
		TLSFingerprintFamily:     e.TLSFingerprintFamily,
		TLSFingerprintVersion:    e.TLSFingerprintVersion,
		TLSFingerprintConfidence: e.TLSFingerprintConfidence,
	}
}

func decorateEvents(events []Event) []eventView {
	if len(events) == 0 {
		return nil
	}
	out := make([]eventView, 0, len(events))
	for _, e := range events {
		out = append(out, decorateEvent(e))
	}
	return out
}

func broadcastWS(msgType string, data interface{}) {
	clientsMu.Lock()
	conns := make([]*websocket.Conn, 0, len(clients))
	for c := range clients {
		conns = append(conns, c)
	}
	clientsMu.Unlock()

	for _, c := range conns {
		if err := wsWrite(c, wsMessage{Type: msgType, Data: data}); err != nil {
			clientsMu.Lock()
			delete(clients, c)
			clientsMu.Unlock()
			c.Close()
		}
	}
}

func broadcastBans() {
	banMutex.Lock()
	copyMap := make(map[string]time.Time, len(banExpirations))
	for k, v := range banExpirations {
		copyMap[k] = v
	}
	banMutex.Unlock()
	broadcastWS("bans", copyMap)
}

func broadcastTraps() {
	broadcastWS("traps", trapSnapshot())
}

func broadcastIfaces() {
	broadcastWS("ifaces", collectIfaces())
}

func broadcastEvent(e Event) {
	broadcastWS("event", decorateEvent(e))
}

func broadcastMode() {
	broadcastWS("mode", map[string]string{"mode": Mode().String()})
}

func broadcastPeers() {
	broadcastWS("peers", peerSnapshot())
}

func collectIfaces() []ifaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]ifaceInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		ipList := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip.IsLinkLocalUnicast() {
				continue
			}
			ipList = append(ipList, ip.String())
		}
		mode := GetIfaceMode(iface.Name)
		isSet := mode != ""
		out = append(out, ifaceInfo{
			Name:  iface.Name,
			IPs:   strings.Join(ipList, ", "),
			Mode:  string(mode),
			IsUp:  true,
			IsSet: isSet,
		})
	}
	return out
}

func sendSnapshot(conn *websocket.Conn) {
	events := snapshotEvents(0)

	banMutex.Lock()
	bans := make(map[string]time.Time, len(banExpirations))
	for k, v := range banExpirations {
		bans[k] = v
	}
	banMutex.Unlock()

	_ = wsWrite(conn, wsMessage{Type: "traps", Data: trapSnapshot()})
	_ = wsWrite(conn, wsMessage{Type: "bans", Data: bans})
	_ = wsWrite(conn, wsMessage{Type: "ifaces", Data: collectIfaces()})
	_ = wsWrite(conn, wsMessage{Type: "peers", Data: peerSnapshot()})
	_ = wsWrite(conn, wsMessage{Type: "mode", Data: map[string]string{"mode": Mode().String()}})
	if len(events) > 0 {
		if len(events) > 15 {
			events = events[len(events)-15:]
		}
		_ = wsWrite(conn, wsMessage{Type: "events", Data: decorateEvents(events)})
	}
}

func wsWrite(conn *websocket.Conn, msg wsMessage) error {
	clientsMu.Lock()
	mu := clients[conn]
	clientsMu.Unlock()
	if mu == nil {
		return fmt.Errorf("websocket not registered")
	}
	mu.Lock()
	defer mu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	return conn.WriteJSON(msg)
}

type peerView struct {
	Address  string `json:"address"`
	LastSeen string `json:"last_seen"`
	AgeSec   int64  `json:"age_s"`
	Healthy  bool   `json:"healthy"`
	Bans     int    `json:"bans"`
	State    string `json:"state"`
}

func peerSnapshot() []peerView {
	if scp == nil {
		return nil
	}
	stats := scp.PeerStats()
	known := scp.KnownPeerStats()
	detailed := scp.PeerStatsDetailed()
	out := make([]peerView, 0, len(stats))
	now := time.Now()
	self := normalizePeerAddrUI(fmt.Sprintf("%s:%s", advertiseAddr(), config.MeshPort))
	banCounts := peerBanCounts()
	seen := make(map[string]struct{})
	for addr, ts := range stats {
		addr = normalizePeerAddrUI(addr)
		if addr == "" || addr == "0.0.0.0:9000" || addr == "[::]:9000" {
			continue
		}
		if addr == self {
			continue
		}
		age := int64(now.Sub(ts).Seconds())
		state := "offline"
		if age < 60 {
			state = "online"
		} else if age < 80 {
			state = "warning"
		}
		added := false
		if det, ok := detailed[addr]; ok && len(det.Stats.IPs) > 0 {
			for _, ip := range det.Stats.IPs {
				ip = strings.TrimSpace(ip)
				if ip == "" || ip == "0.0.0.0" || ip == "::" {
					continue
				}
				entry := normalizePeerAddrUI(fmt.Sprintf("%s:%s", ip, config.MeshPort))
				if entry == "" || entry == self {
					continue
				}
				out = append(out, peerView{
					Address:  entry,
					LastSeen: ts.Format(time.RFC3339),
					AgeSec:   age,
					Healthy:  age < 60,
					Bans:     banCounts[entry],
					State:    state,
				})
				seen[entry] = struct{}{}
				added = true
			}
		}
		if !added {
			out = append(out, peerView{
				Address:  addr,
				LastSeen: ts.Format(time.RFC3339),
				AgeSec:   age,
				Healthy:  age < 60,
				Bans:     banCounts[addr],
				State:    state,
			})
			seen[addr] = struct{}{}
		}
	}
	for p, ts := range known {
		addr := normalizePeerAddrUI(p)
		if addr == "" || addr == self {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		age := int64(now.Sub(ts).Seconds())
		if age >= 80 {
			continue
		}
		state := "offline"
		if age < 60 {
			state = "online"
		} else if age < 80 {
			state = "warning"
		}
		out = append(out, peerView{
			Address:  addr,
			LastSeen: ts.Format(time.RFC3339),
			AgeSec:   age,
			Healthy:  age < 60,
			Bans:     banCounts[addr],
			State:    state,
		})
	}
	return out
}

func peerBanCounts() map[string]int {
	out := make(map[string]int)
	now := time.Now()
	remoteBanMu.Lock()
	for ip, exp := range remoteBanCache {
		if now.After(exp) {
			continue
		}
		if remoteBanSources == nil {
			continue
		}
		peers := remoteBanSources[ip]
		for p := range peers {
			addr := normalizePeerAddrUI(p)
			if addr == "" {
				continue
			}
			out[addr]++
		}
	}
	remoteBanMu.Unlock()
	return out
}

func normalizePeerAddrUI(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	addr = strings.TrimPrefix(addr, "https://")
	if i := strings.Index(addr, "/"); i >= 0 {
		addr = addr[:i]
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "9000"
	}
	if host == "0.0.0.0" || host == "::" || host == "" {
		return ""
	}
	if !strings.Contains(host, ":") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}

type trapView struct {
	Enabled  bool   `json:"enabled"`
	Watchdog bool   `json:"watchdog"`
	Proto    string `json:"proto"`
	Banner   string `json:"banner"`
	Running  bool   `json:"running"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

func trapSnapshot() map[string]trapView {
	out := make(map[string]trapView, len(config.Traps))
	trapStatusMu.Lock()
	defer trapStatusMu.Unlock()
	for port, t := range config.Traps {
		st := trapStatus[port]
		status := "off"
		if t.Watchdog {
			status = "watchdog"
		} else if t.Enabled {
			if st.Running {
				status = "listening"
			} else {
				status = "error"
			}
		}
		out[port] = trapView{
			Enabled:  t.Enabled,
			Watchdog: t.Watchdog,
			Proto:    t.Proto,
			Banner:   t.Banner,
			Running:  st.Running,
			Status:   status,
			Error:    st.LastError,
		}
	}
	return out
}

// ─────────────────────────────────────────────
// DASHBOARD HTML — Your Exact Screenshot Style
// ─────────────────────────────────────────────
var dashboardHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HoneyMesh Bulwark SOC</title>
    <style>
        :root {
            --bg: #000000;
            --panel: #14213D;
            --accent: #FCA311;
            --text: #FFFFFF;
            --muted: #E4E4E4;
            --border: #2a3a5d;
            --red: #e63946;
            --green: #2ecc71;
            --warning-bg: rgba(230, 57, 70, 0.15);
            --warning-border: var(--red);
        }
        .network-row { display:flex; justify-content:space-between; gap:10px; align-items:center; padding:8px 10px; border:1px solid var(--border); border-radius:8px; background:rgba(255,255,255,0.02); margin-bottom:6px; }
        .network-row > div:first-child { min-width:0; word-break:break-all; font-family:ui-monospace,monospace; font-size:0.74rem; }
        .network-row > div:last-child { display:flex; gap:6px; flex-wrap:wrap; align-items:center; }
        body {
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font-family: system-ui, sans-serif;
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        header {
            background: #000;
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 3px solid var(--accent);
            flex-shrink: 0;
        }
        .logo {
            font-weight: 700;
            font-size: 1.5rem;
            color: var(--accent);
            letter-spacing: 1px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .logo img {
            height: 66px;
            width: 66px;
            object-fit: contain;
            background: #000;
        }
        .license {
            color: var(--green);
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            cursor: pointer;
        }
        .mode button {
            margin-left: 8px;
            padding: 6px 14px;
            border: none;
            border-radius: 4px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .mode button.inactive {
            opacity: 0.45;
            outline: 1px solid var(--border);
        }
        .mode button:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }
        .mode button:hover { opacity: 0.8; }
        .mode button.active {
            outline: 2px solid var(--accent);
            box-shadow: 0 0 0 2px rgba(252, 163, 17, 0.35);
        }
        .btn-test { background: var(--accent); color: #000; }
        .btn-enforce { background: #34495e; color: #fff; }
        .btn-lock { background: var(--red); color: #fff; }

        .kpis {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            padding: 15px;
            flex-shrink: 0;
            align-items: stretch;
        }
        .kpi {
            background: var(--panel);
            padding: 12px 14px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            justify-content: center;
            min-height: 72px;
        }
        .kpi b {
            font-size: 1.8rem;
            color: var(--accent);
            display: block;
        }
        .kpi span {
            font-size: 0.75rem;
            text-transform: uppercase;
            margin-top: 5px;
            opacity: 0.8;
            display: block;
        }

        .warning {
            background: var(--warning-bg);
            color: var(--red);
            padding: 10px;
            margin: 0 15px 15px 15px;
            border-radius: 6px;
            text-align: center;
            font-weight: 600;
            border: 1px solid var(--warning-border);
            flex-shrink: 0;
        }

        .main-grid {
            display: grid;
            grid-template-columns: 1fr 1.4fr 1.1fr;
            gap: 15px;
            padding: 0 15px;
            flex: 0 0 300px;
            min-height: 0;
        }
        .panel.live {
            margin: 15px;
            flex: 1.8;
            min-height: 0;
        }
        .panel.live.expanded {
            flex: 2.2;
        }
        .panel-header.clickable {
            cursor: pointer;
        }
        .modal {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.7);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 999;
        }
        .modal.open {
            display: flex;
        }
        .modal-card {
            width: min(1200px, 92vw);
            height: min(85vh, 900px);
            background: #0f1320;
            border: 1px solid var(--border);
            border-radius: 10px;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
        }
        .modal-header {
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            background: #000;
        }
        .tab-row {
            display: flex;
            gap: 8px;
        }
        .tab {
            padding: 6px 12px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: transparent;
            color: var(--text);
            cursor: pointer;
            font-weight: 600;
        }
        .tab.active {
            background: var(--accent);
            color: #000;
            border-color: var(--accent);
        }
        .modal-body {
            flex: 1;
            overflow: auto;
            padding: 12px;
        }
        .modal-close {
            background: transparent;
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 4px 10px;
            cursor: pointer;
        }
        .panel {
            background: var(--panel);
            border-radius: 8px;
            display: flex;
            flex-direction: column;
            border: 1px solid var(--border);
            overflow: hidden;
        }
        .panel-header {
            padding: 12px 15px;
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--accent);
            background: rgba(0,0,0,0.2);
            border-bottom: 1px solid var(--border);
            text-transform: uppercase;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .panel-header .header-actions {
            display: flex;
            gap: 8px;
            align-items: center;
        }
        .panel-body {
            padding: 12px;
            overflow: auto;
            flex: 1;
        }
        .iface-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 10px;
        }
        .iface-card {
            background: rgba(0,0,0,0.2);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .iface-card.stale {
            opacity: 0.45;
            filter: grayscale(0.2);
        }
        .iface-card.warn {
            border-color: #c26a00;
            box-shadow: 0 0 0 1px rgba(194,106,0,0.35);
        }
        .iface-meta {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        .iface-name {
            font-weight: 600;
        }
        .iface-state {
            font-size: 0.72rem;
            color: #9aa7c7;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        th {
            background: rgba(0,0,0,0.3);
            text-align: left;
            padding: 10px;
            color: var(--accent);
            position: sticky;
            top: 0;
            z-index: 1;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid var(--border);
            font-family: monospace;
        }
        .tag {
            background: var(--accent);
            color: #000;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
        }
        .btn {
            padding: 4px 10px;
            border: none;
            border-radius: 4px;
            font-size: 0.8rem;
            cursor: pointer;
        }
        .btn-red { background: var(--red); color: white; }
        .btn-green { background: var(--green); color: white; }
        .btn-accent { background: var(--accent); color: #000; }
        .btn-muted { background: #5a6377; color: #e2e8f0; }
        .ban-duration {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: #94a3b8;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }
        .ban-duration input {
            width: 70px;
            background: #0f172a;
            border: 1px solid #1f2a44;
            color: #e2e8f0;
            padding: 6px 8px;
            border-radius: 6px;
            text-align: center;
        }
        .ban-toolbar {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 10px;
        }
        .trap-item {
            padding: 6px 10px;
            border-bottom: 1px solid var(--border);
            display: flex;
            gap: 8px;
            align-items: center;
        }
        .trap-left {
            display: flex;
            align-items: center;
            gap: 6px;
            min-width: 0;
            flex: 1;
        }
        .trap-hex {
            font-size: 0.85rem;
            color: #5f6a82;
        }
        .trap-hex.active {
            color: var(--accent);
        }
        .ip-ok { color: var(--green); }
        .ip-bad { color: var(--red); }
        .trap-proto {
            font-size: 0.72rem;
            color: #9aa7c7;
        }
        .trap-actions {
            display: flex;
            gap: 6px;
            align-items: center;
            white-space: nowrap;
        }
        .scan-controls {
            display: flex;
            gap: 6px;
            align-items: center;
            font-size: 0.62rem;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        .scan-controls label {
            display: flex;
            align-items: center;
            gap: 4px;
            font-size: 0.62rem;
            color: #9aa7c7;
        }
        .scan-controls input {
            width: 48px;
            padding: 3px 6px;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: rgba(0,0,0,0.2);
            color: var(--text);
            font-size: 0.62rem;
        }
        .scan-controls .btn {
            padding: 4px 8px;
            font-size: 0.62rem;
        }
        .trap-status {
            color: var(--green);
            font-size: 0.7rem;
        }
        .trap-item .btn {
            padding: 3px 8px;
            font-size: 0.75rem;
        }
        .iface-item {
            padding: 6px 10px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .iface-status {
            color: var(--green);
            font-size: 0.7rem;
        }
        .scan-controls {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
            font-size: 0.72rem;
            color: #9aa7c7;
            margin-left: auto;
        }
        .scan-controls .scan-label {
            letter-spacing: 0.06em;
            font-weight: 700;
            color: var(--accent);
        }
        .scan-controls .scan-field {
            display: flex;
            align-items: center;
            gap: 6px;
            background: rgba(0,0,0,0.18);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 4px 8px;
        }
        .scan-controls .scan-field span {
            color: #9aa7c7;
            font-weight: 600;
            letter-spacing: 0.04em;
        }
        .scan-controls input[type="number"] {
            width: 64px;
            background: rgba(0,0,0,0.25);
            border: 1px solid var(--border);
            color: #e2e8f0;
            border-radius: 6px;
            padding: 2px 6px;
            font-size: 0.72rem;
        }
        .scan-controls label {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 0.7rem;
            color: #9aa7c7;
            font-weight: 600;
        }
        .scan-controls .btn {
            padding: 3px 10px;
            font-size: 0.72rem;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo"><img src="/static/logo.png" alt="HoneyMesh logo" />HONEY MESH <span id="cluster-id" style="font-size:0.7rem;color:#9aa7c7;margin-left:6px;"></span></div>
        <div class="license" id="license-pill">License: Community</div>
        <input type="file" id="license-file" accept="application/json" style="display:none" />
        <div class="mode">
            <button class="btn-test" onclick="setMode('TEST')">TEST MODE</button>
            <button class="btn-enforce" onclick="setMode('ENFORCE')">ENFORCE</button>
            <button class="btn-lock" onclick="setMode('LOCKDOWN')">LOCKDOWN</button>
        </div>
    </header>

    <div class="kpis">
        <div class="kpi"><b id="kpi-surface">0 / 0</b><span>PROTECTION SURFACE (LOCAL / NETWORK)</span></div>
        <div class="kpi"><b id="kpi-peers">0 / 0</b><span>DEFENSE NETWORK (NODES / INTERFACES ONLINE)</span></div>
        <div class="kpi"><b id="kpi-blocks">0 / 0</b><span>BLOCKS (LOCAL / NETWORK)</span></div>
        <div class="kpi"><b id="kpi-threats">0 / 0</b><span>THREATS (LOCAL / NETWORK)</span></div>
    </div>

    <div class="main-grid">
        <div class="panel">
            <div class="panel-header">
                <span>TRAPS&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>
                <div class="header-actions scan-controls">
                    <span class="scan-label">SCAN</span>
                    <div class="scan-field">
                        <input id="scan-ports" type="number" min="2" max="100" title="Ports threshold" />
                        <span>PORTS</span>
                        <span>/</span>
                        <input id="scan-window" type="number" min="10" max="600" title="Window (seconds)" />
                        <span>SEC</span>
                    </div>
                    <button class="btn btn-accent" onclick="saveScanSettings()">SAVE</button>
                </div>
            </div>
            <div class="panel-body" id="trap-list">
                <!-- Filled by JS -->
            </div>
        </div>

        <div class="panel">
            <div class="panel-header">INTERFACES</div>
            <div class="panel-body" id="iface-list">
                <div style="text-align:center;color:#666;padding:40px;">No interfaces found</div>
            </div>
        </div>

        <div class="panel">
            <div class="panel-header">
                <span>HONEYMESH DEFENSE NETWORK</span>
                <div class="header-actions">
                    <button class="btn btn-accent" id="trust-levels-btn" onclick="openTrustModal()">TRUST LEVELS</button>
                    <button class="btn btn-accent" id="trusted-peers-btn" onclick="openTrustedModal()">TRUSTED PEERS</button>
                </div>
            </div>
            <div class="panel-body" id="peer-list">
                <div style="display:grid; gap:12px; margin-bottom:16px;">
                    <div style="border:1px solid var(--border); border-radius:10px; padding:12px; background:rgba(0,0,0,0.12);">
                        <div style="font-size:0.78rem; letter-spacing:0.08em; color:var(--accent); margin-bottom:8px;">TEMPORARY MESH INVITE</div>
                        <div style="font-size:0.74rem; color:#9aa7c7; margin-bottom:10px;">Create a short-lived join token you can share with another admin without exposing the permanent admin token.</div>
                        <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                            <input id="mesh-invite-ttl" type="number" min="1" max="1440" value="30" style="width:100px;" />
                            <span style="font-size:0.72rem; color:#9aa7c7;">minutes</span>
                            <button class="btn btn-accent" onclick="createMeshInvite()">CREATE INVITE</button>
                        </div>
                        <div id="mesh-invite-output" style="margin-top:10px; font-size:0.74rem; color:#9aa7c7;">No active invite generated yet.</div>
                    </div>
                    <div style="border:1px solid var(--border); border-radius:10px; padding:12px; background:rgba(0,0,0,0.12);">
                        <div style="font-size:0.78rem; letter-spacing:0.08em; color:var(--accent); margin-bottom:8px;">JOIN WITH INVITE</div>
                        <div style="font-size:0.74rem; color:#9aa7c7; margin-bottom:10px;">Paste the peer address and temporary join token you received from another admin.</div>
                        <div style="display:grid; gap:8px;">
                            <input id="mesh-invite-peer" type="text" placeholder="10.0.0.243:9000" />
                            <input id="mesh-invite-token" type="text" placeholder="temporary join token" />
                        </div>
                        <div style="margin-top:10px; display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                            <button class="btn btn-accent" onclick="joinWithInvite()">JOIN WITH INVITE</button>
                            <div id="mesh-join-output" style="font-size:0.74rem; color:#9aa7c7;">Awaiting invite details.</div>
                        </div>
                    </div>
                </div>
	                <div id="mesh-status" style="color:var(--accent); font-size:0.8rem; margin-bottom:8px;"></div>
	                <div id="sharing-status" style="color:#cbd5f5; font-size:0.76rem; margin-bottom:10px;"></div>
	                <div style="border:1px solid var(--border); border-radius:10px; padding:12px; background:rgba(0,0,0,0.12); margin-bottom:12px;">
	                    <div style="font-size:0.78rem; letter-spacing:0.08em; color:var(--accent); margin-bottom:8px;">HONEYMESH EXCHANGE</div>
	                    <div id="nettools-status" style="color:#cbd5f5; font-size:0.76rem; margin-bottom:6px;">HoneyMesh Exchange status unavailable.</div>
	                    <div id="nettools-last-heartbeat" style="color:#9aa7c7; font-size:0.72rem; margin-bottom:4px;">Last heartbeat: -</div>
	                    <div id="nettools-last-push" style="color:#9aa7c7; font-size:0.72rem; margin-bottom:4px;">Last push: -</div>
	                    <div id="nettools-last-pull" style="color:#9aa7c7; font-size:0.72rem;">Last pull: -</div>
	                </div>
	                <div style="text-align:center;color:#666;padding:40px;">No peers</div>
	            </div>
	        </div>
    </div>

    <div class="panel live" id="live-panel">
        <div class="panel-header clickable" onclick="openLiveModal()">
            <span>LIVE THREAT STREAM</span>
                <div class="header-actions">
                    <button class="btn btn-muted" onclick="event.stopPropagation(); toggleEventOrder()" id="event-order-btn">NEWEST FIRST</button>
                    <button class="btn btn-muted" onclick="event.stopPropagation(); toggleEventStream()" id="event-stream-btn">PAUSE STREAM</button>
                    <button class="btn btn-muted" onclick="event.stopPropagation(); toggleAllowEvents()" id="event-allow-btn">ALLOW EVENTS: OFF</button>
                    <button class="btn btn-accent" onclick="event.stopPropagation(); downloadCSV()">DOWNLOAD CSV</button>
            </div>
        </div>
        <div class="panel-body">
            <div class="live-grid">
                <div class="live-panel">
                    <div class="panel-header">EVENTS</div>
                    <div class="panel-body">
                        <table id="events">
                            <thead>
                                <tr>
                                    <th>TIME</th>
                                    <th>IP ADDRESS</th>
                                    <th>PORT</th>
                                    <th>JA4 / JA3 LEGACY</th>
                                    <th>APP</th>
                                    <th>SESSION</th>
                                    <th>ACTION</th>
                                </tr>
                            </thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
                <div class="live-panel">
                    <div class="panel-header">
                        <span>ACTIVE BANS</span>
                        <div class="header-actions">
                            <label class="ban-duration">
                                DURATION (HRS)
                                <input type="number" class="ban-duration-input" min="1" max="168" step="1" value="5">
                            </label>
                            <button class="btn btn-accent" onclick="promptAllow()">ALLOW IP</button>
                        </div>
                    </div>
                    <div class="panel-body">
                        <table id="bans">
                            <thead>
                                <tr>
                                    <th>IP</th>
                                    <th>EXPIRES</th>
                                    <th>JA4 / JA3 LEGACY</th>
                                    <th>ACTION</th>
                                </tr>
                            </thead>
                            <tbody id="ban-list"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal" id="live-modal" onclick="closeLiveModal(event)">
        <div class="modal-card" onclick="event.stopPropagation()">
            <div class="modal-header">
                <div class="tab-row">
                    <button class="tab active" id="tab-events" onclick="showLiveTab('events')">EVENTS</button>
                    <button class="tab" id="tab-bans" onclick="showLiveTab('bans')">BANS</button>
                </div>
                <button class="modal-close" onclick="document.getElementById('live-modal').classList.remove('open')">CLOSE</button>
            </div>
        <div class="modal-body">
            <div id="block-status" style="color:#f59e0b; font-size:0.8rem; margin-bottom:8px;"></div>
            <div id="live-tab-events">
                    <table id="events-modal">
                        <thead>
                            <tr>
                                <th>TIME</th>
                                <th>IP ADDRESS</th>
                                <th>PORT</th>
                                <th>JA4 / JA3 LEGACY</th>
                                <th>APP</th>
                                <th>SESSION</th>
                                <th>ACTION</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
                <div id="live-tab-bans" style="display:none;">
                    <div class="ban-toolbar">
                        <label class="ban-duration">
                            DURATION (HRS)
                            <input type="number" class="ban-duration-input" min="1" max="168" step="1" value="5">
                        </label>
                    </div>
                    <table id="bans-modal">
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>EXPIRES</th>
                                <th>JA4 / JA3 LEGACY</th>
                                <th>ACTION</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div class="modal" id="trust-modal" onclick="closeTrustModal(event)">
        <div class="modal-card" onclick="event.stopPropagation()">
            <div class="modal-header">
                <div class="tab-row">
                    <button class="tab active">TRUST LEVELS</button>
                </div>
                <div class="header-actions">
                    <button class="btn btn-accent" onclick="refreshTrust()">REFRESH</button>
                    <button class="modal-close" onclick="document.getElementById('trust-modal').classList.remove('open')">CLOSE</button>
                </div>
            </div>
            <div class="modal-body">
                <table id="trust-modal-table">
                    <thead>
                        <tr>
                            <th>PEER</th>
                            <th>SCORE</th>
                            <th>LEVEL</th>
                            <th>REPORTS</th>
                            <th>VALID</th>
                            <th>INVALID</th>
                            <th>LAST</th>
                            <th>ACTION</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="modal" id="trusted-modal" onclick="closeTrustedModal(event)">
        <div class="modal-card" onclick="event.stopPropagation()">
            <div class="modal-header">
                <div class="tab-row">
                    <button class="tab active">TRUSTED PEERS</button>
                </div>
                <div class="header-actions">
                    <button class="btn btn-accent" onclick="loadTrustedPeers()">REFRESH</button>
                    <button class="modal-close" onclick="document.getElementById('trusted-modal').classList.remove('open')">CLOSE</button>
                </div>
            </div>
            <div class="modal-body">
                <div style="margin-bottom:14px;padding:12px;border:1px solid var(--border);border-radius:10px;background:rgba(0,0,0,0.18);">
                    <div style="font-size:0.82rem;font-weight:700;color:#e2e8f0;margin-bottom:6px;">Enable NetTools.cloud Sharing</div>
                    <div style="font-size:0.74rem;color:#9aa7c7;margin-bottom:10px;">Share validated attack intelligence with NetTools.cloud and receive curated attack data from other connected HoneyMesh applications.</div>
                    <label style="display:flex;align-items:center;gap:8px;font-size:0.76rem;color:#cbd5f5;font-weight:600;">
                        <input id="trusted-network-sharing" type="checkbox" />
                        SHARE ATTACK DATA WITH NETTOOLS.CLOUD
                    </label>
                    <div id="trusted-network-sharing-note" style="font-size:0.72rem;color:#7a88a9;margin-top:8px;">Available in Community mode with an operator-managed Exchange.</div>
                    <div style="margin-top:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                        <button class="btn btn-accent" onclick="saveTrustedSharingToggle()">SAVE SHARING</button>
                        <div id="trusted-network-sharing-status" style="font-size:0.72rem;color:#9aa7c7;">Sharing is currently off.</div>
                    </div>
                </div>
                <div style="margin-bottom:14px;padding:12px;border:1px solid var(--border);border-radius:10px;background:rgba(0,0,0,0.18);">
                    <div style="font-size:0.82rem;font-weight:700;color:#e2e8f0;margin-bottom:6px;">HoneyMesh Exchange Trust</div>
                    <div style="font-size:0.74rem;color:#9aa7c7;margin-bottom:10px;">Use cluster IDs to decide which HoneyMesh Exchange nodes this appliance should trust. Leave the list empty to accept all connected clusters.</div>
                    <div id="exchange-connection-status" style="font-size:0.74rem;color:#cbd5f5;margin-bottom:8px;">HoneyMesh Exchange connection status unavailable.</div>
                    <div id="exchange-cluster-id" style="font-size:0.72rem;color:#9aa7c7;margin-bottom:10px;">Local cluster ID: -</div>
                    <div style="font-size:0.72rem;color:#7a88a9;margin-bottom:6px;">Trusted exchange cluster IDs</div>
                    <textarea id="exchange-trusted-clusters" style="width:100%;height:110px;background:rgba(0,0,0,0.25);color:#e2e8f0;border:1px solid var(--border);border-radius:8px;padding:10px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;"></textarea>
                    <div style="font-size:0.72rem;color:#7a88a9;margin:10px 0 6px;">Observed exchange cluster IDs</div>
                    <div id="exchange-known-clusters" style="display:grid;gap:8px;"></div>
                </div>
                <div style="margin-bottom:14px;padding:12px;border:1px solid var(--border);border-radius:10px;background:rgba(0,0,0,0.18);">
                    <div style="font-size:0.82rem;font-weight:700;color:#e2e8f0;margin-bottom:6px;">Trusted Mesh Networks</div>
                    <div style="font-size:0.74rem;color:#9aa7c7;margin-bottom:10px;">Use exchange-discovered cluster IDs to define how much HoneyMesh should trust other networks after an admin explicitly joins them. Exchange stays discovery-only; mesh join still requires a peer address and token.</div>
                    <div id="trusted-mesh-networks" style="display:grid;gap:8px;"></div>
                </div>
                <div style="margin-bottom:14px;padding:12px;border:1px solid var(--border);border-radius:10px;background:rgba(0,0,0,0.18);">
                    <div style="font-size:0.82rem;font-weight:700;color:#e2e8f0;margin-bottom:6px;">Join Trusted HoneyMesh Networks</div>
                    <div style="font-size:0.74rem;color:#9aa7c7;margin-bottom:10px;">Enable peer-to-peer trusted mesh participation so this node can issue invites, join approved HoneyMesh networks, and exchange validated defense signals with trusted peers.</div>
                    <div style="font-size:0.72rem;color:#9aa7c7;margin-bottom:10px;">Community supports up to five direct peers per node. A self-hosted Community Exchange remains independent and free.</div>
                    <label style="display:flex;align-items:center;gap:8px;font-size:0.76rem;color:#cbd5f5;font-weight:600;">
                        <input id="trusted-mesh-network" type="checkbox" />
                        ALLOW THIS NODE TO JOIN TRUSTED MESH NETWORKS
                    </label>
                    <div id="trusted-mesh-network-note" style="font-size:0.72rem;color:#7a88a9;margin-top:8px;">Requires explicit mesh TLS trust and operator opt-in.</div>
                    <div style="margin-top:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                        <button class="btn btn-accent" onclick="saveTrustedMeshToggle()">SAVE MESH</button>
                        <div id="trusted-mesh-network-status" style="font-size:0.72rem;color:#9aa7c7;">Trusted mesh participation is currently off.</div>
                    </div>
                </div>
                <div style="font-size:0.8rem;color:#9aa7c7;margin-bottom:8px;">Central whitelist control. One per line. CIDR or IP (auto-converted to /32 or /128).</div>
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
                    <label style="display:flex;align-items:center;gap:6px;font-size:0.75rem;color:#9aa7c7;font-weight:600;">
                        <input id="allowlist-base" type="checkbox" />
                        BASE ALLOWLIST (RFC1918 + local)
                    </label>
                    <span style="font-size:0.7rem;color:#7a88a9;">Includes 10/8, 172.16/12, 192.168/16, localhost, link‑local.</span>
                </div>
                <div style="font-size:0.72rem;color:#7a88a9;margin-bottom:6px;">Config whitelist (security.whitelist) is shown below and editable.</div>
                <textarea id="whitelist-peers" style="width:100%;height:140px;background:rgba(0,0,0,0.25);color:#e2e8f0;border:1px solid var(--border);border-radius:8px;padding:10px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;"></textarea>
                <div style="font-size:0.72rem;color:#7a88a9;margin:10px 0 6px;">Trusted peers (security.trusted_peers) are shown below and editable.</div>
                <textarea id="trusted-peers" style="width:100%;height:220px;background:rgba(0,0,0,0.25);color:#e2e8f0;border:1px solid var(--border);border-radius:8px;padding:10px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;"></textarea>
                <div style="margin-top:14px;padding:12px;border:1px solid var(--border);border-radius:10px;background:rgba(0,0,0,0.18);">
                    <div style="font-size:0.82rem;font-weight:700;color:#e2e8f0;margin-bottom:6px;">Temporary Mesh Token</div>
                    <div style="font-size:0.72rem;color:#7a88a9;margin-bottom:10px;">Generate a short-lived token to share with another admin. They can use it to join your trusted HoneyMesh network without exposing your permanent admin token.</div>
                    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
                        <input id="trusted-mesh-ttl" type="number" min="1" max="1440" value="30" style="width:110px;" />
                        <span style="font-size:0.72rem;color:#9aa7c7;">minutes</span>
                        <button class="btn btn-accent" onclick="createTrustedMeshInvite()">GENERATE</button>
                    </div>
                    <div id="trusted-mesh-invite-output" style="font-size:0.72rem;color:#9aa7c7;">No temporary token generated yet.</div>
                </div>
                <div style="margin-top:14px;padding:12px;border:1px solid var(--border);border-radius:10px;background:rgba(0,0,0,0.18);">
                    <div style="font-size:0.82rem;font-weight:700;color:#e2e8f0;margin-bottom:6px;">Join With Temporary Token</div>
                    <div style="font-size:0.72rem;color:#7a88a9;margin-bottom:10px;">Paste the peer address and temporary token you received from another admin.</div>
                    <div style="display:grid;gap:8px;">
                        <input id="trusted-mesh-peer" type="text" placeholder="10.0.0.243:9000" />
                        <input id="trusted-mesh-token" type="text" placeholder="temporary join token" />
                    </div>
                    <div style="margin-top:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                        <button class="btn btn-accent" onclick="joinTrustedMeshInvite()">JOIN WITH TOKEN</button>
                        <div id="trusted-mesh-join-output" style="font-size:0.72rem;color:#9aa7c7;">Awaiting peer and token.</div>
                    </div>
                </div>
                <div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end;">
                    <button class="btn btn-accent" onclick="saveTrustedPeers()">SAVE</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        const TOKEN = prompt("Enter Admin Token") || "";
        let trustedMeshNetworksState = [];
        let lastExchangeKnownClusters = [];
        let lastTrustedPeersError = "";

        let unauthorizedShown = false;
        async function api(endpoint, options = {}) {
            try {
                const res = await fetch('/api' + endpoint, {
                    headers: {
                        'X-Honey-Token': TOKEN,
                        'Content-Type': 'application/json'
                    },
                    ...options
                });
                if (!res.ok) {
                    if (res.status === 401 && !unauthorizedShown) {
                        unauthorizedShown = true;
                        alert("Unauthorized: check admin token");
                    }
                    console.error("API Error:", res.status);
                    return null;
                }
                const ct = res.headers.get("content-type") || "";
                if (ct.includes("application/json")) {
                    return await res.json();
                }
                return null;
            } catch (e) {
                console.error("API Error:", e);
                return null;
            }
        }

        async function setMode(mode) {
            await api('/mode', {
                method: 'POST',
                body: JSON.stringify({mode: mode})
            });
        }

        async function loadScanSettings() {
            const res = await api('/security');
            if (!res) return;
            const ports = document.getElementById('scan-ports');
            const windowEl = document.getElementById('scan-window');
            const allowBase = document.getElementById('allowlist-base');
            if (ports) ports.value = res.scan_ports || 10;
            if (windowEl) windowEl.value = res.scan_window_s || 60;
            if (allowBase) allowBase.checked = !!res.allowlist_base;
        }

        async function saveScanSettings() {
            const ports = document.getElementById('scan-ports');
            const windowEl = document.getElementById('scan-window');
            const allowBase = document.getElementById('allowlist-base');
            const sharing = document.getElementById('trusted-network-sharing');
            const meshToggle = document.getElementById('trusted-mesh-network');
            if (!ports || !windowEl) return;
            const payload = {
                scan_ports: parseInt(ports.value || "10", 10),
                scan_window_s: parseInt(windowEl.value || "60", 10),
                allowlist_base: allowBase ? allowBase.checked : true,
                trusted_network_sharing_enabled: !!(sharing && sharing.checked),
                trusted_mesh_network_enabled: !!(meshToggle && meshToggle.checked)
            };
            const res = await api('/security', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            if (res) {
                ports.value = res.scan_ports;
                windowEl.value = res.scan_window_s;
                if (allowBase) allowBase.checked = !!res.allowlist_base;
                if (sharing) {
                    sharing.checked = !!res.trusted_network_sharing_enabled;
                    sharing.disabled = false;
                }
                if (meshToggle) {
                    meshToggle.checked = !!res.trusted_mesh_network_enabled;
                    meshToggle.disabled = false;
                }
                renderSharingStatus(res.license_tier, !!res.premium_enabled, !!res.trusted_network_sharing_enabled, !!res.trusted_mesh_network_enabled);
            }
        }

        function openTrustedModal() {
            document.getElementById('trusted-modal').classList.add('open');
            loadTrustedPeers();
        }

        function closeTrustedModal(e) {
            if (e.target.id === 'trusted-modal') {
                document.getElementById('trusted-modal').classList.remove('open');
            }
        }

        function renderInviteOutput(output, data) {
            output.replaceChildren();
            [['Peer', data.peer || '-'], ['Token', data.token || '-'], ['Expires', data.expires_at || '-'], ['CLI', data.join_cmd || '-']].forEach(([label, value]) => {
                const row = document.createElement('div');
                const strong = document.createElement('strong');
                strong.textContent = label + ': ';
                row.appendChild(strong);
                const code = document.createElement('code');
                code.textContent = String(value);
                row.appendChild(code);
                output.appendChild(row);
            });
        }

        async function createTrustedMeshInvite() {
            const ttlEl = document.getElementById('trusted-mesh-ttl');
            const output = document.getElementById('trusted-mesh-invite-output');
            const ttlMinutes = Number(ttlEl && ttlEl.value ? ttlEl.value : 30);
            if (output) output.textContent = "Generating temporary token...";
            const res = await api('/mesh/invite', {
                method: 'POST',
                body: JSON.stringify({ ttl_minutes: ttlMinutes })
            });
            if (!res) {
                if (output) output.textContent = "Failed to generate temporary token.";
                return;
            }
            if (output) renderInviteOutput(output, res);
            const peerField = document.getElementById('trusted-mesh-peer');
            const tokenField = document.getElementById('trusted-mesh-token');
            if (peerField && res.peer) peerField.value = res.peer;
            if (tokenField && res.token) tokenField.value = res.token;
        }

        async function joinTrustedMeshInvite() {
            const peerField = document.getElementById('trusted-mesh-peer');
            const tokenField = document.getElementById('trusted-mesh-token');
            const output = document.getElementById('trusted-mesh-join-output');
            let peer = peerField && peerField.value ? peerField.value.trim() : "";
            const token = tokenField && tokenField.value ? tokenField.value.trim() : "";
            if (!peer || !token) {
                if (output) output.textContent = "Peer address and temporary token are required.";
                return;
            }
            if (peer && !peer.includes(":")) {
                peer = peer + ":9000";
            }
            if (output) output.textContent = "Sending join request...";
            const res = await api('/mesh/join', {
                method: 'POST',
                body: JSON.stringify({ peer: peer, token: token })
            });
            if (!res) {
                if (output) output.textContent = "Join request failed.";
                return;
            }
            if (output) output.textContent = "Join request sent to " + peer;
            const meshStatus = document.getElementById('mesh-status');
            if (meshStatus) meshStatus.textContent = "Join request sent to " + peer;
            refreshPeers();
        }

        async function loadTrustedPeers() {
            const res = await api('/security');
            if (!res) return;
            const box = document.getElementById('trusted-peers');
            const wl = document.getElementById('whitelist-peers');
            const exchangeTrusted = document.getElementById('exchange-trusted-clusters');
            const sharing = document.getElementById('trusted-network-sharing');
            const sharingNote = document.getElementById('trusted-network-sharing-note');
            const meshToggle = document.getElementById('trusted-mesh-network');
            const meshNote = document.getElementById('trusted-mesh-network-note');
            if (!box || !wl) return;
            box.value = (res.trusted_peers || []).join("\n");
            wl.value = (res.whitelist || []).join("\n");
            if (exchangeTrusted) exchangeTrusted.value = (res.exchange_trusted_clusters || []).join("\n");
            if (sharing) {
                sharing.checked = !!res.trusted_network_sharing_enabled;
                sharing.disabled = false;
            }
            if (meshToggle) {
                meshToggle.checked = !!res.trusted_mesh_network_enabled;
                meshToggle.disabled = false;
            }
            if (sharingNote) {
                sharingNote.textContent = "Exchange sharing requires an operator-managed Exchange connection.";
            }
            if (meshNote) {
                meshNote.textContent = "Trusted mesh participation is off by default and requires explicit TLS trust and opt-in.";
            }
            trustedMeshNetworksState = Array.isArray(res.trusted_mesh_networks) ? res.trusted_mesh_networks.slice() : [];
            lastExchangeKnownClusters = Array.isArray(res.exchange_known_clusters) ? res.exchange_known_clusters : [];
            renderExchangeConnection(res.exchange_connected, res.exchange_cluster_id);
            renderExchangeKnownClusters(lastExchangeKnownClusters);
            renderTrustedMeshNetworks(lastExchangeKnownClusters);
        }

        async function saveTrustedPeers() {
            const box = document.getElementById('trusted-peers');
            const wl = document.getElementById('whitelist-peers');
            const exchangeTrusted = document.getElementById('exchange-trusted-clusters');
            const sharing = document.getElementById('trusted-network-sharing');
            const meshToggle = document.getElementById('trusted-mesh-network');
            if (!box || !wl) return null;
            const list = box.value.split("\n").map(s => s.trim()).filter(Boolean);
            const wlList = wl.value.split("\n").map(s => s.trim()).filter(Boolean);
            const exchangeTrustedList = exchangeTrusted ? exchangeTrusted.value.split("\n").map(s => s.trim()).filter(Boolean) : [];
            const payload = {
                scan_ports: parseInt(document.getElementById('scan-ports')?.value || "10", 10),
                scan_window_s: parseInt(document.getElementById('scan-window')?.value || "60", 10),
                allowlist_base: document.getElementById('allowlist-base')?.checked ?? true,
                trusted_peers: list,
                whitelist: wlList,
                exchange_trusted_clusters: exchangeTrustedList,
                trusted_mesh_networks: trustedMeshNetworksState,
                trusted_network_sharing_enabled: !!(sharing && sharing.checked),
                trusted_mesh_network_enabled: !!(meshToggle && meshToggle.checked)
            };
            lastTrustedPeersError = "";
            const response = await fetch('/api/security', {
                method: 'POST',
                headers: {
                    'X-Honey-Token': TOKEN,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });
            if (!response.ok) {
                try {
                    lastTrustedPeersError = (await response.text()).trim();
                } catch (_) {
                    lastTrustedPeersError = "";
                }
                if (!lastTrustedPeersError) {
                    lastTrustedPeersError = "request failed with status " + response.status;
                }
                return null;
            }
            const res = await response.json();
            if (res && box) {
                box.value = (res.trusted_peers || []).join("\n");
                if (wl) wl.value = (res.whitelist || []).join("\n");
                if (exchangeTrusted) exchangeTrusted.value = (res.exchange_trusted_clusters || []).join("\n");
                if (sharing) {
                    sharing.checked = !!res.trusted_network_sharing_enabled;
                    sharing.disabled = false;
                }
                if (meshToggle) {
                    meshToggle.checked = !!res.trusted_mesh_network_enabled;
                    meshToggle.disabled = false;
                }
                trustedMeshNetworksState = Array.isArray(res.trusted_mesh_networks) ? res.trusted_mesh_networks.slice() : [];
                renderSharingStatus(res.license_tier, !!res.premium_enabled, !!res.trusted_network_sharing_enabled, !!res.trusted_mesh_network_enabled);
                lastExchangeKnownClusters = Array.isArray(res.exchange_known_clusters) ? res.exchange_known_clusters : [];
                renderExchangeConnection(res.exchange_connected, res.exchange_cluster_id);
                renderExchangeKnownClusters(lastExchangeKnownClusters);
                renderTrustedMeshNetworks(lastExchangeKnownClusters);
                updateHealth();
            }
            return res;
        }

        async function saveTrustedSharingToggle() {
            const status = document.getElementById('trusted-network-sharing-status');
            if (status) status.textContent = "Saving sharing setting...";
            const res = await saveTrustedPeers();
            const sharing = document.getElementById('trusted-network-sharing');
            if (status) {
                if (!res) {
                    status.textContent = "Unable to save NetTools.cloud sharing: " + (lastTrustedPeersError || "unknown error");
                } else {
                    status.textContent = sharing && sharing.checked
                        ? "NetTools.cloud sharing is enabled and syncing automatically."
                        : "NetTools.cloud sharing is off.";
                }
            }
        }

        async function saveTrustedMeshToggle() {
            const status = document.getElementById('trusted-mesh-network-status');
            if (status) status.textContent = "Saving mesh setting...";
            const res = await saveTrustedPeers();
            const meshToggle = document.getElementById('trusted-mesh-network');
            if (status) {
                if (!res) {
                    status.textContent = "Unable to save trusted mesh participation: " + (lastTrustedPeersError || "unknown error");
                } else {
                    status.textContent = meshToggle && meshToggle.checked
                        ? "Trusted mesh participation is enabled."
                        : "Trusted mesh participation is off.";
                }
            }
        }

        function setModeUI(mode, enforceAllowed) {
            const buttons = document.querySelectorAll('.mode button');
            buttons.forEach(b => b.classList.remove('active', 'inactive'));
            if (mode === "TEST") document.querySelector('.btn-test')?.classList.add('active');
            if (mode === "ENFORCE") document.querySelector('.btn-enforce')?.classList.add('active');
            if (mode === "LOCKDOWN") document.querySelector('.btn-lock')?.classList.add('active');

            buttons.forEach(b => {
                if (!b.classList.contains('active')) {
                    b.classList.add('inactive');
                }
            });

            const enforceBtn = document.querySelector('.btn-enforce');
            const lockBtn = document.querySelector('.btn-lock');
            if (enforceBtn) enforceBtn.disabled = false;
            if (lockBtn) lockBtn.disabled = false;
        }

        function renderSharingStatus(licenseLabel, premiumEnabled, sharingEnabled, meshEnabled) {
            const status = document.getElementById('sharing-status');
            const modalStatus = document.getElementById('trusted-network-sharing-status');
            const meshModalStatus = document.getElementById('trusted-mesh-network-status');
            const licenseText = licenseLabel || "Community";
            const sharingText = sharingEnabled ? "Enabled" : "Off";
            const meshText = meshEnabled ? "Enabled" : "Off";
            if (status) status.textContent = "License: " + licenseText + " • NetTools.cloud Sharing: " + sharingText + " • Trusted Mesh Networks: " + meshText;
            if (modalStatus) {
                modalStatus.textContent = sharingEnabled
                    ? "NetTools.cloud sharing is enabled and syncing automatically."
                    : "NetTools.cloud sharing is off.";
            }
            if (meshModalStatus) {
                meshModalStatus.textContent = meshEnabled
                    ? "Trusted mesh participation is enabled."
                    : "Trusted mesh participation is off.";
            }
        }

        function renderExchangeConnection(connected, clusterID) {
            const status = document.getElementById('exchange-connection-status');
            const cluster = document.getElementById('exchange-cluster-id');
            if (status) {
                status.textContent = connected
                    ? "Connected to HoneyMesh Exchange."
                    : "Not connected to HoneyMesh Exchange.";
            }
            if (cluster) {
                cluster.textContent = "Local cluster ID: " + (clusterID || "-");
            }
        }

        function renderExchangeKnownClusters(clusters) {
            const box = document.getElementById('exchange-known-clusters');
            if (!box) return;
            box.replaceChildren();
            if (!clusters || !clusters.length) {
                box.textContent = 'No exchange cluster IDs observed yet.';
                return;
            }
            clusters.forEach(cluster => {
                const row = document.createElement('div');
                row.className = 'network-row';
                const info = document.createElement('div');
                const id = document.createElement('div');
                id.textContent = cluster.cluster_id || '';
                info.appendChild(id);
                const seen = document.createElement('div');
                seen.textContent = 'Last seen: ' + (cluster.last_seen || 'not observed yet');
                info.appendChild(seen);
                row.appendChild(info);
                const actions = document.createElement('div');
                const badge = document.createElement('span');
                badge.textContent = cluster.trusted ? 'TRUSTED' : 'UNTRUSTED';
                actions.appendChild(badge);
                [1, 2, 3].forEach(level => {
                    const button = document.createElement('button');
                    button.className = 'btn btn-accent';
                    button.textContent = 'L' + level;
                    button.addEventListener('click', () => setTrustedMeshNetworkLevelFromEncoded(encodeURIComponent(cluster.cluster_id), level));
                    actions.appendChild(button);
                });
                row.appendChild(actions);
                box.appendChild(row);
            });
        }

        function setTrustedMeshNetworkLevelFromEncoded(encodedClusterID, level) {
            const clusterID = decodeURIComponent(encodedClusterID || '').trim();
            if (!clusterID) return;
            trustedMeshNetworksState = (trustedMeshNetworksState || []).filter(network => (network.cluster_id || '').trim() !== clusterID);
            if (level >= 0) {
                trustedMeshNetworksState.push({ cluster_id: clusterID, trust_level: level });
            }
            renderTrustedMeshNetworks(lastExchangeKnownClusters);
        }

        function trustLevelLabel(level) {
            switch (Number(level)) {
                case 3: return 'L3 AUTHORITATIVE';
                case 2: return 'L2 TRUSTED';
                case 1: return 'L1 FEDERATED';
                case 0: return 'L0 OBSERVE';
                default: return 'NOT TRUSTED';
            }
        }

        function renderTrustedMeshNetworks(discoveredClusters) {
            const box = document.getElementById('trusted-mesh-networks');
            if (!box) return;
            const configured = Array.isArray(trustedMeshNetworksState) ? trustedMeshNetworksState : [];
            const merged = new Map();
            (discoveredClusters || []).forEach(cluster => {
                const clusterID = (cluster.cluster_id || '').trim();
                if (clusterID) merged.set(clusterID, {cluster_id: clusterID, trust_level: -1, discovered: true});
            });
            configured.forEach(network => {
                const clusterID = (network.cluster_id || '').trim();
                if (clusterID) merged.set(clusterID, {cluster_id: clusterID, trust_level: Number(network.trust_level), discovered: merged.has(clusterID)});
            });
            box.replaceChildren();
            const rows = Array.from(merged.values()).sort((a, b) => a.cluster_id.localeCompare(b.cluster_id));
            if (!rows.length) {
                box.textContent = 'No discovered networks yet. Once exchange traffic shows other cluster IDs, you can assign L0-L3 trust here.';
                return;
            }
            rows.forEach(network => {
                const row = document.createElement('div');
                row.className = 'network-row';
                const info = document.createElement('div');
                const id = document.createElement('div');
                id.textContent = network.cluster_id;
                info.appendChild(id);
                const status = document.createElement('div');
                status.textContent = trustLevelLabel(network.trust_level) + (network.discovered ? ' • discovered via exchange' : '');
                info.appendChild(status);
                row.appendChild(info);
                const actions = document.createElement('div');
                [0, 1, 2, 3, -1].forEach(level => {
                    const button = document.createElement('button');
                    button.className = level < 0 ? 'btn btn-red' : 'btn btn-accent';
                    button.textContent = level < 0 ? 'REMOVE' : 'L' + level;
                    button.addEventListener('click', () => setTrustedMeshNetworkLevelFromEncoded(encodeURIComponent(network.cluster_id), level));
                    actions.appendChild(button);
                });
                row.appendChild(actions);
                box.appendChild(row);
            });
        }

        let liveTab = "events";
        let newestFirst = true;
        let streamPaused = false;
        let allowXDPEvents = false;

        function isLocalIP(ip) {
            if (!ip) return false;
            if (ip.startsWith("::ffff:")) {
                ip = ip.replace("::ffff:", "");
            }
            if (ip === "127.0.0.1" || ip === "::1") return true;
            if (ip.startsWith("10.")) return true;
            if (ip.startsWith("192.168.")) return true;
            if (ip.startsWith("172.")) {
                const parts = ip.split(".");
                const second = parseInt(parts[1] || "0", 10);
                if (second >= 16 && second <= 31) return true;
            }
            if (ip.startsWith("fc") || ip.startsWith("fd")) return true; // fc00::/7
            if (ip.startsWith("fe80:")) return true; // link-local
            return false;
        }

        function renderEvents(events, targetSelector) {
            const sel = targetSelector || "#events tbody";
            const tbody = document.querySelector(sel);
            if (!tbody) return;
            const list = events || [];
            const limit = targetSelector ? 200 : 15;
            const slice = list.slice(-limit);
            if (newestFirst) {
                slice.reverse();
            }
            const existing = new Map();
            Array.from(tbody.querySelectorAll("tr[data-key]")).forEach((tr) => {
                existing.set(tr.getAttribute("data-key"), tr);
            });
            const frag = document.createDocumentFragment();
            slice.forEach(e => {
                if (isLocalIP(e.attacker)) return;
                const key = [e.timestamp, e.attacker, e.target, e.type].join("|");
                let tr = existing.get(key);
                if (!tr) {
                    tr = document.createElement("tr");
                    tr.setAttribute("data-key", key);
                    for (let i = 0; i < 7; i++) {
                        tr.appendChild(document.createElement("td"));
                    }
                }
                const t = (e.type || "").toUpperCase();
                const isAttack = t === "TRAP" || t === "XDP_DROP" || t.includes("DROP") || t.includes("TRAP");
                const ipClass = isAttack ? "ip-bad" : "ip-ok";
                const cells = tr.children;
                cells[0].textContent = e.timestamp || "";
                cells[1].textContent = e.attacker || "";
                cells[1].className = ipClass;
                cells[2].textContent = e.target || "";
                let fpText = e.ja4 || "-";
                if (e.ja4_label) {
                    fpText = fpText + " • " + e.ja4_label;
                }
                if (e.ja3) {
                    fpText = fpText + " | JA3 " + e.ja3;
                    if (e.ja3_label) {
                        fpText = fpText + " • " + e.ja3_label;
                    }
                }
                cells[3].textContent = fpText;
                cells[4].textContent = e.service || "-";
                cells[5].textContent = e.payload || "-";
                cells[5].style.fontSize = "0.7rem";
                cells[5].style.color = "#888";
                const ip = e.attacker || "";
                cells[6].replaceChildren();
                const blockButton = document.createElement('button');
                blockButton.className = 'btn btn-red block-btn';
                blockButton.dataset.ip = ip;
                blockButton.textContent = 'BLOCK';
                cells[6].appendChild(blockButton);
                frag.appendChild(tr);
            });
            tbody.replaceChildren();
            tbody.appendChild(frag);
        }

        function openLiveModal() {
            const modal = document.getElementById('live-modal');
            if (modal) modal.classList.add('open');
            showLiveTab(liveTab);
        }

        function toggleEventOrder() {
            newestFirst = !newestFirst;
            const btn = document.getElementById('event-order-btn');
            if (btn) btn.textContent = newestFirst ? "NEWEST FIRST" : "OLDEST FIRST";
            renderEvents(eventBuffer);
            const modal = document.getElementById('live-modal');
            if (modal && modal.classList.contains('open') && liveTab === 'events') {
                renderEvents(eventBuffer, '#events-modal tbody');
            }
        }

        function toggleEventStream() {
            streamPaused = !streamPaused;
            const btn = document.getElementById('event-stream-btn');
            if (btn) btn.textContent = streamPaused ? "RESUME STREAM" : "PAUSE STREAM";
        }

        function toggleAllowEvents() {
            allowXDPEvents = !allowXDPEvents;
            const btn = document.getElementById('event-allow-btn');
            if (btn) btn.textContent = allowXDPEvents ? "ALLOW EVENTS: ON" : "ALLOW EVENTS: OFF";
        }

        function openTrustModal() {
            const modal = document.getElementById('trust-modal');
            if (modal) modal.classList.add('open');
            refreshTrust();
        }

        function closeLiveModal(ev) {
            const modal = document.getElementById('live-modal');
            if (!modal) return;
            if (ev && ev.target && ev.target.id === 'live-modal') {
                modal.classList.remove('open');
                return;
            }
        }

        function closeTrustModal(ev) {
            const modal = document.getElementById('trust-modal');
            if (!modal) return;
            if (ev && ev.target && ev.target.id === 'trust-modal') {
                modal.classList.remove('open');
                return;
            }
        }

        function showLiveTab(tab) {
            liveTab = tab;
            const tabEvents = document.getElementById('tab-events');
            const tabBans = document.getElementById('tab-bans');
            const viewEvents = document.getElementById('live-tab-events');
            const viewBans = document.getElementById('live-tab-bans');
            if (tabEvents) tabEvents.classList.toggle('active', tab === 'events');
            if (tabBans) tabBans.classList.toggle('active', tab === 'bans');
            if (viewEvents) viewEvents.style.display = tab === 'events' ? 'block' : 'none';
            if (viewBans) viewBans.style.display = tab === 'bans' ? 'block' : 'none';
            if (tab === 'events') {
                renderEvents(eventBuffer, '#events-modal tbody');
            } else {
                renderBans(latestBans, latestBansMeta, '#bans-modal tbody');
            }
        }

        let latestBans = {};
        let latestBansMeta = {};

        function formatBanExpiry(exp) {
            if (!exp) return "-";
            if (typeof exp === "string") {
                if (exp.startsWith("9999-")) return "PERMANENT";
                return exp;
            }
            return exp;
        }

        function renderBans(bans, meta, targetSelector) {
            const list = bans || {};
            const metaList = meta || {};
            latestBans = list;
            latestBansMeta = metaList;
            const table = document.querySelector(targetSelector || '#ban-list');
            if (!table) return;
            table.replaceChildren();
            Object.keys(list).forEach(ip => {
                const clean = ip.replace(/\\/g, '').replace(/^"+|"+$/g, '');
                if (!clean) return;
                const metaRow = metaList[clean] || metaList[ip] || {};
                let fp = metaRow.ja4 || '-';
                if (metaRow.ja4_label) fp += ' • ' + metaRow.ja4_label;
                if (metaRow.ja3) fp += ' | JA3 ' + metaRow.ja3;
                if (metaRow.ja3_label) fp += ' • ' + metaRow.ja3_label;
                const tr = document.createElement('tr');
                [clean, formatBanExpiry(list[ip] || list[clean] || '-'), fp].forEach(value => {
                    const td = document.createElement('td');
                    td.textContent = String(value);
                    tr.appendChild(td);
                });
                const actions = document.createElement('td');
                [['allow-btn', 'ALLOW', 'btn-accent'], ['whitelist-btn', 'WHITELIST', 'btn-green'], ['release-btn', 'RELEASE', 'btn-muted'], ['extend-btn', 'EXTEND', 'btn-accent'], ['perm-ban-btn', 'PERMANENT', 'btn-red']].forEach(([kind, label, color]) => {
                    const button = document.createElement('button');
                    button.className = 'btn ' + color + ' ' + kind;
                    button.dataset.ip = clean;
                    button.textContent = label;
                    actions.appendChild(button);
                });
                tr.appendChild(actions);
                table.appendChild(tr);
            });
            if (!table.children.length) {
                const tr = document.createElement('tr');
                const td = document.createElement('td');
                td.colSpan = 4;
                td.textContent = 'No active bans';
                tr.appendChild(td);
                table.appendChild(tr);
            }
        }

        function renderTrust(rows, targetSelector) {
            const table = document.querySelector(targetSelector || '#trust-modal-table tbody');
            if (!table) return;
            table.replaceChildren();
            if (!rows || !rows.length) {
                const cell = document.createElement('td');
                cell.colSpan = 8;
                cell.textContent = 'No trust data';
                const tr = document.createElement('tr');
                tr.appendChild(cell);
                table.appendChild(tr);
                return;
            }
            rows.forEach(r => {
                const tr = document.createElement('tr');
                [r.peer || '-', r.score !== undefined ? Number(r.score).toFixed(1) : '-', r.level || '-', r.total || 0, r.valid || 0, r.invalid || 0, r.last_report || '-'].forEach(value => {
                    const td = document.createElement('td');
                    td.textContent = String(value);
                    tr.appendChild(td);
                });
                const actions = document.createElement('td');
                [0, 1, 2, 3, -1].forEach(level => {
                    const button = document.createElement('button');
                    button.className = level < 0 ? 'btn btn-red' : 'btn btn-accent';
                    button.textContent = level < 0 ? 'PENALIZE' : 'L' + level;
                    button.addEventListener('click', () => level < 0 ? penalizeTrust(r.peer || '') : setTrustLevel(r.peer || '', level));
                    actions.appendChild(button);
                });
                tr.appendChild(actions);
                table.appendChild(tr);
            });
        }

        function renderTraps(traps) {
            const box = document.getElementById('trap-list');
            if (!box) return;
            box.replaceChildren();
            const serviceNames = {'21':'FTP','22':'SSH','23':'TELNET','25':'SMTP','53':'DNS','80':'HTTP','110':'POP3','143':'IMAP','443':'HTTPS','445':'SMB','3306':'MYSQL','3389':'RDP','5432':'POSTGRES','6379':'REDIS','8080':'HTTP-ALT','9200':'ELASTIC'};
            const keys = Object.keys(traps || {}).sort((a, b) => Number(a) - Number(b));
            if (!keys.length) { box.textContent = 'No traps configured'; return; }
            keys.forEach(port => {
                const trap = traps[port] || {};
                const row = document.createElement('div');
                row.className = 'trap-item';
                const left = document.createElement('div');
                left.className = 'trap-left';
                const glyph = document.createElement('span');
                glyph.className = trap.enabled ? 'trap-hex active' : 'trap-hex';
                glyph.textContent = trap.enabled ? '⬢' : '⬡';
                left.appendChild(glyph);
                const label = document.createElement('b');
                label.textContent = ':' + port;
                left.appendChild(label);
                const proto = document.createElement('span');
                proto.className = 'trap-proto';
                proto.textContent = '(' + (serviceNames[port] || 'CUSTOM') + ' / ' + (trap.proto || 'tcp') + ')';
                left.appendChild(proto);
                row.appendChild(left);
                const actions = document.createElement('div');
                actions.className = 'trap-actions';
                const status = document.createElement('div');
                status.className = 'trap-status';
                status.textContent = trap.status ? String(trap.status).toUpperCase() : (trap.enabled ? 'ENABLED' : 'DISABLED');
                actions.appendChild(status);
                [['toggleTrap', trap.enabled ? 'DISABLE' : 'ENABLE', trap.enabled ? 'btn-red' : 'btn-green'], ['toggleWatchdog', 'WATCHDOG', trap.watchdog ? 'btn-accent' : ''], ['editTrapBanner', 'EDIT', 'btn-accent']].forEach(([action, text, color]) => {
                    const button = document.createElement('button');
                    button.className = 'btn ' + color;
                    button.textContent = text;
                    if (action === 'toggleWatchdog') button.disabled = !!trap.enabled;
                    button.addEventListener('click', () => {
                        if (action === 'toggleTrap') toggleTrap(port, !trap.enabled);
                        else if (action === 'toggleWatchdog') toggleWatchdog(port, !trap.watchdog);
                        else editTrapBanner(port);
                    });
                    actions.appendChild(button);
                });
                row.appendChild(actions);
                box.appendChild(row);
            });
        }

        function renderIfaces(ifaces) {
            const box = document.getElementById('iface-list');
            if (!box) return;
            box.replaceChildren();
            const grid = document.createElement('div');
            grid.className = 'iface-grid';
            (ifaces || []).forEach(iface => {
                const attached = iface.mode && iface.mode !== 'off' && iface.mode !== 'unknown';
                const card = document.createElement('div');
                card.className = 'iface-card';
                const meta = document.createElement('div');
                meta.className = 'iface-meta';
                const name = document.createElement('div');
                name.className = 'iface-name';
                name.appendChild(document.createTextNode(String(iface.name || '') + ' '));
                const button = document.createElement('button');
                button.className = 'btn ' + (attached ? 'btn-red' : 'btn-green');
                button.textContent = attached ? 'DETACH' : 'ATTACH';
                button.addEventListener('click', () => toggleIface(iface.name, !attached));
                name.appendChild(button);
                meta.appendChild(name);
                [iface.ips || '-', 'state: ' + (iface.is_up ? 'up' : 'down'), 'mode: ' + (iface.mode || 'off')].forEach(value => {
                    const state = document.createElement('div');
                    state.className = 'iface-state';
                    state.textContent = String(value);
                    meta.appendChild(state);
                });
                card.appendChild(meta);
                grid.appendChild(card);
            });
            box.appendChild(grid);
        }

        async function refreshTrust() {
            const t = await api('/trust');
            renderTrust(t || [], "#trust-modal-table tbody");
        }

        function wireBlockButtons() {
            const eventsTable = document.getElementById('events-modal');
            if (!eventsTable) return;
            eventsTable.onclick = (ev) => {
                const btn = ev.target && ev.target.closest ? ev.target.closest('.block-btn') : null;
                if (!btn) return;
                const ip = btn.getAttribute('data-ip');
                blockIP(ip);
            };
        }

        function wireAllowButtons() {
            const banTables = [
                document.getElementById('bans-modal'),
                document.getElementById('ban-list')
            ].filter(Boolean);
            if (banTables.length === 0) return;
            const handler = (ev) => {
                const allowBtn = ev.target && ev.target.closest ? ev.target.closest('.allow-btn') : null;
                const whitelistBtn = ev.target && ev.target.closest ? ev.target.closest('.whitelist-btn') : null;
                const releaseBtn = ev.target && ev.target.closest ? ev.target.closest('.release-btn') : null;
                const extendBtn = ev.target && ev.target.closest ? ev.target.closest('.extend-btn') : null;
                const permBtn = ev.target && ev.target.closest ? ev.target.closest('.perm-ban-btn') : null;
                if (allowBtn) {
                    const ip = allowBtn.getAttribute('data-ip');
                    allowIP(ip);
                    return;
                }
                if (whitelistBtn) {
                    const ip = whitelistBtn.getAttribute('data-ip');
                    whitelistIP(ip);
                    return;
                }
                if (releaseBtn) {
                    const ip = releaseBtn.getAttribute('data-ip');
                    releaseBan(ip);
                    return;
                }
                if (extendBtn) {
                    const ip = extendBtn.getAttribute('data-ip');
                    extendBan(ip);
                    return;
                }
                if (permBtn) {
                    const ip = permBtn.getAttribute('data-ip');
                    permanentBan(ip);
                    return;
                }
            };
            banTables.forEach(tbl => {
                tbl.onclick = handler;
            });
        }

        async function refreshBans() {
            const bans = await api('/bans');
            const meta = await api('/bans/meta');
            if (bans) {
                renderBans(bans, meta || {});
            }
        }

        async function refreshIfaces() {
            const ifaces = await api('/ifaces');
            if (ifaces) {
                renderIfaces(ifaces);
            }
        }

        async function refreshPeers() {
            const peers = await api('/peers');
            if (peers) {
                renderPeers(peers);
            }
        }

        let blockStatusTimer = null;
        function setBlockStatus(msg) {
            const el = document.getElementById('block-status');
            if (el) {
                el.textContent = msg || '';
                if (blockStatusTimer) {
                    clearTimeout(blockStatusTimer);
                }
                if (msg) {
                    blockStatusTimer = setTimeout(() => {
                        el.textContent = '';
                    }, 6000);
                }
            }
        }

        async function blockIP(ip) {
            if (!ip) return;
            ip = ip.replace(/^\"+|\"+$/g, '');
            setBlockStatus("Block request sent...");
            if (!TOKEN) {
                setBlockStatus("Missing admin token.");
                return;
            }
            const reason = prompt("Block reason (optional)") || "";
            try {
                const res = await fetch('/api/ban', {
                    method: 'POST',
                    headers: {
                        'X-Honey-Token': TOKEN,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ip: ip, reason: reason})
                });
                if (!res.ok) {
                    const text = await res.text();
                    setBlockStatus("Block failed: " + text);
                    return;
                }
                setBlockStatus("Block applied.");
                await updateHealth();
                await refreshBans();
            } catch (e) {
                setBlockStatus("Block failed: " + e);
            }
        }

        async function penalizeTrust(peer) {
            if (!peer) return;
            if (!confirm("Penalize peer " + peer + "?")) return;
            await api('/trust/penalize', {
                method: 'POST',
                body: JSON.stringify({peer: peer})
            });
            refreshTrust();
        }

        async function setTrustLevel(peer, level) {
            if (!peer && peer !== "") return;
            await api('/trust/set', {
                method: 'POST',
                body: JSON.stringify({peer: peer, level: level})
            });
            refreshTrust();
        }

        async function allowIP(ip) {
            if (!ip) return;
            ip = ip.replace(/^\"+|\"+$/g, '');
            setBlockStatus("Allow request sent...");
            const ttl = prompt("Allow TTL seconds (blank = default)");
            if (ttl === null) {
                setBlockStatus("Allow canceled.");
                return;
            }
            const ttlSeconds = ttl ? Number(ttl) : 0;
            const reasonInput = prompt("Reason (optional)");
            if (reasonInput === null) {
                setBlockStatus("Allow canceled.");
                return;
            }
            const reason = reasonInput || "";
            try {
                const res = await fetch('/api/allow', {
                    method: 'POST',
                    headers: {
                        'X-Honey-Token': TOKEN,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ip: ip, reason: reason, ttl_seconds: ttlSeconds})
                });
                if (!res.ok) {
                    const text = await res.text();
                    setBlockStatus("Allow failed: " + text);
                    return;
                }
                setBlockStatus("Allow applied.");
                await refreshBans();
            } catch (e) {
                setBlockStatus("Allow failed: " + e);
            }
        }

        async function whitelistIP(ip) {
            if (!ip) return;
            ip = ip.replace(/^\"+|\"+$/g, '');
            setBlockStatus("Whitelist request sent...");
            try {
                const res = await fetch('/api/trusted', {
                    method: 'POST',
                    headers: {
                        'X-Honey-Token': TOKEN,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ip: ip, action: 'add'})
                });
                if (!res.ok) {
                    const text = await res.text();
                    setBlockStatus("Whitelist failed: " + text);
                    return;
                }
                setBlockStatus("Whitelisted.");
                await refreshBans();
            } catch (e) {
                setBlockStatus("Whitelist failed: " + e);
            }
        }

        async function releaseBan(ip) {
            if (!ip) return;
            ip = ip.replace(/^\"+|\"+$/g, '');
            if (!confirm("Release ban for " + ip + "?")) {
                return;
            }
            setBlockStatus("Release request sent...");
            try {
                const res = await fetch('/api/ban/release', {
                    method: 'POST',
                    headers: {
                        'X-Honey-Token': TOKEN,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ip: ip})
                });
                if (!res.ok) {
                    const text = await res.text();
                    setBlockStatus("Release failed: " + text);
                    return;
                }
                setBlockStatus("Released.");
                await refreshBans();
            } catch (e) {
                setBlockStatus("Release failed: " + e);
            }
        }

        function getBanExtendSeconds() {
            const input = document.querySelector('.ban-duration-input');
            if (!input) return 0;
            const hours = Number(input.value);
            if (!hours || hours <= 0) return 0;
            return Math.floor(hours * 3600);
        }

        async function extendBan(ip) {
            if (!ip) return;
            ip = ip.replace(/^\"+|\"+$/g, '');
            const ttlSeconds = getBanExtendSeconds();
            setBlockStatus("Extend request sent...");
            try {
                const res = await fetch('/api/ban/extend', {
                    method: 'POST',
                    headers: {
                        'X-Honey-Token': TOKEN,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ip: ip, ttl_seconds: ttlSeconds})
                });
                if (!res.ok) {
                    const text = await res.text();
                    setBlockStatus("Extend failed: " + text);
                    return;
                }
                setBlockStatus("Ban extended.");
                await refreshBans();
            } catch (e) {
                setBlockStatus("Extend failed: " + e);
            }
        }

        async function permanentBan(ip) {
            if (!ip) return;
            ip = ip.replace(/^\"+|\"+$/g, '');
            if (!confirm("Apply PERMANENT ban for " + ip + "?")) {
                return;
            }
            setBlockStatus("Permanent ban request sent...");
            try {
                const res = await fetch('/api/ban/extend', {
                    method: 'POST',
                    headers: {
                        'X-Honey-Token': TOKEN,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ip: ip, permanent: true})
                });
                if (!res.ok) {
                    const text = await res.text();
                    setBlockStatus("Permanent ban failed: " + text);
                    return;
                }
                setBlockStatus("Permanent ban applied.");
                await refreshBans();
            } catch (e) {
                setBlockStatus("Permanent ban failed: " + e);
            }
        }

        async function promptAllow() {
            const ip = prompt("Allow IP (force whitelist)");
            if (!ip) return;
            await allowIP(ip);
        }

        function renderPeers(peers) {
            const box = document.getElementById('peer-list');
            if (!box) return;
            const status = document.getElementById('mesh-status') || document.createElement('div');
            status.id = 'mesh-status';
            const sharing = document.getElementById('sharing-status') || document.createElement('div');
            sharing.id = 'sharing-status';
            box.replaceChildren(status, sharing);
            if (!lastHealth.trusted_mesh_network_enabled) {
                status.textContent = 'Trusted HoneyMesh network participation is inactive.';
                sharing.textContent = 'License: ' + (lastHealth.license_label || 'Community') + ' • NetTools.cloud Sharing: ' + (lastHealth.trusted_network_sharing_enabled ? 'Enabled' : 'Off') + ' • Trusted Mesh Networks: Off • Enable trusted mesh participation to join peer networks.';
                const message = document.createElement('div');
                message.textContent = 'Trusted mesh participation is off.';
                box.appendChild(message);
                return;
            }
            if (!peers || !peers.length) {
                const message = document.createElement('div');
                message.textContent = 'No peers';
                box.appendChild(message);
                return;
            }
            peers.forEach(peer => {
                let age = typeof peer.age_s === 'number' && peer.age_s >= 0 ? peer.age_s : null;
                if (age === null && peer.last_seen) {
                    const ts = Date.parse(peer.last_seen);
                    if (!Number.isNaN(ts)) age = Math.max(0, Math.floor((Date.now() - ts) / 1000));
                }
                const state = age !== null ? (age < 60 ? 'online' : (age < 80 ? 'warning' : 'offline')) : (peer.state || (peer.healthy ? 'online' : 'offline'));
                const card = document.createElement('div');
                card.className = state === 'online' ? 'iface-card' : (state === 'warning' ? 'iface-card warn' : 'iface-card stale');
                const meta = document.createElement('div');
                meta.className = 'iface-meta';
                [peer.address || '', 'last seen: ' + (peer.last_seen || '-'), 'age: ' + (age !== null && age < 9999 ? age + 's' : '-'), state + ' • bans: ' + (peer.bans || 0)].forEach((value, index) => {
                    const div = document.createElement('div');
                    div.className = index === 0 ? 'iface-name' : 'iface-state';
                    div.textContent = String(value);
                    meta.appendChild(div);
                });
                card.appendChild(meta);
                const revoke = document.createElement('button');
                revoke.className = 'btn btn-red';
                revoke.textContent = 'REVOKE';
                revoke.addEventListener('click', () => revokePeer(peer.address));
                card.appendChild(revoke);
                box.appendChild(card);
            });
        }

        async function toggleTrap(port, enabled) {
            await api('/trap', {
                method: 'POST',
                body: JSON.stringify({port: port, enabled: enabled})
            });
        }

        async function toggleWatchdog(port, watchdog) {
            await api('/trap', {
                method: 'POST',
                body: JSON.stringify({port: port, watchdog: watchdog})
            });
        }

        async function editTrapBanner(port) {
            const traps = await api('/traps');
            if (!traps || !traps[port]) return;
            const current = traps[port].banner || "";
            const next = prompt("Edit banner for :" + port, current);
            if (next === null) return;
            await api('/trap', {
                method: 'POST',
                body: JSON.stringify({port: port, banner: next})
            });
        }

        function downloadCSV() {
            fetch('/api/events.csv', { headers: { 'X-Honey-Token': TOKEN } })
                .then(res => res.blob())
                .then(blob => {
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'honeymesh_events.csv';
                    a.click();
                    URL.revokeObjectURL(url);
                })
                .catch(err => console.error(err));
        }

        async function toggleIface(name, enable) {
            const btn = event && event.target ? event.target : null;
            if (btn) {
                btn.disabled = true;
                btn.dataset.originalText = btn.textContent;
                btn.textContent = "WORKING...";
            }
            await api('/iface', {
                method: 'POST',
                body: JSON.stringify({name: name, enable: enable})
            });
            await refreshIfaces();
            if (btn) {
                btn.disabled = false;
                if (btn.dataset.originalText) {
                    btn.textContent = btn.dataset.originalText;
                    delete btn.dataset.originalText;
                }
            }
        }

        async function createMeshInvite() {
            const ttlEl = document.getElementById('mesh-invite-ttl');
            const output = document.getElementById('mesh-invite-output');
            const ttlMinutes = Number(ttlEl && ttlEl.value ? ttlEl.value : 30);
            if (output) output.textContent = "Generating temporary invite...";
            const res = await fetch('/api/mesh/invite', {
                method: 'POST',
                headers: {
                    'X-Honey-Token': TOKEN,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ttl_minutes: ttlMinutes})
            });
            if (!res.ok) {
                const text = await res.text();
                if (output) output.textContent = "Invite generation failed: " + text;
                return;
            }
            const payload = await res.json();
            if (output) renderInviteOutput(output, payload);
            const peerField = document.getElementById('mesh-invite-peer');
            const tokenField = document.getElementById('mesh-invite-token');
            if (peerField && payload.peer) peerField.value = payload.peer;
            if (tokenField && payload.token) tokenField.value = payload.token;
        }

        async function joinWithInvite() {
            const peerField = document.getElementById('mesh-invite-peer');
            const tokenField = document.getElementById('mesh-invite-token');
            const output = document.getElementById('mesh-join-output');
            let target = peerField && peerField.value ? peerField.value.trim() : "";
            const token = tokenField && tokenField.value ? tokenField.value.trim() : "";
            if (!target || !token) {
                if (output) output.textContent = "Peer address and temporary token are both required.";
                return;
            }
            if (target && !target.includes(":")) {
                target = target + ":9000";
            }
            if (output) output.textContent = "Sending join request...";
            const res = await fetch('/api/mesh/join', {
                method: 'POST',
                headers: {
                    'X-Honey-Token': TOKEN,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({peer: target, token: token})
            });
            const status = document.getElementById('mesh-status');
            if (!res.ok) {
                const text = await res.text();
                if (output) output.textContent = "Join failed: " + text;
                if (status) status.textContent = "Join failed: " + text;
                return;
            }
            if (output) output.textContent = "Join request sent to " + target;
            if (status) status.textContent = "Join request sent to " + target;
            refreshPeers();
        }

        async function revokePeer(peer) {
            if (!confirm("Revoke peer " + peer + "?")) return;
            await api('/mesh/revoke', {
                method: 'POST',
                body: JSON.stringify({peer: peer})
            });
        }

        let lastHealth = { enforce_allowed: true };

        async function updateHealth() {
            const health = await api('/health');
            if (health) {
                lastHealth = health;
                document.getElementById('kpi-surface').innerText = (health.surface_local || '0') + ' / ' + (health.surface_mesh || '0');
                document.getElementById('kpi-peers').innerText = (health.peer_online || '0') + ' / ' + (health.peer_iface_online || '0');
                document.getElementById('kpi-blocks').innerText = (health.blocks_local || '0') + ' / ' + (health.blocks_mesh || '0');
                document.getElementById('kpi-threats').innerText = (health.threat_total || '0') + ' / ' + (health.threat_mesh || '0');
                setModeUI(health.mode, health.enforce_allowed);
                renderSharingStatus(health.license_label, !!health.premium_enabled, !!health.trusted_network_sharing_enabled, !!health.trusted_mesh_network_enabled);
	                const meshStatus = document.getElementById('mesh-status');
	                const nettoolsStatus = document.getElementById('nettools-status');
	                const nettoolsLastHeartbeat = document.getElementById('nettools-last-heartbeat');
	                const nettoolsLastPush = document.getElementById('nettools-last-push');
	                const nettoolsLastPull = document.getElementById('nettools-last-pull');
	                if (meshStatus) {
	                    meshStatus.textContent = health.trusted_network_participation
	                        ? "Trusted HoneyMesh network participation is active."
	                        : "Trusted HoneyMesh network participation is inactive.";
	                }
	                if (nettoolsStatus) {
	                    const prefix = health.honeymesh_exchange_connected
	                        ? "Connected to HoneyMesh Exchange."
	                        : "Not connected to HoneyMesh Exchange.";
	                    const detail = health.nettools_exchange_status || (
	                        health.nettools_exchange_enabled
	                            ? "HoneyMesh Exchange integration is enabled."
	                            : "HoneyMesh Exchange integration is disabled."
	                    );
	                    nettoolsStatus.textContent = prefix + " " + detail;
	                }
	                if (nettoolsLastHeartbeat) nettoolsLastHeartbeat.textContent = "Last heartbeat: " + (health.nettools_exchange_last_heartbeat || "-");
	                if (nettoolsLastPush) nettoolsLastPush.textContent = "Last push: " + (health.nettools_exchange_last_push || "-");
	                if (nettoolsLastPull) nettoolsLastPull.textContent = "Last pull: " + (health.nettools_exchange_last_pull || "-");
                    lastExchangeKnownClusters = Array.isArray(health.honeymesh_exchange_known_clusters) ? health.honeymesh_exchange_known_clusters : [];
                    renderExchangeConnection(!!health.honeymesh_exchange_connected, health.honeymesh_exchange_cluster_id);
                    renderExchangeKnownClusters(lastExchangeKnownClusters);
                    renderTrustedMeshNetworks(lastExchangeKnownClusters);
	                const joinBtn = document.getElementById('join-peer-btn');
                const trustBtn = document.getElementById('trust-levels-btn');
                const trustedBtn = document.getElementById('trusted-peers-btn');
                const sharingControlsEnabled = true;
                if (joinBtn) joinBtn.disabled = !health.trusted_mesh_network_enabled;
                if (trustBtn) trustBtn.disabled = !sharingControlsEnabled;
                if (trustedBtn) trustedBtn.disabled = !sharingControlsEnabled;
            }
        }

        const eventBuffer = [];
        const eventKeySet = new Set();
        let lastTraps = {};
        let lastIfaces = [];
        let lastPeers = [];
        let renderTimer = null;
        const pending = {
            events: false,
            bans: false,
            traps: false,
            ifaces: false,
            peers: false,
            mode: false
        };

        function scheduleRender() {
            if (renderTimer) return;
            renderTimer = setTimeout(() => {
                renderTimer = null;
                if (pending.events) {
                    renderEvents(eventBuffer);
                    const modal = document.getElementById('live-modal');
                    if (modal && modal.classList.contains('open') && liveTab === 'events') {
                        renderEvents(eventBuffer, '#events-modal tbody');
                    }
                    pending.events = false;
                }
                if (pending.bans) {
                    renderBans(latestBans || {}, latestBansMeta || {});
                    const modal = document.getElementById('live-modal');
                    if (modal && modal.classList.contains('open') && liveTab === 'bans') {
                        renderBans(latestBans || {}, latestBansMeta || {}, '#bans-modal tbody');
                    }
                    pending.bans = false;
                }
                if (pending.traps) {
                    renderTraps(lastTraps || {});
                    pending.traps = false;
                }
                if (pending.ifaces) {
                    renderIfaces(lastIfaces || []);
                    pending.ifaces = false;
                }
                if (pending.peers) {
                    renderPeers(lastPeers || []);
                    pending.peers = false;
                }
            }, 500);
        }

        function eventKey(e) {
            if (!e) return "";
            return [e.timestamp, e.attacker, e.target, e.type].join("|");
        }

        function pushEvent(e) {
            const key = eventKey(e);
            if (!key || eventKeySet.has(key)) return false;
            eventKeySet.add(key);
            eventBuffer.push(e);
            if (eventBuffer.length > 200) {
                const dropped = eventBuffer.shift();
                const droppedKey = eventKey(dropped);
                if (droppedKey) eventKeySet.delete(droppedKey);
            }
            return true;
        }

        async function connectWS() {
            try {
                const session = await fetch('/api/session', {method: 'POST', headers: {'X-Honey-Token': TOKEN}});
                if (!session.ok) throw new Error('session rejected');
            } catch (e) {
                setTimeout(connectWS, 5000);
                return;
            }
            const wsUrl = "wss://" + location.host + "/ws";
            const ws = new WebSocket(wsUrl);
            ws.onmessage = (ev) => {
                try {
                    const msg = JSON.parse(ev.data);
                    if (msg.type === "event") {
                        if (streamPaused) return;
                        if (msg.data && msg.data.type === "XDP" && !allowXDPEvents) return;
                        const added = pushEvent(msg.data);
                        if (added) {
                            pending.events = true;
                            scheduleRender();
                        }
                    } else if (msg.type === "events") {
                        if (streamPaused) return;
                        let added = false;
                        msg.data.forEach(e => {
                            if (e && e.type === "XDP" && !allowXDPEvents) return;
                            if (pushEvent(e)) added = true;
                        });
                        if (added) {
                            pending.events = true;
                            scheduleRender();
                        }
                    } else if (msg.type === "bans") {
                        latestBans = msg.data || {};
                        pending.bans = true;
                        scheduleRender();
                    } else if (msg.type === "traps") {
                        lastTraps = msg.data || {};
                        pending.traps = true;
                        scheduleRender();
                    } else if (msg.type === "ifaces") {
                        lastIfaces = msg.data || [];
                        pending.ifaces = true;
                        scheduleRender();
                    } else if (msg.type === "peers") {
                        lastPeers = msg.data || [];
                        pending.peers = true;
                        scheduleRender();
                    } else if (msg.type === "mode") {
                        setModeUI(msg.data && msg.data.mode, lastHealth.enforce_allowed);
                    }
                } catch (e) {
                    console.error("WS parse error", e);
                }
            };
            ws.onclose = () => setTimeout(connectWS, 1000);
        }

        function setupLicenseUpload() {
            const pill = document.getElementById('license-pill');
            const input = document.getElementById('license-file');
            pill.title = "Click to upload license.json";
            pill.addEventListener('click', () => input.click());
            input.addEventListener('change', async () => {
                const file = input.files && input.files[0];
                if (!file) return;
                const text = await file.text();
                const res = await api('/license', {
                    method: 'POST',
                    headers: {
                        'X-Honey-Token': TOKEN,
                        'Content-Type': 'application/json'
                    },
                    body: text
                });
                if (res && res.tier) {
                    if (res.expires_at) {
                        pill.textContent = "License: " + res.tier + " • Expires " + res.expires_at;
                    } else {
                        pill.textContent = "License: " + res.tier;
                    }
                    const cid = document.getElementById('cluster-id');
                    if (cid) {
                        cid.textContent = (res.cluster_id && res.tier === "Pro") ? "• Cluster: " + res.cluster_id : "";
                    }
                    updateHealth();
                } else if (res && res.ok) {
                    pill.textContent = "LICENSE UPDATED";
                }
                input.value = "";
            });
        }

        async function bootstrap() {
            updateHealth();
            const lic = await api('/license-info');
            if (lic && lic.tier) {
                const pill = document.getElementById('license-pill');
                if (lic.expires_at) {
                    pill.textContent = "License: " + lic.tier + " • Expires " + lic.expires_at;
                } else {
                    pill.textContent = "License: " + lic.tier;
                }
                const cid = document.getElementById('cluster-id');
                if (cid) {
                    cid.textContent = (lic.cluster_id && lic.tier === "Pro") ? "• Cluster: " + lic.cluster_id : "";
                }
            } else {
                const pill = document.getElementById('license-pill');
                pill.textContent = "License: Community";
            }
            refreshTrust();
            wireBlockButtons();
            wireAllowButtons();
            const traps = await api('/traps');
            if (traps) renderTraps(traps);
            refreshBans();
            const ifaces = await api('/ifaces');
            if (ifaces) renderIfaces(ifaces);
            const peers = await api('/peers');
            if (peers) renderPeers(peers);
            const events = await api('/events');
            if (events) {
                let added = false;
                events.forEach(e => {
                    if (pushEvent(e)) added = true;
                });
                if (added) renderEvents(eventBuffer);
            }
        }

        // Initial load + refresh
        bootstrap();
        setInterval(updateHealth, 5000);
        setInterval(refreshPeers, 5000);
        setInterval(refreshIfaces, 5000);
        setInterval(refreshTrust, 15000);
        connectWS();
        setupLicenseUpload();
        loadScanSettings();
    </script>
</body>
</html>
`
