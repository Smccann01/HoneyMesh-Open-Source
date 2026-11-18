package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"log"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ─────────────────────────────────────────────
// ALLOWLIST / WHITELIST HANDLING
// ─────────────────────────────────────────────

func initAllowlist(cidrs []string) {
	// Clear previous list for safety on reload
	allowCIDRs = nil

	for _, c := range cidrs {
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			log.Printf("[ALLOWLIST] Invalid CIDR skipped: %s", c)
			continue
		}
		allowCIDRs = append(allowCIDRs, network)
	}
	log.Printf("[ALLOWLIST] Loaded %d base CIDRs", len(allowCIDRs))
}

func baseAllowlistCIDRs() []string {
	return []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"::1/128", "fc00::/7", "fe80::/10",
	}
}

func isWhitelisted(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Built-in safe CIDRs
	for _, cidr := range allowCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	// Config whitelist and trusted peers (pre-parsed)
	whitelistMu.RLock()
	for _, netw := range whitelistCIDRs {
		if netw.Contains(ip) {
			whitelistMu.RUnlock()
			return true
		}
	}
	for _, netw := range trustedCIDRs {
		if netw.Contains(ip) {
			whitelistMu.RUnlock()
			return true
		}
	}
	whitelistMu.RUnlock()

	remoteAllowMu.Lock()
	exp, ok := remoteAllowCache[ipStr]
	remoteAllowMu.Unlock()
	if ok && time.Now().Before(exp) {
		return true
	}

	return false
}

func banSourceForIP(ip string) string {
	ip = normalizeIPKey(ip)
	if ip == "" {
		return ""
	}
	now := time.Now()

	remoteBanMu.Lock()
	if exp, ok := remoteBanCache[ip]; ok && now.Before(exp) && remoteBanSources != nil {
		if peers, ok := remoteBanSources[ip]; ok && len(peers) > 0 {
			addrs := make([]string, 0, len(peers))
			for p := range peers {
				addr := normalizePeerAddrUI(p)
				if addr != "" {
					addrs = append(addrs, addr)
				}
			}
			sort.Strings(addrs)
			if len(addrs) > 0 {
				remoteBanMu.Unlock()
				return "mesh:" + strings.Join(addrs, "|")
			}
		}
	}
	remoteBanMu.Unlock()

	banMutex.Lock()
	exp, ok := banExpirations[ip]
	banMutex.Unlock()
	if ok && now.Before(exp) {
		return "local"
	}
	return ""
}

func addTrustedPeerIP(ipStr string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}
	cidr := ""
	if ip.To4() != nil {
		cidr = ip.String() + "/32"
	} else {
		cidr = ip.String() + "/128"
	}
	for _, existing := range config.Security.TrustedPeers {
		if existing == cidr {
			return
		}
	}
	config.Security.TrustedPeers = append(config.Security.TrustedPeers, cidr)
	refreshTrustedCIDRs(config.Security.TrustedPeers)
}

func removeTrustedPeerIP(ipStr string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}
	cidr := ""
	if ip.To4() != nil {
		cidr = ip.String() + "/32"
	} else {
		cidr = ip.String() + "/128"
	}
	if cidr == "" {
		return
	}
	out := config.Security.TrustedPeers[:0]
	for _, existing := range config.Security.TrustedPeers {
		if existing == cidr {
			continue
		}
		out = append(out, existing)
	}
	config.Security.TrustedPeers = out
	refreshTrustedCIDRs(config.Security.TrustedPeers)
}

func refreshWhitelistCIDRs(list []string) {
	out := make([]*net.IPNet, 0, len(list))
	for _, cidrStr := range list {
		_, netw, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		out = append(out, netw)
	}
	whitelistMu.Lock()
	whitelistCIDRs = out
	whitelistMu.Unlock()
}

func refreshTrustedCIDRs(list []string) {
	out := make([]*net.IPNet, 0, len(list))
	for _, cidrStr := range list {
		_, netw, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		out = append(out, netw)
	}
	whitelistMu.Lock()
	trustedCIDRs = out
	whitelistMu.Unlock()
}

func sanitizePayload(b []byte, max int) string {
	if max <= 0 {
		return ""
	}
	if len(b) > max {
		b = b[:max]
	}
	out := make([]byte, 0, len(b))
	for _, ch := range b {
		if ch >= 32 && ch <= 126 {
			out = append(out, ch)
			continue
		}
		if ch == '\n' || ch == '\r' || ch == '\t' {
			out = append(out, ' ')
			continue
		}
		out = append(out, '.')
	}
	return strings.TrimSpace(string(out))
}

func sanitizeIPStr(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\\", "")
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"")
	s = strings.TrimSpace(s)
	return s
}

func normalizeIPKey(ipStr string) string {
	ipStr = sanitizeIPStr(ipStr)
	if ipStr == "" {
		return ""
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	return ip.String()
}

// ─────────────────────────────────────────────
// NETWORK INTERFACE + IP DISCOVERY
// ─────────────────────────────────────────────

func getAvailableIPs() []string {
	var results []string

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[NET] Failed to list interfaces: %v", err)
		return results
	}

	for _, iface := range ifaces {
		// Skip down or loopback
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			// Skip loopback / link-local
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			results = append(results, ip.String())
		}
	}

	return results
}

func advertiseAddr() string {
	if config.BindIP != "" && config.BindIP != "0.0.0.0" && config.BindIP != "::" {
		return config.BindIP
	}
	ips := getAvailableIPs()
	if len(ips) > 0 {
		return ips[0]
	}
	return config.BindIP
}

type surfaceStats struct {
	Traps   int
	Ifaces  int
	Surface int
}

func localSurfaceStats() surfaceStats {
	trapsEnabled := 0
	for _, t := range config.Traps {
		if t.Enabled {
			trapsEnabled++
		}
	}
	ifaces := collectIfaces()
	attached := 0
	for _, i := range ifaces {
		if i.Mode != "" && i.Mode != "off" && i.Mode != "unknown" {
			attached++
		}
	}
	return surfaceStats{
		Traps:   trapsEnabled,
		Ifaces:  attached,
		Surface: attached * trapsEnabled,
	}
}

func localIfaceIPs() []string {
	ifaces := collectIfaces()
	out := make([]string, 0, len(ifaces))
	seen := make(map[string]struct{})
	for _, i := range ifaces {
		if i.IPs == "" {
			continue
		}
		for _, ip := range strings.Split(i.IPs, ",") {
			ip = strings.TrimSpace(ip)
			if ip == "" || ip == "0.0.0.0" || ip == "::" {
				continue
			}
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}
	return out
}

// ─────────────────────────────────────────────
// ENTROPY CALCULATION (for payload analysis)
// ─────────────────────────────────────────────

func calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]int
	for _, b := range []byte(data) {
		freq[b]++
	}

	var entropy float64
	length := float64(len(data))

	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// ─────────────────────────────────────────────
// SAFE STRING UTILITIES
// ─────────────────────────────────────────────

// Normalize JA3 (strip spaces, lowercase)
func normalizeJA3(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func isGreaseValue(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && ((v>>8)&0xff) == (v&0xff)
}

func ja3HashFromString(ja3 string) string {
	sum := md5.Sum([]byte(ja3))
	return hex.EncodeToString(sum[:])
}

func seedJA3BlacklistFromConfig() {
	if ja3Blacklist == nil {
		return
	}
	ja3Mu.Lock()
	for k := range ja3Blacklist {
		delete(ja3Blacklist, k)
	}
	for _, v := range config.Security.JA3Blacklist {
		hash := parseJA3ConfigValue(v)
		if hash == "" {
			continue
		}
		ja3Blacklist[hash] = time.Now().Add(3650 * 24 * time.Hour)
	}
	ja3Mu.Unlock()
}

func getJA3PortSet() map[string]struct{} {
	ports := config.Security.JA3Ports
	if len(ports) == 0 {
		ports = []string{"443", "465", "636", "853", "990", "993", "995", "8443", "9443"}
	}
	out := make(map[string]struct{}, len(ports))
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out[p] = struct{}{}
	}
	return out
}

func getJA3ReadMaxBytes() int {
	if config.Security.JA3MaxBytes <= 0 {
		return 4096
	}
	if config.Security.JA3MaxBytes > 64*1024 {
		return 64 * 1024
	}
	return config.Security.JA3MaxBytes
}

func getJA3ReadTimeout() time.Duration {
	if config.Security.JA3TimeoutMs <= 0 {
		return 750 * time.Millisecond
	}
	if config.Security.JA3TimeoutMs > 5000 {
		return 5 * time.Second
	}
	return time.Duration(config.Security.JA3TimeoutMs) * time.Millisecond
}

func parseJA3ConfigValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.Contains(v, ",") {
		return strings.ToLower(ja3HashFromString(v))
	}
	if len(v) == 32 && isHex(v) {
		return strings.ToLower(v)
	}
	return strings.ToLower(ja3HashFromString(v))
}

func ja3LabelFor(hash string) string {
	if hash == "" {
		return ""
	}
	norm := normalizeJA3Key(hash)
	if norm == "" {
		return ""
	}
	labels := config.Security.JA3Labels
	if len(labels) == 0 {
		return ""
	}
	if v, ok := labels[norm]; ok {
		return v
	}
	for k, v := range labels {
		if normalizeJA3Key(k) == norm {
			return v
		}
	}
	return ""
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		case ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}
	return true
}

// computeJA3FromClientHello parses a TLS ClientHello record and returns the JA3 hash.
func computeJA3FromClientHello(data []byte) string {
	return computeTLSFingerprintsFromClientHello(data).JA3
}

func buildJA3String(ver uint16, ciphers, exts, groups, points []string) string {
	return strconvUint16(ver) + "," +
		strings.Join(ciphers, "-") + "," +
		strings.Join(exts, "-") + "," +
		strings.Join(groups, "-") + "," +
		strings.Join(points, "-")
}

func strconvUint16(v uint16) string {
	return strconv.FormatUint(uint64(v), 10)
}

func strconvUint8(v uint8) string {
	return strconv.FormatUint(uint64(v), 10)
}

func ipFromUint32(v uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return net.IP(b[:]).String()
}

func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return addr
}
