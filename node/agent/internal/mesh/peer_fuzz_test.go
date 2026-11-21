package mesh

import (
	"net/netip"
	"net/url"
	"strconv"
	"testing"
)

// A peer that passes validation must produce one exact HTTPS mesh endpoint.
// The fuzz engine also probes authority, URL, and control-character injection.
func FuzzMeshPeerURL(f *testing.F) {
	for _, peer := range []string{
		"10.0.0.2", "10.0.0.2:9443", "[fd00::2]:9000", "localhost:9000",
		"10.0.0.2@evil.example", "10.0.0.2/other", "10.0.0.2:0",
		"https://10.0.0.2:9000", "10.0.0.2\r\nHost: evil.example",
	} {
		f.Add(peer)
	}
	f.Fuzz(func(t *testing.T, peer string) {
		endpoint, err := meshPeerURL(peer, "/mesh/join")
		if err != nil {
			return
		}
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.User != nil ||
			parsed.Path != "/mesh/join" || parsed.RawQuery != "" || parsed.Fragment != "" ||
			parsed.Opaque != "" || parsed.ForceQuery {
			t.Fatalf("validated peer %q produced unsafe URL %q: %v", peer, endpoint, err)
		}
		ip, err := netip.ParseAddr(parsed.Hostname())
		if err != nil || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
			t.Fatalf("validated peer %q produced unsafe host %q: %v", peer, parsed.Hostname(), err)
		}
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			t.Fatalf("validated peer %q produced unsafe port %q: %v", peer, parsed.Port(), err)
		}
	})
}
