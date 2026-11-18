package main

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf/link"
)

// ─────────────────────────────────────────────
// INTERFACE MODE CONTROL (SINGLE SOURCE OF TRUTH)
// ─────────────────────────────────────────────

func applyInterfaceMode(ifName string, mode IfaceMode) error {
	switch mode {

	case IfaceOff:
		if l, ok := xdpLinks[ifName]; ok {
			if err := l.Close(); err != nil {
				return fmt.Errorf("detach XDP from %s: %w", ifName, err)
			}
			delete(xdpLinks, ifName)
			log.Printf("[XDP] Detached from %s", ifName)
		}
		SetIfaceMode(ifName, IfaceOff)

	case IfaceMonitor, IfaceEnforce:
		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			log.Printf("[XDP] Interface not found: %s", ifName)
			return fmt.Errorf("interface %s: %w", ifName, err)
		}

		// prevent duplicate attach
		if _, exists := xdpLinks[ifName]; exists {
			SetIfaceMode(ifName, mode)
			return nil
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   bpfObjs.XdpProgFunc,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			log.Printf("[XDP] Attach failed on %s: %v", ifName, err)
			return fmt.Errorf("attach XDP to %s: %w", ifName, err)
		}

		xdpLinks[ifName] = l
		SetIfaceMode(ifName, mode)

		log.Printf("[XDP] Attached to %s (%s)", ifName, mode)
	}
	return nil
}

// persistInterfaceSelection records dashboard/TUI changes for the next start.
func persistInterfaceSelection(ifName string, enabled bool) error {
	selected := make([]string, 0, len(config.Ifaces)+1)
	for _, name := range config.Ifaces {
		if name != ifName {
			selected = append(selected, name)
		}
	}
	if enabled {
		selected = append(selected, ifName)
	}
	config.Ifaces = selected
	if !saveConfig() {
		return fmt.Errorf("save interface selection")
	}
	return nil
}

// ─────────────────────────────────────────────
// FIREWALL DETACH
// ─────────────────────────────────────────────

func detachFirewall() {
	for iface, l := range xdpLinks {
		l.Close()
		delete(xdpLinks, iface)
	}
	log.Println("[XDP] Firewall fully detached")
}

// The BPF maps compare IPv4 addresses as bytes copied directly from packets.
// Keep the map key in network byte order on both little- and big-endian hosts.
func ipv4BPFKey(ip net.IP) [4]byte {
	var key [4]byte
	copy(key[:], ip.To4())
	return key
}

// ─────────────────────────────────────────────
// BAN / UNBAN (IPv4 + IPv6)
// ─────────────────────────────────────────────

func banIP(ipStr string) {
	if liveUEE != nil {
		log.Printf("[UEE] refused legacy direct ban write for %s", ipStr)
		return
	}
	if err := (ueeKernelAdapter{}).Apply(ipStr); err != nil {
		log.Printf("[BAN] insert failed for %s: %v", ipStr, err)
	}
}

func unbanIP(ipStr string) {
	if liveUEE != nil {
		log.Printf("[UEE] refused legacy direct release write for %s", ipStr)
		return
	}
	if err := (ueeKernelAdapter{}).Remove(ipStr); err != nil {
		log.Printf("[BAN] release failed for %s: %v", ipStr, err)
	}
}

func applyRemoteBanKernelOnly(ip string) {
	banIP(ip)
}

// ─────────────────────────────────────────────
// WHITELIST → LPM TRIE
// ─────────────────────────────────────────────

type lpmKey struct {
	PrefixLen uint32
	IP        [4]byte
}

type lpmKey6 struct {
	PrefixLen uint32
	IP        [16]byte
}

func syncWhitelist() {
	// Reconcile both maps so a CIDR removed in the dashboard stops bypassing
	// enforcement immediately. Collect keys before deleting while iterating.
	if bpfObjs.WhitelistCidr == nil || bpfObjs.WhitelistCidrV6 == nil {
		return
	}
	var old4 []lpmKey
	var key4 lpmKey
	var value uint8
	it4 := bpfObjs.WhitelistCidr.Iterate()
	for it4.Next(&key4, &value) {
		old4 = append(old4, key4)
	}
	if err := it4.Err(); err != nil {
		log.Printf("[WHITELIST] IPv4 map iteration failed: %v", err)
		return
	}
	var old6 []lpmKey6
	var key6 lpmKey6
	it6 := bpfObjs.WhitelistCidrV6.Iterate()
	for it6.Next(&key6, &value) {
		old6 = append(old6, key6)
	}
	if err := it6.Err(); err != nil {
		log.Printf("[WHITELIST] IPv6 map iteration failed: %v", err)
		return
	}
	for _, key := range old4 {
		if err := bpfObjs.WhitelistCidr.Delete(key); err != nil {
			log.Printf("[WHITELIST] IPv4 map delete failed: %v", err)
		}
	}
	for _, key := range old6 {
		if err := bpfObjs.WhitelistCidrV6.Delete(key); err != nil {
			log.Printf("[WHITELIST] IPv6 map delete failed: %v", err)
		}
	}
	count := 0
	count6 := 0

	for _, cidr := range config.Security.Whitelist {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		ip4 := ipNet.IP.To4()
		if ip4 != nil {
			ones, _ := ipNet.Mask.Size()

			key := lpmKey{PrefixLen: uint32(ones), IP: ipv4BPFKey(ip4)}

			if err := bpfObjs.WhitelistCidr.Put(key, uint8(1)); err != nil {
				log.Printf("[WHITELIST] Failed to insert %s: %v", cidr, err)
				continue
			}

			count++
			continue
		}

		ip6 := ipNet.IP.To16()
		if ip6 == nil {
			continue
		}
		ones, _ := ipNet.Mask.Size()
		var key6 lpmKey6
		key6.PrefixLen = uint32(ones)
		copy(key6.IP[:], ip6)
		if err := bpfObjs.WhitelistCidrV6.Put(key6, uint8(1)); err != nil {
			log.Printf("[WHITELIST] Failed to insert %s: %v", cidr, err)
			continue
		}
		count6++
	}

	log.Printf("[WHITELIST] Synced %d IPv4 and %d IPv6 CIDRs into kernel LPM trie", count, count6)
}
