package main

import (
	"errors"
	"net/http"

	"github.com/cilium/ebpf"
)

type dropTotals struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type banDropSnapshot struct {
	Reason string     `json:"reason"`
	IPv4   dropTotals `json:"ipv4"`
	IPv6   dropTotals `json:"ipv6"`
	Reset  string     `json:"reset"`
}

func readBanDropTotals() (banDropSnapshot, error) {
	out := banDropSnapshot{Reason: "EXACT_BAN", Reset: "agent_start"}
	if bpfObjs.BanDropTotals == nil {
		return out, errors.New("XDP drop counters unavailable")
	}
	for key := uint32(0); key < 2; key++ {
		var perCPU []dropTotals
		if err := bpfObjs.BanDropTotals.Lookup(key, &perCPU); err != nil {
			return out, err
		}
		var total dropTotals
		for _, cpu := range perCPU {
			total.Packets += cpu.Packets
			total.Bytes += cpu.Bytes
		}
		if key == 0 {
			out.IPv4 = total
		} else {
			out.IPv6 = total
		}
	}
	return out, nil
}

func apiBanDropTotals(w http.ResponseWriter, r *http.Request) {
	if config.AdminToken == "" || r.Header.Get("X-Honey-Token") != config.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOriginAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	result, err := readBanDropTotals()
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			http.Error(w, "XDP counter slot unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "XDP drop counters unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, result)
}
