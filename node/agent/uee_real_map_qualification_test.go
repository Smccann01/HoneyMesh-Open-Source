//go:build hm_qualification

package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"honeymesh/internal/banownership"
	"honeymesh/internal/enforcementengine"
)

// This opt-in test uses the real eBPF ban maps and UEE adapter. It is excluded
// from customer packages and ordinary test runs. It does not exercise producer
// authentication or packet traffic, which require separate field evidence.
func TestQualificationFourOwnersRealXDPMaps(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("qualification map test requires root and CAP_BPF")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock limit: %v", err)
	}
	if err := loadBpfObjects(&bpfObjs, nil); err != nil {
		t.Fatalf("load real eBPF collection: %v", err)
	}
	defer bpfObjs.Close()

	owners := []banownership.Owner{
		{Kind: banownership.Local, ID: "qualification-local"},
		{Kind: banownership.App, ID: "qualification-app"},
		{Kind: banownership.Mesh, ID: "qualification-mesh"},
		{Kind: banownership.Exchange, ID: "qualification-exchange"},
	}
	for _, raw := range []string{"192.0.2.80", "2001:db8::80"} {
		ip := netip.MustParseAddr(raw)
		for _, order := range qualificationOwnerOrders(4) {
			t.Run(fmt.Sprintf("%s/%d-%d-%d-%d", raw, order[0], order[1], order[2], order[3]), func(t *testing.T) {
				store, err := sql.Open("sqlite", ":memory:")
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				store.SetMaxOpenConns(1)
				engine, err := enforcementengine.New(store, ueeKernelAdapter{})
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				for _, owner := range owners {
					if _, err := engine.Put(enforcementengine.Grant{
						IP: raw, Owner: owner, ExpiresAt: now.Add(15 * time.Minute),
						Reason: "isolated real-map qualification", PolicyVersion: "rc4-real-map-1",
					}, now); err != nil {
						t.Fatal(err)
					}
					qualificationAssertMap(t, ip, true)
				}
				for step, ownerIndex := range order {
					decision, err := engine.Remove(raw, owners[ownerIndex], now.Add(time.Second))
					if err != nil {
						t.Fatal(err)
					}
					remaining := len(owners) - step - 1
					if decision.Owners != remaining || decision.Active != (remaining > 0) {
						t.Fatalf("decision after owner removal: %+v; want %d owners", decision, remaining)
					}
					qualificationAssertMap(t, ip, remaining > 0)
				}
			})
		}
	}
}

func qualificationAssertMap(t *testing.T, ip netip.Addr, wantPresent bool) {
	t.Helper()
	var value uint8
	var err error
	if ip.Is4() {
		err = bpfObjs.BanMap.Lookup(ip.As4(), &value)
	} else {
		err = bpfObjs.BanMapV6.Lookup(ip.As16(), &value)
	}
	if wantPresent {
		if err != nil || value != 1 {
			t.Fatalf("real XDP map missing expected key: value=%d error=%v", value, err)
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("real XDP map retained key after final removal: value=%d error=%v", value, err)
	}
}

func qualificationOwnerOrders(count int) [][]int {
	var result [][]int
	var visit func([]int, []bool)
	visit = func(order []int, used []bool) {
		if len(order) == count {
			result = append(result, append([]int(nil), order...))
			return
		}
		for index := 0; index < count; index++ {
			if used[index] {
				continue
			}
			used[index] = true
			visit(append(order, index), used)
			used[index] = false
		}
	}
	visit(nil, make([]bool, count))
	return result
}
