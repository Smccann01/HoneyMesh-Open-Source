package enforcementengine

import (
	"fmt"
	"testing"
	"time"

	"honeymesh/internal/banownership"
)

// This is a source-level ownership test. The disposable packet lab must still
// confirm that the same decisions reach the attached XDP maps.
func TestFourOwnerRemovalOrdersAfterRestart(t *testing.T) {
	owners := []banownership.Owner{
		{Kind: banownership.Local, ID: "trap-80"},
		{Kind: banownership.App, ID: "app-a:event-1"},
		{Kind: banownership.Mesh, ID: "trusted-peer:event-1"},
		{Kind: banownership.Exchange, ID: "signal-1"},
	}
	for _, ip := range []string{"192.0.2.80", "2001:db8::80"} {
		for _, order := range ownerOrders(4) {
			name := fmt.Sprintf("%s/%d-%d-%d-%d", ip, order[0], order[1], order[2], order[3])
			t.Run(name, func(t *testing.T) {
				engine, kernel, db := testEngine(t)
				now := time.Now().UTC()
				for _, owner := range owners {
					decision, err := engine.Put(Grant{
						IP: ip, Owner: owner, ExpiresAt: now.Add(15 * time.Minute),
						Reason: "qualification", PolicyVersion: "rc4-ownership-1",
					}, now)
					if err != nil || !decision.Active || !kernel.active[ip] {
						t.Fatalf("put %v: decision=%+v kernel=%v err=%v", owner, decision, kernel.active[ip], err)
					}
				}
				engine, err := New(db, kernel)
				if err != nil || engine.ReconcileAll(now.Add(time.Second)) != nil {
					t.Fatalf("restart reconciliation: %v", err)
				}
				for step, index := range order {
					decision, err := engine.Remove(ip, owners[index], now.Add(2*time.Second))
					remaining := len(owners) - step - 1
					if err != nil || decision.Owners != remaining || decision.Active != (remaining > 0) || kernel.active[ip] != (remaining > 0) {
						t.Fatalf("remove %v: decision=%+v kernel=%v err=%v", owners[index], decision, kernel.active[ip], err)
					}
					grants, err := engine.Grants(ip, now.Add(2*time.Second))
					if err != nil || len(grants) != remaining {
						t.Fatalf("stored grants after removal: count=%d want=%d err=%v", len(grants), remaining, err)
					}
				}
			})
		}
	}
}

func ownerOrders(count int) [][]int {
	var result [][]int
	var visit func([]int, []bool)
	visit = func(order []int, used []bool) {
		if len(order) == count {
			result = append(result, append([]int(nil), order...))
			return
		}
		for i := 0; i < count; i++ {
			if used[i] {
				continue
			}
			used[i] = true
			visit(append(order, i), used)
			used[i] = false
		}
	}
	visit(nil, make([]bool, count))
	return result
}
