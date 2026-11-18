package enforcementengine

import (
	"sync"
	"testing"
	"time"

	"honeymesh/internal/banownership"
)

func TestConcurrentGrantExpiryRetractionAndOverrideConverge(t *testing.T) {
	for _, ip := range []string{"192.0.2.91", "2001:db8::91"} {
		t.Run(ip, func(t *testing.T) {
			engine, kernel, _ := testEngine(t)
			now := time.Now().UTC().Truncate(time.Second)
			local := banownership.Owner{Kind: banownership.Local, ID: "trap-80"}
			mesh := banownership.Owner{Kind: banownership.Mesh, ID: "peer-a:event-1"}
			exchange := banownership.Owner{Kind: banownership.Exchange, ID: "signal-1"}
			app := banownership.Owner{Kind: banownership.App, ID: "app-a:event-1"}
			grant := func(owner banownership.Owner, expiry time.Time) Grant {
				return Grant{IP: ip, Owner: owner, ExpiresAt: expiry, Reason: "qualification", PolicyVersion: "rc4-concurrent-1"}
			}
			run := func(operations ...func() error) {
				t.Helper()
				start := make(chan struct{})
				errors := make(chan error, len(operations))
				var workers sync.WaitGroup
				for _, operation := range operations {
					workers.Add(1)
					go func(operation func() error) {
						defer workers.Done()
						<-start
						errors <- operation()
					}(operation)
				}
				close(start)
				workers.Wait()
				close(errors)
				for err := range errors {
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			run(
				func() error { _, err := engine.Put(grant(local, now.Add(time.Second)), now); return err },
				func() error { _, err := engine.Put(grant(mesh, now.Add(time.Minute)), now); return err },
				func() error { _, err := engine.Put(grant(exchange, now.Add(time.Minute)), now); return err },
			)
			if grants, err := engine.Grants(ip, now); err != nil || len(grants) != 3 || !kernel.active[ip] {
				t.Fatalf("simultaneous grants: count=%d active=%v err=%v", len(grants), kernel.active[ip], err)
			}
			later := now.Add(2 * time.Second)
			run(
				func() error { _, err := engine.Put(grant(app, now.Add(time.Minute)), later); return err },
				func() error { _, err := engine.Remove(ip, mesh, later); return err },
				func() error { return engine.Sweep(later) },
			)
			if grants, err := engine.Grants(ip, later); err != nil || len(grants) != 2 || !kernel.active[ip] {
				t.Fatalf("expiry/add/retraction: count=%d active=%v err=%v", len(grants), kernel.active[ip], err)
			}
			run(
				func() error {
					_, err := engine.SetOverride(ip, "operator", "qualification recovery", 30*time.Second, later)
					return err
				},
				func() error { _, err := engine.Put(grant(exchange, now.Add(2*time.Minute)), later); return err },
			)
			if grants, err := engine.Grants(ip, later); err != nil || len(grants) != 2 || kernel.active[ip] {
				t.Fatalf("override/refresh: count=%d active=%v err=%v", len(grants), kernel.active[ip], err)
			}
			if _, err := engine.ClearOverride(ip, "operator", later); err != nil || !kernel.active[ip] {
				t.Fatalf("override release: active=%v err=%v", kernel.active[ip], err)
			}
			run(
				func() error { _, err := engine.Remove(ip, exchange, later); return err },
				func() error { _, err := engine.Remove(ip, app, later); return err },
			)
			if grants, err := engine.Grants(ip, later); err != nil || len(grants) != 0 || kernel.active[ip] {
				t.Fatalf("final state: count=%d active=%v err=%v", len(grants), kernel.active[ip], err)
			}
		})
	}
}
