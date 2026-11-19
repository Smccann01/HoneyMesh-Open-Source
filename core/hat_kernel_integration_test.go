package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"honeymesh/internal/adaptivetrust"
	"honeymesh/internal/adaptivetrustkernel"
	"honeymesh/internal/adaptivetruststore"
	"honeymesh/internal/enforcementengine"
	_ "modernc.org/sqlite"
)

// This opt-in test loads the real eBPF collection into an isolated test host.
// It verifies UEE writes and removes the kernel ban map, without attaching XDP
// to a network interface or affecting host traffic.
func TestAdaptiveTrustRealKernelMap(t *testing.T) {
	if os.Getenv("HONEY_KERNEL_INTEGRATION") != "1" {
		t.Skip("requires disposable Linux host with BPF privileges")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	previous := bpfObjs
	var objects bpfObjects
	if err := loadBpfObjects(&objects, nil); err != nil {
		t.Fatal(err)
	}
	bpfObjs = objects
	t.Cleanup(func() { bpfObjs = previous; _ = objects.Close() })
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	store, err := adaptivetruststore.New(database)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := enforcementengine.NewWithEnforcement(database, ueeKernelAdapter{}, true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := adaptivetrust.Request{TenantID: "kernel-test", SubjectID: "dedicated-source",
		ResourceID: adaptivetrustkernel.NetworkResource, Action: adaptivetrustkernel.QuarantineAction,
		SessionID: "kernel-test-session"}
	if err := store.PlaceHold(context.Background(), adaptivetrust.Hold{ID: "kernel-test-hold",
		TenantID: request.TenantID, SubjectID: request.SubjectID, ResourceID: request.ResourceID,
		Action: request.Action, PlacedBy: "operator-1", PlacedAt: now.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	binding := adaptivetrustkernel.SourceBinding{TenantID: request.TenantID, SubjectID: request.SubjectID,
		IP: "192.0.2.11", VerifierID: "local-test-verifier", EvidenceID: "kernel-test-binding",
		ApprovedBy: "operator-2", Verified: true, Exclusive: true, ExpiresAt: now.Add(time.Minute)}
	policy := adaptivetrust.Policy{Version: "hat-kernel-test-1", MaxLease: 30 * time.Second}
	result, err := adaptivetrustkernel.ApplyQuarantine(context.Background(), store, engine, request, binding, policy, now)
	if err != nil || !result.KernelApplied {
		t.Fatalf("quarantine not confirmed: %+v %v", result, err)
	}
	key := [4]byte{192, 0, 2, 11}
	var value uint8
	if err := bpfObjs.BanMap.Lookup(key, &value); err != nil || value != 1 {
		t.Fatalf("kernel map did not contain exact source: value=%d err=%v", value, err)
	}
	if err := engine.Sweep(now.Add(31 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := bpfObjs.BanMap.Lookup(key, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("expired HAT owner remained in kernel: value=%d err=%v", value, err)
	}
}
