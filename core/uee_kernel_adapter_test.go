package main

import "testing"

func TestUEEKernelAdapterFailsClosedWithoutMaps(t *testing.T) {
	previous := bpfObjs
	bpfObjs = bpfObjects{}
	t.Cleanup(func() { bpfObjs = previous })
	adapter := ueeKernelAdapter{}
	for _, ip := range []string{"192.0.2.8", "2001:db8::8"} {
		if err := adapter.Apply(ip); err == nil {
			t.Fatalf("Apply(%s) accepted an unavailable map", ip)
		}
		if err := adapter.Remove(ip); err == nil {
			t.Fatalf("Remove(%s) accepted an unavailable map", ip)
		}
	}
	for _, ip := range []string{"", "not-an-ip", "fe80::1%eth0"} {
		if err := adapter.Apply(ip); err == nil {
			t.Fatalf("Apply(%q) accepted an invalid exact source", ip)
		}
	}
}
