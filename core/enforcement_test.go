package main

import (
	"net"
	"testing"
	"unsafe"
)

func TestIPv4BPFKeyMatchesPacketBytes(t *testing.T) {
	ip := net.ParseIP("172.17.0.4").To4()
	want := [4]byte{172, 17, 0, 4}
	if got := ipv4BPFKey(ip); got != want {
		t.Fatalf("BPF key %v does not match packet bytes %v", got, want)
	}
	if got := unsafe.Sizeof(lpmKey{}); got != 8 {
		t.Fatalf("IPv4 LPM key size = %d, want 8", got)
	}
}
