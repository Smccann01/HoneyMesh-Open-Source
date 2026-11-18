package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cilium/ebpf"
)

func TestBanDropCounterMapIsBounded(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Maps["ban_drop_totals"]
	if m == nil || m.Type != ebpf.PerCPUArray || m.MaxEntries != 2 || m.ValueSize != 16 {
		t.Fatalf("unexpected drop counter map: %+v", m)
	}
}

func TestBanDropCounterEndpointRequiresAdmin(t *testing.T) {
	previous := config.AdminToken
	defer func() { config.AdminToken = previous }()
	config.AdminToken = "test-only-admin-token"
	w := httptest.NewRecorder()
	apiBanDropTotals(w, httptest.NewRequest(http.MethodGet, "/api/xdp/drop-totals", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", w.Code)
	}
}
