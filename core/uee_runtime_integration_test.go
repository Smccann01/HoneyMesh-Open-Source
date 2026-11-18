package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"honeymesh/internal/banownership"
	"honeymesh/internal/enforcementengine"
)

type runtimeTestKernel struct{ active map[string]bool }

func (k *runtimeTestKernel) Apply(ip string) error  { k.active[ip] = true; return nil }
func (k *runtimeTestKernel) Remove(ip string) error { delete(k.active, ip); return nil }

func TestLiveUEELocalAndMeshOwnership(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	kernel := &runtimeTestKernel{active: map[string]bool{}}
	engine, err := enforcementengine.NewWithEnforcement(database, kernel, true)
	if err != nil {
		t.Fatal(err)
	}
	previous := liveUEE
	liveUEE = engine
	defer func() { liveUEE = previous }()
	now := time.Now()
	ip := "8.8.8.8"
	if _, err := ueeLocalGrant(ip, "MANUAL", "operator", now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := ueeRemoteGrant(ip, "REMOTE_MESH", "peer-signal-1", "trusted peer", nil, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Remove(ip, banownership.Owner{Kind: banownership.Local, ID: "manual"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !kernel.active[ip] {
		t.Fatal("removing local owner removed mesh rule")
	}
	grants, err := engine.Grants(ip, time.Now())
	if err != nil || len(grants) != 1 || grants[0].Owner.Kind != banownership.Mesh {
		t.Fatalf("mesh owner lost: %+v %v", grants, err)
	}
	if _, err := engine.Remove(ip, grants[0].Owner, time.Now()); err != nil {
		t.Fatal(err)
	}
	if kernel.active[ip] {
		t.Fatal("final owner did not release kernel rule")
	}
}

func TestEnforcementGrantAPIRequiresAdminAndShowsPendingState(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	kernel := &runtimeTestKernel{active: map[string]bool{}}
	engine, err := enforcementengine.NewWithEnforcement(database, kernel, false)
	if err != nil {
		t.Fatal(err)
	}
	previousEngine, previousToken := liveUEE, config.AdminToken
	liveUEE, config.AdminToken = engine, "test-only-admin-token"
	defer func() { liveUEE, config.AdminToken = previousEngine, previousToken }()
	if _, err := ueeLocalGrant("8.8.8.8", "MANUAL", "test", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRecorder()
	apiEnforcementGrants(unauthorized, httptest.NewRequest(http.MethodGet, "/api/enforcement/grants", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/enforcement/grants", nil)
	request.Header.Set("X-Honey-Token", config.AdminToken)
	response := httptest.NewRecorder()
	apiEnforcementGrants(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"KernelApplied":false`) || kernel.active["8.8.8.8"] {
		t.Fatalf("pending state misreported: status=%d body=%s", response.Code, response.Body.String())
	}
}
