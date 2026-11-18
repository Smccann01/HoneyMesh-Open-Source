package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"honeymesh/internal/banownership"
	"honeymesh/internal/enforcementengine"
)

func TestOperatorDecisionAndPreviewAreAuthenticatedAndReadOnly(t *testing.T) {
	testOperatorPaidLicense(t)
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
	previousUEE, previousToken, previousBind, previousAllow := liveUEE, config.AdminToken, config.BindIP, allowCIDRs
	previousMode := Mode()
	defer func() {
		liveUEE, config.AdminToken, config.BindIP, allowCIDRs = previousUEE, previousToken, previousBind, previousAllow
		ModeMu.Lock()
		GlobalMode = previousMode
		ModeMu.Unlock()
	}()
	liveUEE, config.AdminToken, config.BindIP = engine, "decision-test-token", "127.0.0.1"
	initAllowlist(baseAllowlistCIDRs())
	ModeMu.Lock()
	GlobalMode = ModeEnforce
	ModeMu.Unlock()
	const ip = "2001:4860:4860::8888"
	path := "/api/enforcement/decision?ip=" + ip
	if got := operatorAPIRequest(apiEnforcementDecision, path, "", "wrong", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized decision status=%d", got.Code)
	}
	if got := operatorAPIRequest(apiEnforcementDecision, "/api/enforcement/decision?ip=localhost", "", config.AdminToken, ""); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid decision status=%d", got.Code)
	}
	absent := operatorAPIRequest(apiEnforcementDecision, path, "", config.AdminToken, "")
	if absent.Code != http.StatusOK || !strings.Contains(absent.Body.String(), `"outcome":"no_active_uee_grant"`) {
		t.Fatalf("absent decision status=%d body=%s", absent.Code, absent.Body.String())
	}
	owner := banownership.Owner{Kind: banownership.Local, ID: "operator-review"}
	if _, err := engine.Put(enforcementengine.Grant{IP: ip, Owner: owner,
		ExpiresAt: time.Now().Add(5 * time.Minute), Reason: "manual review", PolicyVersion: runtimePolicyVersion}, time.Now()); err != nil {
		t.Fatal(err)
	}
	applied := operatorAPIRequest(apiEnforcementDecision, path, "", config.AdminToken, "")
	var decision operatorDecisionView
	if err := json.Unmarshal(applied.Body.Bytes(), &decision); err != nil || applied.Code != http.StatusOK {
		t.Fatalf("applied decision status=%d err=%v body=%s", applied.Code, err, applied.Body.String())
	}
	if decision.Outcome != "kernel_block_reported" || !decision.KernelApplied || len(decision.Grants) != 1 ||
		decision.Grants[0].PolicyVersion != runtimePolicyVersion || !kernel.active[ip] {
		t.Fatalf("unexpected applied decision: %+v", decision)
	}
	if got := operatorAPIRequest(apiEnforcementHistory, "/api/enforcement/history?ip="+ip, "", "wrong", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized history status=%d", got.Code)
	}
	if got := operatorAPIRequest(apiEnforcementHistory, "/api/enforcement/history?ip="+ip+"&limit=101", "", config.AdminToken, ""); got.Code != http.StatusBadRequest {
		t.Fatalf("unbounded history status=%d", got.Code)
	}
	history := operatorAPIRequest(apiEnforcementHistory, "/api/enforcement/history?ip="+ip+"&limit=1", "", config.AdminToken, "")
	if history.Code != http.StatusOK || !strings.Contains(history.Body.String(), `"operation":"apply"`) ||
		!strings.Contains(history.Body.String(), `"result":"success"`) {
		t.Fatalf("history status=%d body=%s", history.Code, history.Body.String())
	}
	previewBody := `{"ip":"` + ip + `","ttl_seconds":300}`
	if got := operatorAPIRequest(apiEnforcementPreview, "/api/enforcement/preview", previewBody, "wrong", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized preview status=%d", got.Code)
	}
	if got := operatorAPIRequest(apiEnforcementPreview, "/api/enforcement/preview", previewBody, config.AdminToken, "https://untrusted.example"); got.Code != http.StatusForbidden {
		t.Fatalf("cross-origin preview status=%d", got.Code)
	}
	if got := operatorAPIRequest(apiEnforcementPreview, "/api/enforcement/preview", `{"ip":"`+ip+`","ttl_seconds":86401}`, config.AdminToken, ""); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid duration status=%d", got.Code)
	}
	preview := operatorAPIRequest(apiEnforcementPreview, "/api/enforcement/preview", previewBody, config.AdminToken, "")
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"existing_owner_count":1`) ||
		!strings.Contains(preview.Body.String(), `"immediate_kernel_effect_possible":false`) {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	grants, err := engine.Grants(ip, time.Now())
	if err != nil || len(grants) != 1 {
		t.Fatalf("preview changed grants: %+v %v", grants, err)
	}
	if _, err := engine.SetOverride(ip, "test", "emergency release", time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
	overridden := operatorAPIRequest(apiEnforcementDecision, path, "", config.AdminToken, "")
	if overridden.Code != http.StatusOK || !strings.Contains(overridden.Body.String(), `"outcome":"release_override_active"`) {
		t.Fatalf("override decision status=%d body=%s", overridden.Code, overridden.Body.String())
	}
	history = operatorAPIRequest(apiEnforcementHistory, "/api/enforcement/history?ip="+ip+"&limit=1", "", config.AdminToken, "")
	if history.Code != http.StatusOK || !strings.Contains(history.Body.String(), `"override_active":true`) ||
		!strings.Contains(history.Body.String(), `"operation":"remove"`) {
		t.Fatalf("override history status=%d body=%s", history.Code, history.Body.String())
	}
	ModeMu.Lock()
	GlobalMode = ModeTest
	ModeMu.Unlock()
	preview = operatorAPIRequest(apiEnforcementPreview, "/api/enforcement/preview", previewBody, config.AdminToken, "")
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"test_mode"`) ||
		!strings.Contains(preview.Body.String(), `"release_override_active"`) {
		t.Fatalf("TEST preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	protected := operatorAPIRequest(apiEnforcementPreview, "/api/enforcement/preview", `{"ip":"127.0.0.1","ttl_seconds":60}`, config.AdminToken, "")
	if protected.Code != http.StatusBadRequest {
		t.Fatalf("loopback preview status=%d", protected.Code)
	}
}

func TestOperatorDecisionReportsPendingKernelApply(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	engine, err := enforcementengine.NewWithEnforcement(database, failedOperatorKernel{}, true)
	if err != nil {
		t.Fatal(err)
	}
	previousUEE, previousToken := liveUEE, config.AdminToken
	defer func() { liveUEE, config.AdminToken = previousUEE, previousToken }()
	liveUEE, config.AdminToken = engine, "decision-test-token"
	const ip = "8.8.8.8"
	if _, err := engine.Put(enforcementengine.Grant{IP: ip, Owner: banownership.Owner{Kind: banownership.Local, ID: "test"},
		ExpiresAt: time.Now().Add(time.Minute), PolicyVersion: runtimePolicyVersion}, time.Now()); err == nil {
		t.Fatal("expected injected kernel failure")
	}
	response := operatorAPIRequest(apiEnforcementDecision, "/api/enforcement/decision?ip="+ip, "", config.AdminToken, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"outcome":"grant_pending_or_not_applied"`) ||
		!strings.Contains(response.Body.String(), `"kernel_applied":false`) {
		t.Fatalf("pending decision status=%d body=%s", response.Code, response.Body.String())
	}
}
