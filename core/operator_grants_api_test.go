package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"honeymesh/internal/banownership"
	"honeymesh/internal/enforcementengine"
	"honeymesh/internal/license"
)

func testOperatorPaidLicense(t *testing.T) {
	t.Helper()
	tier, valid, expiry, nodes := license.Tier(), license.Valid(), license.ExpiresAt(), license.MaxNodes()
	license.SetStateForTesting(license.TierPro, true, time.Now().Add(time.Hour), 1)
	t.Cleanup(func() { license.SetStateForTesting(tier, valid, expiry, nodes) })
}

type failedOperatorKernel struct{}

func (failedOperatorKernel) Apply(string) error  { return errors.New("injected apply failure") }
func (failedOperatorKernel) Remove(string) error { return nil }

func operatorAPIRequest(handler http.HandlerFunc, path, body, token, origin string) *httptest.ResponseRecorder {
	method := http.MethodPost
	if body == "" {
		method = http.MethodGet
	}
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("X-Honey-Token", token)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	response := httptest.NewRecorder()
	handler(response, request)
	return response
}

func TestOperatorGrantAPIIsScopedAcrossAddressFamilies(t *testing.T) {
	testOperatorPaidLicense(t)
	for _, ip := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		t.Run(ip, func(t *testing.T) {
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
			previousUEE, previousToken, previousBind, previousBans, previousAllow := liveUEE, config.AdminToken, config.BindIP, banExpirations, allowCIDRs
			previousMode := Mode()
			defer func() {
				liveUEE, config.AdminToken, config.BindIP, banExpirations, allowCIDRs = previousUEE, previousToken, previousBind, previousBans, previousAllow
				ModeMu.Lock()
				GlobalMode = previousMode
				ModeMu.Unlock()
			}()
			liveUEE, config.AdminToken, config.BindIP = engine, "operator-api-test-token", "127.0.0.1"
			initAllowlist(baseAllowlistCIDRs())
			ModeMu.Lock()
			GlobalMode = ModeTest
			ModeMu.Unlock()
			body := `{"ip":"` + ip + `","ttl_seconds":60,"reason":"manual review"}`
			if got := operatorAPIRequest(apiOperatorGrants, "/api/enforcement/operator-grants", body, "wrong", ""); got.Code != http.StatusUnauthorized {
				t.Fatalf("unauthorized create status=%d", got.Code)
			}
			if got := operatorAPIRequest(apiOperatorGrants, "/api/enforcement/operator-grants", body, config.AdminToken, "https://untrusted.example"); got.Code != http.StatusForbidden {
				t.Fatalf("cross-origin create status=%d", got.Code)
			}
			if got := operatorAPIRequest(apiOperatorGrants, "/api/enforcement/operator-grants", body, config.AdminToken, ""); got.Code != http.StatusConflict {
				t.Fatalf("TEST create status=%d", got.Code)
			}
			ModeMu.Lock()
			GlobalMode = ModeEnforce
			ModeMu.Unlock()
			now := time.Now()
			owners := []banownership.Owner{
				{Kind: banownership.Local, ID: "detection"},
				{Kind: banownership.App, ID: "billing-api"},
				{Kind: banownership.Mesh, ID: "trusted-node"},
				{Kind: banownership.Exchange, ID: "signal-123"},
			}
			for _, owner := range owners {
				if _, err := engine.Put(enforcementengine.Grant{IP: ip, Owner: owner, ExpiresAt: now.Add(5 * time.Minute), Reason: "independent", PolicyVersion: runtimePolicyVersion}, now); err != nil {
					t.Fatal(err)
				}
			}
			created := operatorAPIRequest(apiOperatorGrants, "/api/enforcement/operator-grants", body, config.AdminToken, "")
			if created.Code != http.StatusOK {
				t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
			}
			var result struct {
				GrantID          string `json:"grant_id"`
				KernelReconciled bool   `json:"kernel_reconciled"`
			}
			if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || !result.KernelReconciled {
				t.Fatalf("create result=%+v err=%v", result, err)
			}
			if _, valid := operatorGrantOwner(result.GrantID); !valid || !kernel.active[ip] {
				t.Fatalf("missing operator owner or kernel rule: %+v", result)
			}
			if got := operatorAPIRequest(apiOperatorGrantRelease, "/api/enforcement/operator-grants/release", `{"ip":"`+ip+`","grant_id":"detection"}`, config.AdminToken, ""); got.Code != http.StatusBadRequest {
				t.Fatalf("other-owner release status=%d", got.Code)
			}
			license.SetStateForTesting(license.TierFree, false, time.Time{}, 0)
			withoutLicense := operatorAPIRequest(apiOperatorGrants, "/api/enforcement/operator-grants", body, config.AdminToken, "")
			if withoutLicense.Code != http.StatusOK {
				t.Fatalf("community create status=%d", withoutLicense.Code)
			}
			var communityResult struct {
				GrantID string `json:"grant_id"`
			}
			if err := json.Unmarshal(withoutLicense.Body.Bytes(), &communityResult); err != nil || communityResult.GrantID == "" || communityResult.GrantID == result.GrantID {
				t.Fatalf("community grant result=%+v err=%v", communityResult, err)
			}
			if got := operatorAPIRequest(apiOperatorGrantRelease, "/api/enforcement/operator-grants/release", `{"ip":"`+ip+`","grant_id":"`+communityResult.GrantID+`"}`, config.AdminToken, ""); got.Code != http.StatusOK {
				t.Fatalf("community grant release status=%d", got.Code)
			}
			released := operatorAPIRequest(apiOperatorGrantRelease, "/api/enforcement/operator-grants/release", `{"ip":"`+ip+`","grant_id":"`+result.GrantID+`"}`, config.AdminToken, "")
			if released.Code != http.StatusOK || !kernel.active[ip] {
				t.Fatalf("scoped release status=%d kernel=%v", released.Code, kernel.active)
			}
			grants, err := engine.Grants(ip, time.Now())
			if err != nil || len(grants) != len(owners) {
				t.Fatalf("independent owners changed: %+v %v", grants, err)
			}
			for _, owner := range owners {
				if _, err := engine.Remove(ip, owner, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if kernel.active[ip] {
				t.Fatal("final owner removal did not release kernel rule")
			}
			license.SetStateForTesting(license.TierPro, true, time.Now().Add(time.Hour), 1)
			longGrant := operatorAPIRequest(apiOperatorGrants, "/api/enforcement/operator-grants",
				`{"ip":"`+ip+`","ttl_seconds":86400}`, config.AdminToken, "")
			if longGrant.Code != http.StatusOK {
				t.Fatalf("24-hour create status=%d body=%s", longGrant.Code, longGrant.Body.String())
			}
			var longResult struct {
				GrantID string `json:"grant_id"`
			}
			if err := json.Unmarshal(longGrant.Body.Bytes(), &longResult); err != nil || longResult.GrantID == "" {
				t.Fatalf("24-hour create result=%+v err=%v", longResult, err)
			}
			longRelease := operatorAPIRequest(apiOperatorGrantRelease, "/api/enforcement/operator-grants/release",
				`{"ip":"`+ip+`","grant_id":"`+longResult.GrantID+`"}`, config.AdminToken, "")
			if longRelease.Code != http.StatusOK {
				t.Fatalf("24-hour release status=%d", longRelease.Code)
			}
		})
	}
}

func TestOperatorContractAndProtectedSource(t *testing.T) {
	testOperatorPaidLicense(t)
	previousToken, previousBind := config.AdminToken, config.BindIP
	defer func() { config.AdminToken, config.BindIP = previousToken, previousBind }()
	config.AdminToken, config.BindIP = "operator-api-test-token", "8.8.8.8"
	contract := operatorAPIRequest(apiEnforcementContract, "/api/enforcement/contract", "", config.AdminToken, "")
	if contract.Code != http.StatusOK || !strings.Contains(contract.Body.String(), `"contract_version":1`) {
		t.Fatalf("contract status=%d body=%s", contract.Code, contract.Body.String())
	}
	license.SetStateForTesting(license.TierFree, false, time.Time{}, 0)
	contract = operatorAPIRequest(apiEnforcementContract, "/api/enforcement/contract", "", config.AdminToken, "")
	if contract.Code != http.StatusOK || !strings.Contains(contract.Body.String(), `"operator_grants":true`) {
		t.Fatalf("community contract status=%d body=%s", contract.Code, contract.Body.String())
	}
	if _, valid := operatorSource("8.8.8.8"); valid {
		t.Fatal("dashboard bind source must be protected")
	}
	if _, valid := operatorSource("127.0.0.1"); valid {
		t.Fatal("loopback source must be protected")
	}
}

func TestOperatorGrantReportsPendingAfterKernelFailure(t *testing.T) {
	testOperatorPaidLicense(t)
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
	previousUEE, previousToken, previousBind, previousBans := liveUEE, config.AdminToken, config.BindIP, banExpirations
	previousMode := Mode()
	defer func() {
		liveUEE, config.AdminToken, config.BindIP, banExpirations = previousUEE, previousToken, previousBind, previousBans
		ModeMu.Lock()
		GlobalMode = previousMode
		ModeMu.Unlock()
	}()
	liveUEE, config.AdminToken, config.BindIP = engine, "operator-api-test-token", "127.0.0.1"
	ModeMu.Lock()
	GlobalMode = ModeEnforce
	ModeMu.Unlock()
	response := operatorAPIRequest(apiOperatorGrants, "/api/enforcement/operator-grants",
		`{"ip":"8.8.8.8","ttl_seconds":60}`, config.AdminToken, "")
	if response.Code != http.StatusAccepted {
		t.Fatalf("expected pending status, got %d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		GrantID          string `json:"grant_id"`
		KernelReconciled bool   `json:"kernel_reconciled"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.KernelReconciled {
		t.Fatalf("pending response=%+v err=%v", result, err)
	}
	owner, valid := operatorGrantOwner(result.GrantID)
	if !valid {
		t.Fatalf("invalid pending owner %q", result.GrantID)
	}
	exists, err := operatorGrantExists("8.8.8.8", owner, time.Now())
	if err != nil || !exists {
		t.Fatalf("desired grant not retained for retry: exists=%t err=%v", exists, err)
	}
	entries, err := engine.Snapshot(time.Now())
	if err != nil || len(entries) != 1 || entries[0].KernelApplied {
		t.Fatalf("kernel failure misreported: %+v %v", entries, err)
	}
}
