package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestManualBanDurationBounds(t *testing.T) {
	for _, tc := range []struct {
		seconds int
		valid   bool
	}{
		{seconds: -1},
		{seconds: 0},
		{seconds: 29},
		{seconds: 30, valid: true},
		{seconds: 120, valid: true},
		{seconds: 86400, valid: true},
		{seconds: 86401},
	} {
		got, err := manualBanDuration(&tc.seconds)
		if (err == nil) != tc.valid {
			t.Fatalf("seconds=%d valid=%t err=%v", tc.seconds, tc.valid, err)
		}
		if tc.valid && got != time.Duration(tc.seconds)*time.Second {
			t.Fatalf("seconds=%d duration=%s", tc.seconds, got)
		}
	}
	defaultDuration, err := manualBanDuration(nil)
	if err != nil || defaultDuration != getBanDuration() {
		t.Fatalf("default duration=%s err=%v", defaultDuration, err)
	}
}

func TestManualBanRejectsTestModeAndInvalidTTL(t *testing.T) {
	testPaidHostLicense(t)
	previousMode := Mode()
	previousToken := config.AdminToken
	defer func() {
		SetMode(previousMode)
		config.AdminToken = previousToken
	}()
	config.AdminToken = "test-only-admin-token"
	request := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/ban", strings.NewReader(body))
		r.Header.Set("X-Honey-Token", config.AdminToken)
		w := httptest.NewRecorder()
		apiBan(w, r)
		return w
	}
	SetMode(ModeTest)
	if got := request(`{"ip":"8.8.8.8","ttl_seconds":30}`); got.Code != http.StatusConflict {
		t.Fatalf("TEST mode status=%d", got.Code)
	}
	SetMode(ModeEnforce)
	if got := request(`{"ip":"8.8.8.8","ttl_seconds":29}`); got.Code != http.StatusBadRequest {
		t.Fatalf("short TTL status=%d", got.Code)
	}
	if got := request(`{"ip":"8.8.8.8","ttl_seconds":86401}`); got.Code != http.StatusBadRequest {
		t.Fatalf("long TTL status=%d", got.Code)
	}
}
