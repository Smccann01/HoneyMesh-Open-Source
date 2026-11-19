package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"honeymesh/internal/adaptivetrust"
	"honeymesh/internal/adaptivetruststore"
	_ "modernc.org/sqlite"
)

func hatAPIRequest(handler http.HandlerFunc, method, path, body, token, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Honey-Token", token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

func setupHATAPI(t *testing.T) *adaptivetruststore.Store {
	t.Helper()
	priorToken, priorStore := config.AdminToken, liveHATStore
	config.AdminToken = "local-test-admin-token"
	t.Cleanup(func() { config.AdminToken, liveHATStore = priorToken, priorStore })
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
	liveHATStore = store
	return store
}

const hatTestBody = `{"tenant_id":"tenant-a","subject_id":"web-a","resource_id":"orders-api","action":"orders.read","policy_version":"pilot-1"}`
const hatTestQuery = "/api/adaptive-trust/relationship?tenant_id=tenant-a&subject_id=web-a&resource_id=orders-api&action=orders.read&policy_version=pilot-1"

func TestAdaptiveTrustOperatorAPIIsAuthenticatedAndObserveOnly(t *testing.T) {
	store := setupHATAPI(t)
	if got := hatAPIRequest(apiAdaptiveTrustStatus, http.MethodGet, "/api/adaptive-trust/status", "", "wrong", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("status leaked without auth: %d", got.Code)
	}
	status := hatAPIRequest(apiAdaptiveTrustStatus, http.MethodGet, "/api/adaptive-trust/status", "", config.AdminToken, "")
	if status.Code != http.StatusOK || status.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(status.Body.String(), `"kernel_quarantine":"disabled"`) {
		t.Fatalf("status did not label enforcement: %d %s", status.Code, status.Body.String())
	}
	if got := hatAPIRequest(apiAdaptiveTrustPreview, http.MethodPost, "/api/adaptive-trust/preview", hatTestBody, "wrong", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("preview allowed wrong token: %d", got.Code)
	}
	if got := hatAPIRequest(apiAdaptiveTrustPreview, http.MethodPost, "/api/adaptive-trust/preview", hatTestBody, config.AdminToken, "https://untrusted.example"); got.Code != http.StatusForbidden {
		t.Fatalf("preview allowed foreign origin: %d", got.Code)
	}
	if got := hatAPIRequest(apiAdaptiveTrustPreview, http.MethodPost, "/api/adaptive-trust/preview", hatTestBody[:len(hatTestBody)-1]+`,"identity":{"verified":true}}`, config.AdminToken, ""); got.Code != http.StatusBadRequest {
		t.Fatalf("browser identity assertion accepted: %d", got.Code)
	}
	if got := hatAPIRequest(apiAdaptiveTrustPreview, http.MethodGet, "/api/adaptive-trust/preview", "", config.AdminToken, ""); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("preview allowed wrong method: %d", got.Code)
	}
	now := time.Now().UTC()
	grant := adaptivetrust.Grant{ID: "grant-1", TenantID: "tenant-a", SubjectID: "web-a", ResourceID: "orders-api",
		Actions: []string{"orders.read"}, ApprovedBy: "operator-1", IssuedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour), PolicyVersion: "pilot-1"}
	if err := store.PutGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	preview := hatAPIRequest(apiAdaptiveTrustPreview, http.MethodPost, "/api/adaptive-trust/preview", hatTestBody, config.AdminToken, "")
	if preview.Code != http.StatusOK || preview.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(preview.Body.String(), `"reason":"identity_unverified"`) ||
		!strings.Contains(preview.Body.String(), `"enforcement":"disabled"`) {
		t.Fatalf("unverified preview was not bounded: %d %s", preview.Code, preview.Body.String())
	}
	inspect := hatAPIRequest(apiAdaptiveTrustRelationship, http.MethodGet, hatTestQuery, "", config.AdminToken, "")
	if inspect.Code != http.StatusOK || !strings.Contains(inspect.Body.String(), `"id":"grant-1"`) ||
		!strings.Contains(inspect.Body.String(), `"identity_unverified"`) {
		t.Fatalf("relationship detail missing durable grant or audit: %d %s", inspect.Code, inspect.Body.String())
	}
	if err := store.PlaceHold(context.Background(), adaptivetrust.Hold{ID: "hold-1", TenantID: "tenant-a", SubjectID: "web-a",
		ResourceID: "orders-api", Action: "orders.read", PlacedBy: "operator-2", PlacedAt: now}); err != nil {
		t.Fatal(err)
	}
	preview = hatAPIRequest(apiAdaptiveTrustPreview, http.MethodPost, "/api/adaptive-trust/preview", hatTestBody, config.AdminToken, "")
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"reason":"quarantine_hold"`) {
		t.Fatalf("durable hold not reflected: %d %s", preview.Code, preview.Body.String())
	}
	if strings.Contains(preview.Body.String(), `"effect":"allow"`) {
		t.Fatal("operator preview claimed live allow")
	}
}

func TestAdaptiveTrustOperatorAPIRejectsInvalidScopeAndUnavailableStore(t *testing.T) {
	setupHATAPI(t)
	for _, path := range []string{hatTestQuery + "&limit=26", "/api/adaptive-trust/relationship?tenant_id=tenant-a"} {
		if got := hatAPIRequest(apiAdaptiveTrustRelationship, http.MethodGet, path, "", config.AdminToken, ""); got.Code != http.StatusBadRequest {
			t.Fatalf("invalid query accepted: %s %d", path, got.Code)
		}
	}
	if got := hatAPIRequest(apiAdaptiveTrustRelationship, http.MethodGet, hatTestQuery, "", "wrong", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("relationship leaked without auth: %d", got.Code)
	}
	liveHATStore = nil
	if got := hatAPIRequest(apiAdaptiveTrustPreview, http.MethodPost, "/api/adaptive-trust/preview", hatTestBody, config.AdminToken, ""); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing store accepted preview: %d", got.Code)
	}
	var status map[string]any
	response := hatAPIRequest(apiAdaptiveTrustStatus, http.MethodGet, "/api/adaptive-trust/status", "", config.AdminToken, "")
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil || status["store_available"] != false {
		t.Fatalf("missing store misreported: %+v %v", status, err)
	}
}
