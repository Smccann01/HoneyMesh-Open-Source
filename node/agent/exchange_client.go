package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"honeymesh/internal/license"
)

const (
	defaultExchangePullInterval   = 300
	defaultExchangeTrustThreshold = 50
	maxExchangeTTL                = 5 * time.Minute
	defaultExchangeBaseURL        = "https://exchange.nettools.cloud"
	fallbackExchangeBaseURL       = "https://nettools.cloud"
)

type exchangeRegisterResponse struct {
	NodeID     string `json:"node_id"`
	TenantID   string `json:"tenant_id"`
	APIBaseURL string `json:"api_base_url"`
	Secret     string `json:"secret"`
}

type exchangeBootstrapResponse struct {
	NodeID     string `json:"node_id"`
	TenantID   string `json:"tenant_id"`
	APIBaseURL string `json:"api_base_url"`
	Secret     string `json:"secret"`
}

type exchangeVerifiedLicenseClaim struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	ClusterID string `json:"clusterId"`
	ExpiresAt string `json:"expiresAt"`
	MaxNodes  int    `json:"maxNodes"`
	Tier      string `json:"tier"`
}

type exchangeConfigResponse struct {
	TenantID           string `json:"tenantId"`
	SharingEnabled     bool   `json:"sharingEnabled"`
	ExchangeKillSwitch bool   `json:"exchangeKillSwitch"`
	ReviewOnlyMode     bool   `json:"reviewOnlyMode"`
	Plan               string `json:"plan"`
	LicenseStatus      string `json:"licenseStatus"`
	SyncWindowSeconds  int    `json:"syncWindowSeconds"`
}

type exchangeFeedRecord struct {
	ID         string  `json:"id"`
	AttackerIP string  `json:"attackerIp"`
	JA4        string  `json:"ja4"`
	JA3Legacy  string  `json:"ja3Legacy"`
	ClusterID  string  `json:"clusterId"`
	AttackType string  `json:"attackType"`
	Protocol   string  `json:"protocol"`
	Port       int     `json:"port"`
	Service    string  `json:"service"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	TTL        int     `json:"ttl"`
	Status     string  `json:"status"`
	Publisher  string  `json:"publisher"`
}

type exchangeFeedResponse struct {
	Cursor               string               `json:"cursor"`
	RetractionCursor     int64                `json:"retractionCursor"`
	Retractions          []exchangeRetraction `json:"retractions"`
	SyncWindowSeconds    int                  `json:"syncWindowSeconds"`
	LocalNodeAttacks     []exchangeFeedRecord `json:"localNodeAttacks"`
	ConnectedMeshAttacks []exchangeFeedRecord `json:"connectedMeshAttacks"`
	MergedFeed           []exchangeFeedRecord `json:"mergedFeed"`
}

type exchangeSnapshotResponse struct {
	Complete         bool                 `json:"complete"`
	Records          []exchangeFeedRecord `json:"records"`
	Cursor           string               `json:"cursor"`
	RetractionCursor int64                `json:"retractionCursor"`
	AsOf             string               `json:"asOf"`
}

func exchangeConfigured() bool {
	return strings.TrimSpace(config.Exchange.BaseURL) != "" &&
		strings.TrimSpace(config.Exchange.NodeID) != "" &&
		strings.TrimSpace(config.Exchange.SharedSecret) != ""
}

func exchangeEnabled() bool {
	return config.Exchange.Enabled &&
		trustedNetworkSharingEnabled() &&
		exchangeConfigured()
}

func exchangeHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}
}

func exchangeBodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func exchangeNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func exchangeSignature(method, path, timestamp, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(config.Exchange.SharedSecret))
	_, _ = mac.Write([]byte(method))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(path))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(nonce))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func exchangeResponseSignature(status int, timestamp, bodyHash string) string {
	mac := hmac.New(sha256.New, []byte(config.Exchange.SharedSecret))
	_, _ = mac.Write([]byte("response"))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(strconv.Itoa(status)))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(bodyHash))
	return hex.EncodeToString(mac.Sum(nil))
}

func doExchangeRequest(method, path string, body []byte) ([]byte, int, error) {
	if !exchangeConfigured() {
		return nil, 0, fmt.Errorf("exchange not configured")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(config.Exchange.BaseURL), "/")
	if parsed, err := url.Parse(baseURL); err == nil {
		host := strings.ToLower(parsed.Hostname())
		if parsed.Scheme != "https" && host != "localhost" && host != "127.0.0.1" {
			return nil, 0, fmt.Errorf("exchange base URL must use https")
		}
	}
	req, err := http.NewRequest(method, baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := exchangeNonce()
	req.Header.Set("X-HM-Node-Id", config.Exchange.NodeID)
	req.Header.Set("X-HM-Timestamp", timestamp)
	req.Header.Set("X-HM-Nonce", nonce)
	req.Header.Set("X-HM-Body-SHA256", exchangeBodyHash(body))
	req.Header.Set("X-HM-Signature", exchangeSignature(method, path, timestamp, nonce, body))
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := exchangeHTTPClient().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if err := verifyExchangeResponse(resp.StatusCode, resp.Header, data); err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode >= 400 {
		return data, resp.StatusCode, fmt.Errorf("exchange request failed: %s", strings.TrimSpace(string(data)))
	}
	return data, resp.StatusCode, nil
}

func verifyExchangeResponse(status int, headers http.Header, body []byte) error {
	timestamp := headers.Get("x-hm-response-timestamp")
	bodyHash := headers.Get("x-hm-response-body-sha256")
	signature := headers.Get("x-hm-response-signature")
	if timestamp == "" || bodyHash == "" || signature == "" {
		return fmt.Errorf("unsigned_exchange_response")
	}
	parsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return fmt.Errorf("invalid_exchange_response_timestamp")
	}
	if mathAbsDuration(time.Since(parsed)) > 5*time.Minute {
		return fmt.Errorf("stale_exchange_response")
	}
	if exchangeBodyHash(body) != bodyHash {
		return fmt.Errorf("exchange_response_body_mismatch")
	}
	if !hmac.Equal([]byte(exchangeResponseSignature(status, timestamp, bodyHash)), []byte(signature)) {
		return fmt.Errorf("invalid_exchange_response_signature")
	}
	return nil
}

func mathAbsDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func setExchangeStatus(format string, args ...interface{}) {
	exchangeStatusMu.Lock()
	exchangeStatusText = fmt.Sprintf(format, args...)
	exchangeStatusMu.Unlock()
}

func exchangeStatusSnapshot() (string, string, string, string) {
	exchangeStatusMu.Lock()
	defer exchangeStatusMu.Unlock()
	status := exchangeStatusText
	lastPush := ""
	lastPull := ""
	lastHeartbeat := ""
	if !exchangeLastPush.IsZero() {
		lastPush = exchangeLastPush.Format(time.RFC3339)
	}
	if !exchangeLastPull.IsZero() {
		lastPull = exchangeLastPull.Format(time.RFC3339)
	}
	if !exchangeLastHeartbeat.IsZero() {
		lastHeartbeat = exchangeLastHeartbeat.Format(time.RFC3339)
	}
	return status, lastPush, lastPull, lastHeartbeat
}

func normalizeClusterIDs(input []string) []string {
	out := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, raw := range input {
		clusterID := strings.TrimSpace(raw)
		if !validClusterID(clusterID) {
			continue
		}
		if _, ok := seen[clusterID]; ok {
			continue
		}
		seen[clusterID] = struct{}{}
		out = append(out, clusterID)
	}
	return out
}

func exchangeTrustedCluster(clusterID string) bool {
	trusted := normalizeClusterIDs(config.Exchange.TrustedClusters)
	if len(trusted) == 0 {
		return true
	}
	clusterID = strings.TrimSpace(clusterID)
	if clusterID == "" {
		return false
	}
	for _, allowed := range trusted {
		if allowed == clusterID {
			return true
		}
	}
	return false
}

func recordObservedExchangeCluster(clusterID string) {
	clusterID = strings.TrimSpace(clusterID)
	if !validClusterID(clusterID) {
		return
	}
	exchangeStatusMu.Lock()
	exchangeObservedClusters[clusterID] = time.Now().UTC()
	exchangeStatusMu.Unlock()
}

func validClusterID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i, r := range id {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		if i > 0 && (r == '-' || r == '_' || r == '.' || r == ':') {
			continue
		}
		return false
	}
	return true
}

type exchangeClusterView struct {
	ClusterID string `json:"cluster_id"`
	LastSeen  string `json:"last_seen"`
	Trusted   bool   `json:"trusted"`
}

func exchangeClusterSnapshot() []exchangeClusterView {
	exchangeStatusMu.Lock()
	defer exchangeStatusMu.Unlock()

	now := time.Now().UTC()
	for clusterID, ts := range exchangeObservedClusters {
		if now.Sub(ts) > 24*time.Hour {
			delete(exchangeObservedClusters, clusterID)
		}
	}

	combined := make(map[string]time.Time, len(exchangeObservedClusters)+len(config.Exchange.TrustedClusters)+1)
	for clusterID, ts := range exchangeObservedClusters {
		combined[clusterID] = ts
	}
	localCluster := strings.TrimSpace(license.GetOrGenerateClusterID())
	for _, clusterID := range normalizeClusterIDs(config.Exchange.TrustedClusters) {
		if localCluster != "" && clusterID == localCluster {
			continue
		}
		if _, ok := combined[clusterID]; !ok {
			combined[clusterID] = time.Time{}
		}
	}

	out := make([]exchangeClusterView, 0, len(combined))
	for clusterID, ts := range combined {
		if localCluster != "" && clusterID == localCluster {
			continue
		}
		lastSeen := ""
		if !ts.IsZero() {
			lastSeen = ts.Format(time.RFC3339)
		}
		out = append(out, exchangeClusterView{
			ClusterID: clusterID,
			LastSeen:  lastSeen,
			Trusted:   exchangeTrustedCluster(clusterID),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Trusted != out[j].Trusted {
			return out[i].Trusted
		}
		return out[i].ClusterID < out[j].ClusterID
	})
	return out
}

func exchangeConnected() bool {
	if !config.Exchange.Enabled || !exchangeConfigured() || !trustedNetworkSharingEnabled() {
		return false
	}
	exchangeStatusMu.Lock()
	lastHeartbeat := exchangeLastHeartbeat
	lastPull := exchangeLastPull
	exchangeStatusMu.Unlock()

	interval := time.Duration(config.Exchange.PullIntervalS) * time.Second
	if interval <= 0 {
		interval = defaultExchangePullInterval * time.Second
	}
	maxAge := interval * 2
	if maxAge < 10*time.Minute {
		maxAge = 10 * time.Minute
	}
	now := time.Now().UTC()
	if !lastHeartbeat.IsZero() && now.Sub(lastHeartbeat) <= maxAge {
		return true
	}
	return !lastPull.IsZero() && now.Sub(lastPull) <= maxAge
}

func machineFingerprint() string {
	host, _ := os.Hostname()
	if host == "" {
		host = config.NodeName
	}
	sum := sha256.Sum256([]byte(host + "|" + config.BindIP + "|" + config.MeshPort))
	return hex.EncodeToString(sum[:16])
}

func exchangeBaseURL() string {
	if base := strings.TrimRight(strings.TrimSpace(config.Exchange.BaseURL), "/"); base != "" {
		return base
	}
	if env := strings.TrimRight(strings.TrimSpace(os.Getenv("HM_NETTOOLS_URL")), "/"); env != "" {
		return env
	}
	return defaultExchangeBaseURL
}

func exchangeBootstrapBaseURLs() []string {
	candidates := []string{
		strings.TrimRight(strings.TrimSpace(config.Exchange.BaseURL), "/"),
		strings.TrimRight(strings.TrimSpace(os.Getenv("HM_NETTOOLS_URL")), "/"),
		defaultExchangeBaseURL,
		fallbackExchangeBaseURL,
	}
	out := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, base := range candidates {
		if base == "" {
			continue
		}
		if _, ok := seen[base]; ok {
			continue
		}
		seen[base] = struct{}{}
		out = append(out, base)
	}
	return out
}

func readLocalLicenseJSON() (string, error) {
	data, err := os.ReadFile("license.json")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func buildExactLicensePayload(clusterID, expiresAt string, maxNodes int, tier string) string {
	return fmt.Sprintf("%s|%s|%d|%s", strings.TrimSpace(clusterID), strings.TrimSpace(expiresAt), maxNodes, strings.ToUpper(license.NormalizeTier(tier)))
}

func verifiedExchangeLicenseClaim() (exchangeVerifiedLicenseClaim, string, error) {
	rawLicenseJSON, err := readLocalLicenseJSON()
	if err != nil {
		return exchangeVerifiedLicenseClaim{}, "", err
	}

	var raw struct {
		ClusterID string `json:"cluster_id"`
		ExpiresAt string `json:"expires_at"`
		MaxNodes  int    `json:"max_nodes"`
		Tier      string `json:"tier"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal([]byte(rawLicenseJSON), &raw); err != nil {
		return exchangeVerifiedLicenseClaim{}, "", err
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(raw.ExpiresAt))
	if err != nil {
		return exchangeVerifiedLicenseClaim{}, "", fmt.Errorf("invalid license expiry: %w", err)
	}
	lf := &license.LicenseFile{
		ClusterID: strings.TrimSpace(raw.ClusterID),
		ExpiresAt: expiresAt,
		MaxNodes:  raw.MaxNodes,
		Tier:      strings.TrimSpace(raw.Tier),
		Signature: strings.TrimSpace(raw.Signature),
	}
	if err := license.VerifyLicense(lf); err != nil {
		return exchangeVerifiedLicenseClaim{}, "", err
	}

	tier := strings.ToUpper(license.NormalizeTier(raw.Tier))
	return exchangeVerifiedLicenseClaim{
		Payload:   buildExactLicensePayload(raw.ClusterID, raw.ExpiresAt, raw.MaxNodes, raw.Tier),
		Signature: strings.TrimSpace(raw.Signature),
		ClusterID: strings.TrimSpace(raw.ClusterID),
		ExpiresAt: strings.TrimSpace(raw.ExpiresAt),
		MaxNodes:  raw.MaxNodes,
		Tier:      tier,
	}, rawLicenseJSON, nil
}

func bootstrapExchangeFromLicense() error {
	licenseClaim, licenseJSON, err := verifiedExchangeLicenseClaim()
	if err != nil {
		return fmt.Errorf("license.json required for NetTools bootstrap: %w", err)
	}
	ident := currentNodeIdentity()
	payload := map[string]interface{}{
		"id":                 ident.NodeID,
		"nodeName":           config.NodeName,
		"clusterId":          license.GetOrGenerateClusterID(),
		"publicKey":          base64.StdEncoding.EncodeToString(ident.PublicKey),
		"softwareVersion":    Version,
		"machineFingerprint": machineFingerprint(),
		"trustLevel":         75,
		"licenseJson":        json.RawMessage(licenseJSON),
		"licensePayload":     licenseClaim.Payload,
		"licenseSignature":   licenseClaim.Signature,
		"licenseClaim":       licenseClaim,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var (
		out       exchangeBootstrapResponse
		usedBase  string
		lastError error
	)
	for _, baseURL := range exchangeBootstrapBaseURLs() {
		for attempt := 0; attempt < 3; attempt++ {
			req, err := http.NewRequest(http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/hm/bootstrap", bytes.NewReader(body))
			if err != nil {
				lastError = err
				break
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := exchangeHTTPClient().Do(req)
			if err != nil {
				lastError = err
				if attempt < 2 {
					time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
					continue
				}
				break
			}
			raw, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				lastError = readErr
				if attempt < 2 {
					time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
					continue
				}
				break
			}
			if resp.StatusCode >= 400 {
				lastError = fmt.Errorf("machine bootstrap failed: %s", strings.TrimSpace(string(raw)))
				break
			}
			if err := json.Unmarshal(raw, &out); err != nil {
				lastError = err
				break
			}
			usedBase = baseURL
			lastError = nil
			break
		}
		if lastError == nil {
			break
		}
	}
	if lastError != nil {
		return lastError
	}
	if strings.TrimSpace(out.NodeID) == "" || strings.TrimSpace(out.Secret) == "" {
		return fmt.Errorf("bootstrap response missing node credentials")
	}
	config.Exchange.Enabled = true
	config.Exchange.BaseURL = strings.TrimRight(strings.TrimSpace(out.APIBaseURL), "/")
	if config.Exchange.BaseURL == "" {
		config.Exchange.BaseURL = strings.TrimRight(usedBase, "/")
	}
	config.Exchange.NodeID = strings.TrimSpace(out.NodeID)
	config.Exchange.TenantID = strings.TrimSpace(out.TenantID)
	config.Exchange.SharedSecret = strings.TrimSpace(out.Secret)
	if config.Exchange.PullIntervalS <= 0 {
		config.Exchange.PullIntervalS = defaultExchangePullInterval
	}
	config.Exchange.PushLocalBans = true
	config.Exchange.PullSharedFeed = true
	if config.Exchange.TrustThreshold <= 0 {
		config.Exchange.TrustThreshold = defaultExchangeTrustThreshold
	}
	config.Exchange.LastRegistered = time.Now().UTC().Format(time.RFC3339)
	saveConfig()
	setExchangeStatus("Machine-registered with NetTools.cloud as %s", config.Exchange.NodeID)
	return nil
}

func registerWithExchange(baseURL, enrollToken string) error {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	enrollToken = strings.TrimSpace(enrollToken)
	if baseURL == "" || enrollToken == "" {
		return fmt.Errorf("exchange URL and enrollment token are required")
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" ||
		(parsedURL.Scheme != "https" && !(parsedURL.Scheme == "http" && (parsedURL.Hostname() == "localhost" || parsedURL.Hostname() == "127.0.0.1"))) {
		return fmt.Errorf("exchange enrollment requires an HTTPS URL (HTTP is allowed only on loopback)")
	}
	ident := currentNodeIdentity()
	payload := map[string]interface{}{
		"id":                 ident.NodeID,
		"nodeName":           config.NodeName,
		"clusterId":          license.GetOrGenerateClusterID(),
		"enrollToken":        enrollToken,
		"publicKey":          base64.StdEncoding.EncodeToString(ident.PublicKey),
		"softwareVersion":    Version,
		"machineFingerprint": machineFingerprint(),
		"trustLevel":         75,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/hm/enroll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := exchangeHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("registration failed: %s", strings.TrimSpace(string(raw)))
	}
	var out exchangeRegisterResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	if strings.TrimSpace(out.NodeID) == "" || strings.TrimSpace(out.Secret) == "" {
		return fmt.Errorf("registration response missing node credentials")
	}
	config.Exchange.Enabled = true
	config.Exchange.BaseURL = strings.TrimRight(strings.TrimSpace(out.APIBaseURL), "/")
	if config.Exchange.BaseURL == "" {
		config.Exchange.BaseURL = baseURL
	}
	config.Exchange.NodeID = strings.TrimSpace(out.NodeID)
	config.Exchange.TenantID = strings.TrimSpace(out.TenantID)
	config.Exchange.SharedSecret = strings.TrimSpace(out.Secret)
	config.Exchange.PullIntervalS = defaultExchangePullInterval
	config.Exchange.PushLocalBans = true
	config.Exchange.PullSharedFeed = true
	config.Exchange.TrustThreshold = defaultExchangeTrustThreshold
	config.Exchange.LastRegistered = time.Now().UTC().Format(time.RFC3339)
	saveConfig()
	setExchangeStatus("Registered with NetTools.cloud as %s", config.Exchange.NodeID)
	return nil
}

func startExchangeSyncLoop(shutdown chan struct{}) {
	interval := time.Duration(config.Exchange.PullIntervalS) * time.Second
	if interval <= 0 {
		interval = defaultExchangePullInterval * time.Second
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			syncNetToolsExchange()
			timer.Reset(exchangePollDelay(interval))
		case <-shutdown:
			return
		}
	}
}

func exchangePollDelay(base time.Duration) time.Duration {
	if base <= 0 {
		base = defaultExchangePullInterval * time.Second
	}
	jitter := base / 5
	if jitter < 5*time.Second {
		jitter = 5 * time.Second
	}
	if jitter > 30*time.Second {
		jitter = 30 * time.Second
	}
	offset := time.Duration(mrand.Int63n(int64(jitter*2)+1)) - jitter
	delay := base + offset
	if delay < 15*time.Second {
		return 15 * time.Second
	}
	return delay
}

func syncNetToolsExchange() {
	if !config.Exchange.Enabled {
		releaseExchangeRulesWhenDisabled()
		setExchangeStatus("NetTools.cloud integration is disabled.")
		return
	}
	if !exchangeConfigured() {
		releaseExchangeRulesWhenDisabled()
		setExchangeStatus("NetTools.cloud is not registered on this node.")
		return
	}
	if !trustedNetworkSharingEnabled() {
		releaseExchangeRulesWhenDisabled()
		setExchangeStatus("NetTools.cloud sharing is off.")
		return
	}
	if err := pushExchangeHeartbeat(); err != nil {
		setExchangeStatus("NetTools.cloud heartbeat failed: %v", err)
		return
	}
	cfg, err := pullExchangeConfig()
	if err != nil {
		setExchangeStatus("NetTools.cloud config sync failed: %v", err)
		return
	}
	if cfg.ExchangeKillSwitch || !cfg.SharingEnabled || cfg.LicenseStatus != "active" || (cfg.Plan != "pro" && cfg.Plan != "community") {
		releaseExchangeRulesWhenDisabled()
		setExchangeStatus("NetTools.cloud sharing unavailable for tenant.")
		return
	}
	if cfg.ReviewOnlyMode || cfg.Plan == "community" {
		releaseExchangeRulesWhenDisabled()
	}
	if config.Exchange.PullSharedFeed {
		if err := pullExchangeFeed(cfg.ReviewOnlyMode || cfg.Plan == "community"); err != nil {
			setExchangeStatus("NetTools.cloud feed pull failed: %v", err)
			return
		}
	}
	if !config.Exchange.PullSharedFeed {
		releaseExchangeRulesWhenDisabled()
	}
	setExchangeStatus("NetTools.cloud sharing active.")
}

func releaseExchangeRulesWhenDisabled() {
	if liveExchangeRules != nil {
		if err := liveExchangeRules.releaseAll(); err != nil {
			log.Printf("[EXCHANGE] failed to release disabled shared rules: %v", err)
		}
	}
}

func pushExchangeHeartbeat() error {
	body, _ := json.Marshal(map[string]string{"status": "online"})
	_, _, err := doExchangeRequest(http.MethodPost, "/api/hm/heartbeat", body)
	if err != nil {
		return err
	}
	exchangeStatusMu.Lock()
	exchangeLastHeartbeat = time.Now().UTC()
	exchangeStatusMu.Unlock()
	return nil
}

func pullExchangeConfig() (exchangeConfigResponse, error) {
	var out exchangeConfigResponse
	body, _, err := doExchangeRequest(http.MethodGet, "/api/hm/config", nil)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	return out, nil
}

func reconcileExchangeSnapshot() error {
	values := url.Values{}
	values.Set("trustThreshold", strconv.Itoa(config.Exchange.TrustThreshold))
	body, _, err := doExchangeRequest(http.MethodGet, "/api/hm/attack-snapshot?"+values.Encode(), nil)
	if err != nil {
		return err
	}
	var snapshot exchangeSnapshotResponse
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return err
	}
	asOf, err := time.Parse(time.RFC3339Nano, snapshot.AsOf)
	if err != nil || mathAbsDuration(time.Since(asOf)) > 5*time.Minute || !snapshot.Complete || len(snapshot.Records) > 2500 || snapshot.RetractionCursor < 0 {
		return errors.New("Exchange snapshot is incomplete or invalid")
	}
	if err := liveExchangeRules.reconcileSnapshot(snapshot.Records); err != nil {
		return err
	}
	config.Exchange.FeedCursor = snapshot.Cursor
	config.Exchange.RetractionCursor = snapshot.RetractionCursor
	if !saveConfig() {
		return errors.New("Exchange snapshot cursors could not be saved")
	}
	return nil
}

func pullExchangeFeed(reviewOnly bool) error {
	if liveExchangeRules == nil {
		return errors.New("Exchange rule ownership unavailable")
	}
	if err := liveExchangeRules.reconcileTrust(); err != nil {
		return err
	}
	if Mode() == ModeEnforce && !reviewOnly {
		if err := reconcileExchangeSnapshot(); err != nil {
			return err
		}
	}
	values := url.Values{}
	values.Set("trustThreshold", strconv.Itoa(config.Exchange.TrustThreshold))
	values.Set("limit", "64")
	values.Set("retractionAfter", strconv.FormatInt(config.Exchange.RetractionCursor, 10))
	if strings.TrimSpace(config.Exchange.FeedCursor) != "" {
		values.Set("after", strings.TrimSpace(config.Exchange.FeedCursor))
	}
	query := "/api/hm/attack-feed?" + values.Encode()
	body, _, err := doExchangeRequest(http.MethodGet, query, nil)
	if err != nil {
		return err
	}
	var out exchangeFeedResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return err
	}
	lastRetraction := config.Exchange.RetractionCursor
	changed := false
	for _, event := range out.Retractions {
		if event.Seq <= lastRetraction || event.Seq > out.RetractionCursor {
			return errors.New("Exchange retraction sequence is invalid")
		}
		if err := liveExchangeRules.retract(event); err != nil {
			return err
		}
		lastRetraction = event.Seq
		changed = true
	}
	for _, record := range out.MergedFeed {
		recordObservedExchangeCluster(record.ClusterID)
		if !shouldApplyExchangeRecord(record) {
			continue
		}
		ttl := time.Duration(record.TTL) * time.Second
		if ttl <= 0 || ttl > maxExchangeTTL {
			ttl = getBanDuration()
		}
		if Mode() == ModeEnforce && !reviewOnly {
			if err := liveExchangeRules.applyRecord(record, ttl); err != nil {
				return err
			}
			changed = true
		}
		rememberExchangeFeedRecord(record.ID)
	}
	needsSave := false
	if lastRetraction != config.Exchange.RetractionCursor {
		config.Exchange.RetractionCursor = lastRetraction
		needsSave = true
	}
	if strings.TrimSpace(out.Cursor) != "" && out.Cursor != config.Exchange.FeedCursor {
		config.Exchange.FeedCursor = out.Cursor
		needsSave = true
	}
	if needsSave {
		if !saveConfig() {
			return errors.New("Exchange feed cursors could not be saved")
		}
	}
	if changed {
		broadcastBans()
	}
	exchangeStatusMu.Lock()
	exchangeLastPull = time.Now().UTC()
	exchangeStatusMu.Unlock()
	return nil
}

func shouldApplyExchangeRecord(record exchangeFeedRecord) bool {
	if !exchangeRecordEligible(record) {
		return false
	}
	id := strings.TrimSpace(record.ID)
	exchangeStatusMu.Lock()
	defer exchangeStatusMu.Unlock()
	now := time.Now()
	for k, ts := range exchangeSeenFeed {
		if now.Sub(ts) > 30*time.Minute {
			delete(exchangeSeenFeed, k)
		}
	}
	_, seen := exchangeSeenFeed[id]
	return !seen
}

func exchangeRecordEligible(record exchangeFeedRecord) bool {
	id := strings.TrimSpace(record.ID)
	if id == "" || strings.TrimSpace(record.AttackerIP) == "" || record.Status != "approved" {
		return false
	}
	if !exchangeTrustedCluster(record.ClusterID) {
		return false
	}
	if isWhitelisted(record.AttackerIP) || isExchangeLocalIP(record.AttackerIP) {
		return false
	}
	return true
}

func rememberExchangeFeedRecord(id string) {
	if strings.TrimSpace(id) == "" {
		return
	}
	exchangeStatusMu.Lock()
	exchangeSeenFeed[id] = time.Now()
	exchangeStatusMu.Unlock()
}

func isExchangeLocalIP(ip string) bool {
	ip = normalizeIPKey(ip)
	if ip == "" {
		return false
	}
	switch ip {
	case "127.0.0.1", "::1":
		return true
	}
	return ip == normalizeIPKey(config.BindIP)
}

func shouldPublishExchangeBan(key string, ttl time.Duration) bool {
	exchangeStatusMu.Lock()
	defer exchangeStatusMu.Unlock()
	now := time.Now()
	window := ttl
	if window <= 0 || window > 30*time.Minute {
		window = 30 * time.Minute
	}
	for k, ts := range exchangePublished {
		if now.Sub(ts) > window {
			delete(exchangePublished, k)
		}
	}
	if ts, ok := exchangePublished[key]; ok && now.Sub(ts) <= window {
		return false
	}
	exchangePublished[key] = now
	return true
}

func publishNetToolsBan(ip, targetIP, target, service, category, reason string, meta BanMeta, duration time.Duration) {
	if !exchangeEnabled() || !config.Exchange.PushLocalBans {
		return
	}
	key := strings.Join([]string{normalizeIPKey(ip), strings.TrimSpace(category), strings.TrimSpace(reason)}, "|")
	if !shouldPublishExchangeBan(key, duration) {
		return
	}
	port := parseExchangePort(target)
	protocol := strings.ToLower(strings.TrimSpace(service))
	if protocol != "tcp" && protocol != "udp" {
		protocol = "tcp"
	}
	actionTaken := "temporary_ban"
	mode := "auto_temp"
	if duration >= time.Hour || strings.Contains(strings.ToUpper(category), "WATCHDOG") || strings.Contains(strings.ToUpper(category), "JA4") {
		actionTaken = "high_confidence_ban"
		mode = "auto_high_confidence"
	}
	body, err := json.Marshal(map[string]interface{}{
		"id":            fmt.Sprintf("%s-%d", strings.ToLower(strings.TrimSpace(category)), time.Now().UnixNano()),
		"attackerIp":    normalizeIPKey(ip),
		"cidr":          nil,
		"ja4":           meta.JA4,
		"ja3Legacy":     meta.JA3,
		"attackType":    strings.ToLower(strings.TrimSpace(category)),
		"protocol":      protocol,
		"port":          port,
		"service":       protocol,
		"confidence":    exchangeConfidence(category, duration),
		"reason":        reason,
		"ttl":           boundedExchangeTTL(duration),
		"sourceChannel": "local",
		"actionTaken":   actionTaken,
		"mode":          mode,
		"evidence": map[string]interface{}{
			"evidenceLevel": "sanitized",
			"payloadShared": false,
		},
	})
	if err != nil {
		log.Printf("[NETTOOLS] Failed to encode publish body: %v", err)
		return
	}
	if _, _, err := doExchangeRequest(http.MethodPost, "/api/hm/publish-ban", body); err != nil {
		log.Printf("[NETTOOLS] Publish failed ip=%s err=%v", ip, err)
		return
	}
	exchangeStatusMu.Lock()
	exchangeLastPush = time.Now().UTC()
	exchangeStatusMu.Unlock()
}

func boundedExchangeTTL(duration time.Duration) int {
	if duration <= 0 {
		duration = 5 * time.Minute
	}
	if duration > maxExchangeTTL {
		duration = maxExchangeTTL
	}
	seconds := int(duration.Seconds())
	if seconds < 60 {
		return 60
	}
	return seconds
}

func exchangeConfidence(category string, duration time.Duration) float64 {
	score := 65.0
	switch strings.ToUpper(strings.TrimSpace(category)) {
	case "WATCHDOG":
		score = 96
	case "TRAP_HIT":
		score = 92
	case "JA4_MATCH", "JA3_MATCH":
		score = 88
	case "PORT_SCAN":
		score = 82
	case "HIGH_ENTROPY":
		score = 76
	}
	if duration >= time.Hour && score < 90 {
		score += 8
	}
	if score > 99 {
		score = 99
	}
	return score
}

func parseExchangePort(target string) int {
	target = strings.TrimSpace(target)
	if target == "" || target == "multi-port" {
		return 0
	}
	if n, err := strconv.Atoi(target); err == nil && n >= 0 && n <= 65535 {
		return n
	}
	return 0
}
