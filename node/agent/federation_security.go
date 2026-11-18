package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"honeymesh/internal/license"
	"honeymesh/internal/mesh"
)

const (
	federationSchemaVersion = "v2"
	defaultReplayWindow     = 5 * time.Minute
	defaultMeshRatePerMin   = 120
	defaultMeshBurst        = 20
	federationAuditLimit    = 128
)

type nodeIdentityFile struct {
	Version    string `json:"version"`
	NodeID     string `json:"node_id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	CreatedAt  string `json:"created_at"`
}

type federationAuditEntry struct {
	Timestamp string `json:"timestamp"`
	Peer      string `json:"peer"`
	Publisher string `json:"publisher"`
	Reason    string `json:"reason"`
	Accepted  bool   `json:"accepted"`
}

type federationLimiter struct {
	Minute []time.Time
	Burst  []time.Time
}

type nodeIdentityState struct {
	NodeID     string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

var (
	nodeIdentityMu sync.RWMutex
	nodeIdentity   nodeIdentityState

	federationAuditMu sync.Mutex
	federationAudit   []federationAuditEntry

	federationReplayMu sync.Mutex
	federationReplay   = make(map[string]map[string]time.Time)

	federationLimitMu sync.Mutex
	federationLimit   = make(map[string]*federationLimiter)

	federationAccepted     atomic.Uint64
	federationRejected     atomic.Uint64
	federationContributed  atomic.Uint64
	federationRejectReason = map[string]uint64{}
)

var (
	federationNow          = time.Now
	verifyPeerLicenseClaim = defaultVerifyPeerLicenseClaim
)

func initNodeIdentityStore() error {
	ident, err := loadOrCreateNodeIdentity()
	if err != nil {
		return err
	}
	setNodeIdentity(ident)
	return nil
}

func regenerateNodeIdentityStore() error {
	ident, err := newRandomNodeIdentity()
	if err != nil {
		return err
	}
	if err := saveNodeIdentityFile(ident); err != nil {
		return err
	}
	setNodeIdentity(ident)
	return nil
}

func setNodeIdentity(ident nodeIdentityState) {
	nodeIdentityMu.Lock()
	nodeIdentity = ident
	nodeIdentityMu.Unlock()
}

func currentNodeIdentity() nodeIdentityState {
	nodeIdentityMu.RLock()
	defer nodeIdentityMu.RUnlock()
	return nodeIdentity
}

func nodeIdentityReady() bool {
	ident := currentNodeIdentity()
	return ident.NodeID != "" && len(ident.PublicKey) == ed25519.PublicKeySize && len(ident.PrivateKey) == ed25519.PrivateKeySize
}

func loadOrCreateNodeIdentity() (nodeIdentityState, error) {
	data, err := os.ReadFile("identity.key")
	if err != nil {
		if os.IsNotExist(err) {
			ident, err := newRandomNodeIdentity()
			if err != nil {
				return nodeIdentityState{}, err
			}
			if err := saveNodeIdentityFile(ident); err != nil {
				return nodeIdentityState{}, err
			}
			return ident, nil
		}
		return nodeIdentityState{}, err
	}

	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return nodeIdentityState{}, fmt.Errorf("empty identity file")
	}

	var disk nodeIdentityFile
	if err := json.Unmarshal(data, &disk); err == nil && disk.Version != "" {
		return parseNodeIdentityFile(disk)
	}

	ident, err := migrateLegacyIdentity(raw)
	if err != nil {
		return nodeIdentityState{}, err
	}
	if err := saveNodeIdentityFile(ident); err != nil {
		return nodeIdentityState{}, err
	}
	return ident, nil
}

func parseNodeIdentityFile(disk nodeIdentityFile) (nodeIdentityState, error) {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(disk.PublicKey))
	if err != nil {
		return nodeIdentityState{}, fmt.Errorf("decode public key: %w", err)
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(disk.PrivateKey))
	if err != nil {
		return nodeIdentityState{}, fmt.Errorf("decode private key: %w", err)
	}
	ident := nodeIdentityState{
		NodeID:     strings.TrimSpace(disk.NodeID),
		PublicKey:  ed25519.PublicKey(pub),
		PrivateKey: ed25519.PrivateKey(priv),
	}
	if err := validateNodeIdentity(ident); err != nil {
		return nodeIdentityState{}, err
	}
	return ident, nil
}

func migrateLegacyIdentity(raw string) (nodeIdentityState, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(decoded) == 0 {
		return nodeIdentityState{}, fmt.Errorf("invalid legacy identity format")
	}
	seed := sha256.Sum256(decoded)
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return nodeIdentityState{
		NodeID:     deriveNodeID(pub),
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

func newRandomNodeIdentity() (nodeIdentityState, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nodeIdentityState{}, err
	}
	return nodeIdentityState{
		NodeID:     deriveNodeID(pub),
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

func saveNodeIdentityFile(ident nodeIdentityState) error {
	if err := validateNodeIdentity(ident); err != nil {
		return err
	}
	payload := nodeIdentityFile{
		Version:    federationSchemaVersion,
		NodeID:     ident.NodeID,
		PublicKey:  base64.StdEncoding.EncodeToString(ident.PublicKey),
		PrivateKey: base64.StdEncoding.EncodeToString(ident.PrivateKey),
		CreatedAt:  federationNow().UTC().Format(time.RFC3339),
	}
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("identity.key", body, 0600)
}

func validateNodeIdentity(ident nodeIdentityState) error {
	if ident.NodeID == "" {
		return fmt.Errorf("missing node id")
	}
	if len(ident.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key")
	}
	if len(ident.PrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key")
	}
	if deriveNodeID(ident.PublicKey) != ident.NodeID {
		return fmt.Errorf("node id mismatch")
	}
	return nil
}

func deriveNodeID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "node_" + hex.EncodeToString(sum[:16])
}

func currentPeerCapability() mesh.PeerCapability {
	ident := currentNodeIdentity()
	cap := mesh.PeerCapability{
		SchemaVersion:         federationSchemaVersion,
		NodeID:                ident.NodeID,
		TenantID:              license.GetOrGenerateClusterID(),
		ClusterID:             license.GetOrGenerateClusterID(),
		LicenseTier:           effectiveLicenseTier(),
		TrustedNetworkSharing: trustedMeshNetworkEnabled(),
		PublicKey:             base64.StdEncoding.EncodeToString(ident.PublicKey),
		Capabilities:          []string{"local_protection", "ja4_intelligence"},
	}
	if trustedMeshNetworkEnabled() {
		cap.Capabilities = append(cap.Capabilities, "trusted_network_sharing")
	}
	if lf, err := license.Load("license.json"); err == nil && premiumFeaturesEnabled() {
		cap.ClusterID = lf.ClusterID
		cap.TenantID = lf.ClusterID
		cap.LicenseTier = license.NormalizeTier(lf.Tier)
		cap.LicenseExpiresAt = lf.ExpiresAt.UTC().Format(time.RFC3339)
		cap.LicenseMaxNodes = lf.MaxNodes
		cap.LicenseSignature = lf.Signature
	}
	return cap
}

func validatePeerCapability(cap mesh.PeerCapability) error {
	reason := ""
	switch {
	case cap.SchemaVersion != federationSchemaVersion:
		reason = "schema_mismatch"
	case strings.TrimSpace(cap.NodeID) == "":
		reason = "invalid_publisher_identity"
	case !cap.TrustedNetworkSharing:
		reason = "sharing_disabled"
	case !containsString(cap.Capabilities, "trusted_network_sharing"):
		reason = "invalid_license"
	}
	if reason != "" {
		recordFederationReject("", cap.NodeID, reason)
		return errors.New(reason)
	}

	pub, err := decodeCapabilityPublicKey(cap)
	if err != nil {
		recordFederationReject("", cap.NodeID, "invalid_publisher_identity")
		return fmt.Errorf("invalid_publisher_identity")
	}
	if deriveNodeID(pub) != cap.NodeID {
		recordFederationReject("", cap.NodeID, "invalid_publisher_identity")
		return fmt.Errorf("invalid_publisher_identity")
	}
	if err := verifyPeerLicenseClaim(cap); err != nil {
		recordFederationReject("", cap.NodeID, "invalid_license")
		return fmt.Errorf("invalid_license")
	}
	return nil
}

func defaultVerifyPeerLicenseClaim(cap mesh.PeerCapability) error {
	localCluster := strings.TrimSpace(license.GetOrGenerateClusterID())
	peerCluster := strings.TrimSpace(cap.ClusterID)
	if localCluster == "" || peerCluster == "" {
		return fmt.Errorf("cluster identity required")
	}
	if peerCluster != localCluster && !trustedMeshNetworkClusterAllowed(peerCluster) {
		return fmt.Errorf("cluster mismatch")
	}
	if license.NormalizeTier(cap.LicenseTier) == license.TierFree {
		// Community peers use operator-managed mTLS trust and signed signals.
		// A legacy publisher license is unnecessary for self-hosted mesh.
		return nil
	}
	expiresAt, err := time.Parse(time.RFC3339, cap.LicenseExpiresAt)
	if err != nil {
		return fmt.Errorf("invalid license expiry")
	}
	lf := &license.LicenseFile{
		ClusterID: peerCluster,
		ExpiresAt: expiresAt,
		MaxNodes:  cap.LicenseMaxNodes,
		Tier:      cap.LicenseTier,
		Signature: cap.LicenseSignature,
	}
	if err := license.VerifyLicense(lf); err != nil {
		return err
	}
	if !expiresAt.IsZero() && federationNow().After(expiresAt) {
		return fmt.Errorf("license expired")
	}
	return nil
}

func normalizeTrustedMeshNetworks(input []TrustedMeshNetwork) []TrustedMeshNetwork {
	out := make([]TrustedMeshNetwork, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, raw := range input {
		clusterID := strings.TrimSpace(raw.ClusterID)
		if !validClusterID(clusterID) {
			continue
		}
		level := raw.TrustLevel
		if level < trustLevel0 {
			level = trustLevel0
		}
		if level > trustLevel3 {
			level = trustLevel3
		}
		if _, ok := seen[clusterID]; ok {
			continue
		}
		seen[clusterID] = struct{}{}
		out = append(out, TrustedMeshNetwork{
			ClusterID:  clusterID,
			TrustLevel: level,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TrustLevel != out[j].TrustLevel {
			return out[i].TrustLevel > out[j].TrustLevel
		}
		return out[i].ClusterID < out[j].ClusterID
	})
	return out
}

func trustedMeshNetworkPolicy(clusterID string) (TrustedMeshNetwork, bool) {
	clusterID = strings.TrimSpace(clusterID)
	if clusterID == "" {
		return TrustedMeshNetwork{}, false
	}
	for _, network := range normalizeTrustedMeshNetworks(config.Mesh.TrustedNetworks) {
		if network.ClusterID == clusterID {
			return network, true
		}
	}
	return TrustedMeshNetwork{}, false
}

func trustedMeshNetworkClusterAllowed(clusterID string) bool {
	clusterID = strings.TrimSpace(clusterID)
	if clusterID == "" {
		return false
	}
	localCluster := strings.TrimSpace(license.GetOrGenerateClusterID())
	if localCluster == "" || clusterID == localCluster {
		return true
	}
	_, ok := trustedMeshNetworkPolicy(clusterID)
	return ok
}

func applyTrustedMeshNetworkPolicy(peer string, cap mesh.PeerCapability) {
	clusterID := strings.TrimSpace(cap.ClusterID)
	if clusterID == "" {
		return
	}
	localCluster := strings.TrimSpace(license.GetOrGenerateClusterID())
	if localCluster != "" && clusterID == localCluster {
		return
	}
	policy, ok := trustedMeshNetworkPolicy(clusterID)
	if !ok {
		return
	}
	peer = normalizePeerAddr(peer)
	if peer == "" {
		return
	}
	if policy.TrustLevel == trustLevel3 {
		addAuthoritativePeer(peer)
	} else {
		removeAuthoritativePeer(peer)
	}
	setTrustLevel(peer, policy.TrustLevel)
}

func prepareTrustedNetworkSignal(base mesh.BanSignal) (mesh.BanSignal, error) {
	if !trustedMeshNetworkEnabled() {
		return mesh.BanSignal{}, fmt.Errorf("sharing disabled")
	}
	ident := currentNodeIdentity()
	if err := validateNodeIdentity(ident); err != nil {
		return mesh.BanSignal{}, err
	}

	out := base
	out.SchemaVersion = federationSchemaVersion
	out.EventID = newFederationEventID()
	out.PublisherNodeID = ident.NodeID
	out.PublishedAt = federationNow().UTC().Format(time.RFC3339)
	out.DataClassification = selectedDataClassification()
	out.Capability = currentPeerCapability()
	out = applyDataClassification(out)

	sig, err := signBanSignal(ident.PrivateKey, out)
	if err != nil {
		return mesh.BanSignal{}, err
	}
	out.Signature = sig
	federationContributed.Add(1)
	return out, nil
}

func validateTrustedNetworkSignal(peer string, signal mesh.BanSignal) error {
	if signal.IP == "" {
		recordFederationReject(peer, signal.PublisherNodeID, "invalid_payload")
		return fmt.Errorf("invalid_payload")
	}
	if signal.SchemaVersion != federationSchemaVersion {
		recordFederationReject(peer, signal.PublisherNodeID, "schema_mismatch")
		return fmt.Errorf("schema_mismatch")
	}
	if err := validatePeerCapability(signal.Capability); err != nil {
		return err
	}
	if signal.PublisherNodeID == "" || signal.PublisherNodeID != signal.Capability.NodeID {
		recordFederationReject(peer, signal.PublisherNodeID, "invalid_publisher_identity")
		return fmt.Errorf("invalid_publisher_identity")
	}
	publishedAt, err := time.Parse(time.RFC3339, signal.PublishedAt)
	if err != nil {
		recordFederationReject(peer, signal.PublisherNodeID, "invalid_payload")
		return fmt.Errorf("invalid_payload")
	}
	if err := validateSignalFreshness(signal.PublisherNodeID, signal.EventID, publishedAt); err != nil {
		recordFederationReject(peer, signal.PublisherNodeID, err.Error())
		return err
	}
	if err := enforceSignalRateLimit(signal.PublisherNodeID, publishedAt); err != nil {
		recordFederationReject(peer, signal.PublisherNodeID, err.Error())
		return err
	}
	pub, err := decodeCapabilityPublicKey(signal.Capability)
	if err != nil {
		recordFederationReject(peer, signal.PublisherNodeID, "invalid_publisher_identity")
		return fmt.Errorf("invalid_publisher_identity")
	}
	if !verifyBanSignalSignature(pub, signal) {
		recordFederationReject(peer, signal.PublisherNodeID, "invalid_signature")
		return fmt.Errorf("invalid_signature")
	}
	recordFederationAccept(peer, signal.PublisherNodeID)
	return nil
}

func decodeCapabilityPublicKey(cap mesh.PeerCapability) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cap.PublicKey))
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length")
	}
	return ed25519.PublicKey(decoded), nil
}

func signBanSignal(priv ed25519.PrivateKey, signal mesh.BanSignal) (string, error) {
	payload, err := canonicalBanSignal(signal)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)), nil
}

func verifyBanSignalSignature(pub ed25519.PublicKey, signal mesh.BanSignal) bool {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signal.Signature))
	if err != nil || len(sig) == 0 {
		return false
	}
	payload, err := canonicalBanSignal(signal)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, payload, sig)
}

func canonicalBanSignal(signal mesh.BanSignal) ([]byte, error) {
	clone := signal
	clone.Signature = ""
	type canonicalSignal struct {
		SchemaVersion      string              `json:"schema_version"`
		EventID            string              `json:"event_id"`
		PublisherNodeID    string              `json:"publisher_node_id"`
		PublishedAt        string              `json:"published_at"`
		DataClassification string              `json:"data_classification"`
		Capability         mesh.PeerCapability `json:"capability"`
		IP                 string              `json:"ip"`
		Reason             string              `json:"reason"`
		JA4                string              `json:"ja4"`
		JA3                string              `json:"ja3"`
		TargetIP           string              `json:"target_ip"`
		Target             string              `json:"target"`
		Service            string              `json:"service"`
		Category           string              `json:"category"`
		EventType          string              `json:"event_type"`
		Interface          string              `json:"interface"`
		Payload            string              `json:"payload"`
	}
	payload := canonicalSignal{
		SchemaVersion:      clone.SchemaVersion,
		EventID:            clone.EventID,
		PublisherNodeID:    clone.PublisherNodeID,
		PublishedAt:        clone.PublishedAt,
		DataClassification: clone.DataClassification,
		Capability:         normalizeCapability(clone.Capability),
		IP:                 clone.IP,
		Reason:             clone.Reason,
		JA4:                clone.JA4,
		JA3:                clone.JA3,
		TargetIP:           clone.TargetIP,
		Target:             clone.Target,
		Service:            clone.Service,
		Category:           clone.Category,
		EventType:          clone.EventType,
		Interface:          clone.Interface,
		Payload:            clone.Payload,
	}
	return json.Marshal(payload)
}

func normalizeCapability(cap mesh.PeerCapability) mesh.PeerCapability {
	out := cap
	out.SchemaVersion = strings.TrimSpace(out.SchemaVersion)
	out.NodeID = strings.TrimSpace(out.NodeID)
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.ClusterID = strings.TrimSpace(out.ClusterID)
	out.LicenseTier = license.NormalizeTier(out.LicenseTier)
	out.LicenseExpiresAt = strings.TrimSpace(out.LicenseExpiresAt)
	out.LicenseSignature = strings.TrimSpace(out.LicenseSignature)
	out.PublicKey = strings.TrimSpace(out.PublicKey)
	out.Capabilities = append([]string(nil), out.Capabilities...)
	sort.Strings(out.Capabilities)
	return out
}

func validateSignalFreshness(publisher, eventID string, publishedAt time.Time) error {
	if strings.TrimSpace(eventID) == "" {
		return fmt.Errorf("replay_detected")
	}
	now := federationNow()
	window := replayWindow()
	if publishedAt.Before(now.Add(-window)) || publishedAt.After(now.Add(window)) {
		return fmt.Errorf("replay_detected")
	}
	federationReplayMu.Lock()
	defer federationReplayMu.Unlock()
	pruneBefore := now.Add(-window)
	cache, ok := federationReplay[publisher]
	if !ok {
		cache = make(map[string]time.Time)
		federationReplay[publisher] = cache
	}
	for id, ts := range cache {
		if ts.Before(pruneBefore) {
			delete(cache, id)
		}
	}
	if _, exists := cache[eventID]; exists {
		return fmt.Errorf("replay_detected")
	}
	cache[eventID] = publishedAt
	return nil
}

func enforceSignalRateLimit(publisher string, _ time.Time) error {
	perMinute := meshEventRateLimitPerMin()
	burst := meshEventBurst()
	now := federationNow()

	federationLimitMu.Lock()
	defer federationLimitMu.Unlock()

	limiter := federationLimit[publisher]
	if limiter == nil {
		limiter = &federationLimiter{}
		federationLimit[publisher] = limiter
	}
	minuteCutoff := now.Add(-time.Minute)
	burstCutoff := now.Add(-10 * time.Second)
	limiter.Minute = trimTimes(limiter.Minute, minuteCutoff)
	limiter.Burst = trimTimes(limiter.Burst, burstCutoff)
	if len(limiter.Minute) >= perMinute || len(limiter.Burst) >= burst {
		return fmt.Errorf("rate_limit_exceeded")
	}
	limiter.Minute = append(limiter.Minute, now)
	limiter.Burst = append(limiter.Burst, now)
	return nil
}

func trimTimes(values []time.Time, cutoff time.Time) []time.Time {
	if len(values) == 0 {
		return values
	}
	out := values[:0]
	for _, ts := range values {
		if !ts.Before(cutoff) {
			out = append(out, ts)
		}
	}
	return out
}

func selectedDataClassification() string {
	level := strings.ToUpper(strings.TrimSpace(config.Security.MeshDataClassification))
	switch level {
	case "L1", "L2", "L3", "L4":
		return level
	default:
		return "L2"
	}
}

func applyDataClassification(signal mesh.BanSignal) mesh.BanSignal {
	signal.Payload = sanitizePayload([]byte(signal.Payload), 200)
	switch strings.ToUpper(strings.TrimSpace(signal.DataClassification)) {
	case "L1":
		signal.Reason = ""
		signal.TargetIP = ""
		signal.Target = ""
		signal.Service = ""
		signal.Interface = ""
		signal.Payload = ""
	case "L2":
		signal.TargetIP = ""
		signal.Payload = ""
	case "L3":
		signal.Payload = sanitizePayload([]byte(signal.Payload), 120)
	case "L4":
		signal.Payload = sanitizePayload([]byte(signal.Payload), 200)
	}
	return signal
}

func meshEventRateLimitPerMin() int {
	if config.Security.MeshEventRateLimitPerMin > 0 {
		return config.Security.MeshEventRateLimitPerMin
	}
	return defaultMeshRatePerMin
}

func meshEventBurst() int {
	if config.Security.MeshEventBurst > 0 {
		return config.Security.MeshEventBurst
	}
	return defaultMeshBurst
}

func replayWindow() time.Duration {
	if config.Security.MeshReplayWindowS > 0 {
		return time.Duration(config.Security.MeshReplayWindowS) * time.Second
	}
	return defaultReplayWindow
}

func newFederationEventID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("event-%d", federationNow().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func recordFederationAccept(peer, publisher string) {
	federationAccepted.Add(1)
	appendFederationAudit(federationAuditEntry{
		Timestamp: federationNow().UTC().Format(time.RFC3339),
		Peer:      peer,
		Publisher: publisher,
		Reason:    "accepted",
		Accepted:  true,
	})
	log.Printf("[MESH][AUDIT] accepted peer=%s publisher=%s", peer, publisher)
}

func recordFederationReject(peer, publisher, reason string) {
	federationRejected.Add(1)
	federationAuditMu.Lock()
	federationRejectReason[reason]++
	federationAuditMu.Unlock()
	appendFederationAudit(federationAuditEntry{
		Timestamp: federationNow().UTC().Format(time.RFC3339),
		Peer:      peer,
		Publisher: publisher,
		Reason:    reason,
		Accepted:  false,
	})
	log.Printf("[MESH][AUDIT] rejected peer=%s publisher=%s reason=%s", peer, publisher, reason)
}

func appendFederationAudit(entry federationAuditEntry) {
	federationAuditMu.Lock()
	defer federationAuditMu.Unlock()
	federationAudit = append(federationAudit, entry)
	if len(federationAudit) > federationAuditLimit {
		federationAudit = federationAudit[len(federationAudit)-federationAuditLimit:]
	}
}

func federationRejectReasonsSnapshot() map[string]uint64 {
	federationAuditMu.Lock()
	defer federationAuditMu.Unlock()
	out := make(map[string]uint64, len(federationRejectReason))
	for reason, count := range federationRejectReason {
		out[reason] = count
	}
	return out
}

func resetFederationSecurityState() {
	federationAccepted.Store(0)
	federationRejected.Store(0)
	federationContributed.Store(0)
	federationAuditMu.Lock()
	federationAudit = nil
	federationRejectReason = map[string]uint64{}
	federationAuditMu.Unlock()
	federationReplayMu.Lock()
	federationReplay = make(map[string]map[string]time.Time)
	federationReplayMu.Unlock()
	federationLimitMu.Lock()
	federationLimit = make(map[string]*federationLimiter)
	federationLimitMu.Unlock()
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
