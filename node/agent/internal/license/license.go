package license

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	TierFree = "free"
	TierPro  = "pro"
)

var stateMu sync.RWMutex
var clusterID = ""
var maxNodes = 0
var tier = TierFree
var licenseValid bool
var licenseExpiresAt time.Time

const clusterIDFile = "cluster.id"

// LoadAndVerify validates a license file (stub)
func LoadAndVerify(path string, cluster string) error {
	lf, err := Load(path)
	if err != nil {
		invalidate()
		return err
	}
	if err := VerifyLicense(lf); err != nil {
		invalidate()
		return err
	}
	if cluster == "" && lf.ClusterID != "" {
		_ = SetClusterID(lf.ClusterID)
		cluster = lf.ClusterID
	}
	if lf.ClusterID != "" && lf.ClusterID != cluster {
		invalidate()
		return fmt.Errorf("cluster mismatch")
	}
	if !lf.ExpiresAt.IsZero() && time.Now().After(lf.ExpiresAt) {
		invalidate()
		return fmt.Errorf("license expired")
	}
	SetMaxNodes(lf.MaxNodes)
	SetTier(lf.Tier)
	stateMu.Lock()
	licenseExpiresAt = lf.ExpiresAt
	licenseValid = true
	stateMu.Unlock()
	return nil
}

// GetOrGenerateClusterID returns cluster ID (stub)
func GetOrGenerateClusterID() string {
	if clusterID != "" {
		return clusterID
	}
	if id, err := os.ReadFile(clusterIDFile); err == nil {
		clusterID = strings.TrimSpace(string(id))
	}
	return clusterID
}

// SetClusterID sets cluster ID (stub)
func SetClusterID(id string) error {
	id = strings.TrimSpace(id)
	clusterID = id
	if id == "" {
		_ = os.Remove(clusterIDFile)
		return nil
	}
	return os.WriteFile(clusterIDFile, []byte(id), 0600)
}

// CanEnforce reports that local enforcement is available to community builds.
// Operator mode and scoped authorization still determine each action.
func CanEnforce() bool {
	return true
}

func PremiumEnabled() bool {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return tier == TierPro && licenseValid && clockOK()
}

func Invalidate() {
	invalidate()
}

func invalidate() {
	stateMu.Lock()
	defer stateMu.Unlock()
	tier = TierFree
	maxNodes = 0
	licenseValid = false
	licenseExpiresAt = time.Time{}
}

// MaxNodes returns allowed nodes from license (0 = unlimited).
func MaxNodes() int {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return maxNodes
}

// SetMaxNodes sets max nodes (used by loader).
func SetMaxNodes(n int) {
	if n < 0 {
		n = 0
	}
	stateMu.Lock()
	maxNodes = n
	stateMu.Unlock()
}

// Tier returns current license tier.
func Tier() string {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return tier
}

// SetTier sets tier (default is "free").
func SetTier(t string) {
	stateMu.Lock()
	tier = NormalizeTier(t)
	stateMu.Unlock()
}

func NormalizeTier(t string) string {
	switch strings.TrimSpace(strings.ToLower(t)) {
	case "pro", "enterprise":
		return TierPro
	case "community", "free", "trial", "":
		return TierFree
	default:
		return TierFree
	}
}

func ExpiresAt() time.Time {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return licenseExpiresAt
}

func Valid() bool {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return licenseValid && clockOK()
}

// SetStateForTesting overrides in-memory license state for unit tests.
func SetStateForTesting(t string, valid bool, expires time.Time, nodes int) {
	stateMu.Lock()
	tier = NormalizeTier(t)
	licenseValid = valid
	licenseExpiresAt = expires
	if nodes < 0 {
		nodes = 0
	}
	maxNodes = nodes
	stateMu.Unlock()

	clockMu.Lock()
	clockValid = true
	clockMu.Unlock()
}
