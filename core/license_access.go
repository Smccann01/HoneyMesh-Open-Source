package main

import (
	"time"

	"honeymesh/internal/license"
)

// Community builds support a small direct mesh for evaluation. This is a
// product default in the open-source implementation, not a license restriction
// on modified versions or on a customer-operated Exchange.
const communityMaxDirectPeers = 5

func meshMaxNodesAllowed() int {
	if licenseDisplayName() == "Community" {
		return communityMaxDirectPeers + 1 // include this node
	}
	return license.MaxNodes()
}

func directMeshPeerLimit() int {
	if max := meshMaxNodesAllowed(); max > 0 {
		return max - 1
	}
	return 0 // unlimited by this build; trust and operator controls still apply
}

func premiumFeaturesEnabled() bool {
	return license.PremiumEnabled()
}

func trustedNetworkSharingEnabled() bool {
	return config.TrustedNetworkSharingEnabled
}

func trustedMeshNetworkEnabled() bool {
	return config.TrustedMeshNetworkEnabled
}

func effectiveLicenseTier() string {
	if premiumFeaturesEnabled() {
		return license.TierPro
	}
	return license.TierFree
}

func licenseDisplayName() string {
	if effectiveLicenseTier() == license.TierPro {
		return "Pro"
	}
	return "Community"
}

func syncLicenseConfigState() {
	changed := false
	tier := effectiveLicenseTier()
	if config.LicenseTier != tier {
		config.LicenseTier = tier
		changed = true
	}
	if changed {
		saveConfig()
	}
}

func setTrustedNetworkSharing(enabled bool) bool {
	if enabled && exchangeConfigured() {
		config.Exchange.Enabled = true
	}
	if config.TrustedNetworkSharingEnabled == enabled {
		return false
	}
	config.TrustedNetworkSharingEnabled = enabled
	saveConfig()
	return true
}

func setTrustedMeshNetwork(enabled bool) bool {
	if config.TrustedMeshNetworkEnabled == enabled {
		applyTrustedMeshNetworkState()
		return false
	}
	config.TrustedMeshNetworkEnabled = enabled
	saveConfig()
	applyTrustedMeshNetworkState()
	return true
}

func applyTrustedMeshNetworkState() {
	if trustedMeshNetworkEnabled() {
		if scp != nil {
			if meshMaxNodesAllowed() > 0 {
				for _, peer := range scp.KnownPeers() {
					if !activeMeshPeerConfigured(peer) {
						scp.RemovePeer(peer)
					}
				}
			}
			for _, peer := range activeMeshPeers() {
				if peer == "" {
					continue
				}
				go scp.ConnectToPeer(peer)
			}
		}
		return
	}

	clearRemoteNetworkState()
}

func clearRemoteNetworkState() {
	remoteBanMu.Lock()
	remoteBanCache = make(map[string]time.Time, 4096)
	remoteBanSources = make(map[string]map[string]struct{}, 4096)
	remoteBanMu.Unlock()
	if scp != nil {
		scp.ClearPeerState()
	}
	broadcastBans()
	broadcastPeers()
}

func handleLicenseRuntimeStateChange() {
	syncLicenseConfigState()
	applyTrustedMeshNetworkState()
}
