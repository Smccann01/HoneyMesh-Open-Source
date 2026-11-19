package main

import (
	"time"

	"honeymesh/internal/license"
)

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
			for _, peer := range config.Mesh.Peers {
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
