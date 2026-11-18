package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const runtimeStateVersion = 1
const runtimeStateFilename = "runtime-state.json"

var runtimeStateMu sync.Mutex
var configFingerprint string

type runtimeSecurityState struct {
	AllowlistBase          *bool    `json:"allowlist_base"`
	Whitelist              []string `json:"whitelist"`
	TrustedPeers           []string `json:"trusted_peers"`
	ScanPorts              int      `json:"scan_ports"`
	ScanWindowS            int      `json:"scan_window_s"`
	AutomaticBanTTLSeconds *int     `json:"automatic_ban_ttl_seconds,omitempty"`
}

type runtimeState struct {
	Version                      int                   `json:"version"`
	ConfigFingerprint            string                `json:"config_fingerprint"`
	AdminToken                   string                `json:"admin_token"`
	LicenseTier                  string                `json:"license_tier"`
	TrustedNetworkSharingEnabled bool                  `json:"trusted_network_sharing_enabled"`
	TrustedMeshNetworkEnabled    bool                  `json:"trusted_mesh_network_enabled"`
	Ifaces                       []string              `json:"interfaces"`
	Traps                        map[string]*TrapState `json:"traps"`
	MeshPeers                    []string              `json:"mesh_peers"`
	MeshAuthoritativePeers       []string              `json:"mesh_authoritative_peers"`
	MeshTrustedNetworks          []TrustedMeshNetwork  `json:"mesh_trusted_networks"`
	MeshRevokedPeerCerts         []string              `json:"mesh_revoked_peer_certs,omitempty"`
	Exchange                     ExchangeConfig        `json:"exchange"`
	Security                     runtimeSecurityState  `json:"security"`
}

func runtimeStatePath() string {
	dir := stateDir
	if dir == "" {
		dir = filepath.Dir(configFile)
	}
	return filepath.Join(dir, runtimeStateFilename)
}

func currentRuntimeState() runtimeState {
	return runtimeState{
		Version:                      runtimeStateVersion,
		ConfigFingerprint:            configFingerprint,
		AdminToken:                   config.AdminToken,
		LicenseTier:                  config.LicenseTier,
		TrustedNetworkSharingEnabled: config.TrustedNetworkSharingEnabled,
		TrustedMeshNetworkEnabled:    config.TrustedMeshNetworkEnabled,
		Ifaces:                       config.Ifaces,
		Traps:                        config.Traps,
		MeshPeers:                    config.Mesh.Peers,
		MeshAuthoritativePeers:       config.Mesh.AuthoritativePeers,
		MeshTrustedNetworks:          config.Mesh.TrustedNetworks,
		MeshRevokedPeerCerts:         config.Mesh.RevokedPeerCerts,
		Exchange:                     config.Exchange,
		Security: runtimeSecurityState{
			AllowlistBase:          config.Security.AllowlistBase,
			Whitelist:              config.Security.Whitelist,
			TrustedPeers:           config.Security.TrustedPeers,
			ScanPorts:              config.Security.ScanPorts,
			ScanWindowS:            config.Security.ScanWindowS,
			AutomaticBanTTLSeconds: config.Security.AutomaticBanTTLSeconds,
		},
	}
}

func applyRuntimeState(state runtimeState) {
	config.AdminToken = state.AdminToken
	config.LicenseTier = state.LicenseTier
	config.TrustedNetworkSharingEnabled = state.TrustedNetworkSharingEnabled
	config.TrustedMeshNetworkEnabled = state.TrustedMeshNetworkEnabled
	config.Ifaces = state.Ifaces
	config.Traps = state.Traps
	config.Mesh.Peers = state.MeshPeers
	config.Mesh.AuthoritativePeers = state.MeshAuthoritativePeers
	config.Mesh.TrustedNetworks = state.MeshTrustedNetworks
	config.Mesh.RevokedPeerCerts = state.MeshRevokedPeerCerts
	config.Exchange = state.Exchange
	config.Security.AllowlistBase = state.Security.AllowlistBase
	config.Security.Whitelist = state.Security.Whitelist
	config.Security.TrustedPeers = state.Security.TrustedPeers
	config.Security.ScanPorts = state.Security.ScanPorts
	config.Security.ScanWindowS = state.Security.ScanWindowS
	config.Security.AutomaticBanTTLSeconds = state.Security.AutomaticBanTTLSeconds
}

func loadRuntimeState() error {
	path := runtimeStatePath()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect runtime state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("runtime state must be a private regular file: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read runtime state: %w", err)
	}
	var state runtimeState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode runtime state: %w", err)
	}
	if state.Version != runtimeStateVersion {
		return fmt.Errorf("unsupported runtime state version %d", state.Version)
	}
	operatorIfaces, operatorTraps, operatorSecurity := config.Ifaces, config.Traps, config.Security
	operatorMeshEnabled, operatorSharingEnabled := config.TrustedMeshNetworkEnabled, config.TrustedNetworkSharingEnabled
	applyRuntimeState(state)
	if state.ConfigFingerprint != "" && state.ConfigFingerprint != configFingerprint {
		// An operator edit to the root config reselects protected interfaces,
		// traps, detection policy, and explicit sharing opt-ins.
		// Keep generated credentials and the remaining runtime settings intact.
		config.Ifaces, config.Traps = operatorIfaces, operatorTraps
		config.Security = operatorSecurity
		config.TrustedMeshNetworkEnabled = operatorMeshEnabled
		config.TrustedNetworkSharingEnabled = operatorSharingEnabled
		log.Printf("[STATE] Operator config changed; refreshed interfaces, traps, security policy, and sharing opt-ins")
	}
	return nil
}

func saveConfig() bool {
	runtimeStateMu.Lock()
	defer runtimeStateMu.Unlock()
	path := runtimeStatePath()
	data, err := json.MarshalIndent(currentRuntimeState(), "", "  ")
	if err != nil {
		log.Printf("[STATE] Encode failed: %v", err)
		return false
	}
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".runtime-state-*")
	if err != nil {
		log.Printf("[STATE] Temporary file failed: %v", err)
		return false
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0600); err != nil {
		file.Close()
		log.Printf("[STATE] Permissions failed: %v", err)
		return false
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		log.Printf("[STATE] Write failed: %v", err)
		return false
	}
	if err := file.Sync(); err != nil {
		file.Close()
		log.Printf("[STATE] Sync failed: %v", err)
		return false
	}
	if err := file.Close(); err != nil {
		log.Printf("[STATE] Close failed: %v", err)
		return false
	}
	if err := os.Rename(file.Name(), path); err != nil {
		log.Printf("[STATE] Replace failed: %v", err)
		return false
	}
	return true
}
