package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeStatePersistsMutableFieldsWithoutEditingOperatorConfig(t *testing.T) {
	previousConfig, previousFile, previousDir, previousConfigDir := config, configFile, stateDir, configDir
	defer func() {
		config, configFile, stateDir, configDir = previousConfig, previousFile, previousDir, previousConfigDir
	}()
	root := t.TempDir()
	configFile = filepath.Join(root, "honeymesh.json")
	stateDir = filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	operator := Config{NodeName: "operator-node", BindIP: "127.0.0.1", Security: SecurityConfig{CertFile: "certs/node.crt", KeyFile: "certs/node.key"}, Mesh: MeshConfig{TLS: MeshTLSConfig{PeerCAFile: "certs/peer-ca.crt"}}}
	original, err := json.Marshal(operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configFile, original, 0600); err != nil {
		t.Fatal(err)
	}
	loadConfig()
	config.AdminToken = "synthetic-token"
	config.Security.ScanPorts = 25
	autoTTL := 60
	config.Security.AutomaticBanTTLSeconds = &autoTTL
	config.Mesh.Peers = []string{"peer.example:9000"}
	config.Exchange.NodeID = "synthetic-node"
	if !saveConfig() {
		t.Fatal("save runtime state")
	}
	onDisk, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != string(original) {
		t.Fatal("operator config was modified")
	}
	info, err := os.Stat(runtimeStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("runtime state mode %o", info.Mode().Perm())
	}
	config = Config{}
	loadConfig()
	if config.AdminToken != "synthetic-token" || config.Security.ScanPorts != 25 || config.Security.AutomaticBanTTLSeconds == nil || *config.Security.AutomaticBanTTLSeconds != 60 || len(config.Mesh.Peers) != 1 || config.Exchange.NodeID != "synthetic-node" {
		t.Fatalf("runtime state did not persist: %#v", config)
	}
	if config.NodeName != "operator-node" || config.Security.CertFile != filepath.Join(root, "certs/node.crt") || config.Mesh.TLS.PeerCAFile != filepath.Join(root, "certs/peer-ca.crt") {
		t.Fatal("operator-owned settings were lost")
	}
	operator.Ifaces = []string{"eth-test"}
	operator.Traps = map[string]*TrapState{"2222": {Enabled: true}}
	operator.Security.ScanPorts = 31
	updated, err := json.Marshal(operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configFile, updated, 0600); err != nil {
		t.Fatal(err)
	}
	config = Config{}
	loadConfig()
	if len(config.Ifaces) != 1 || config.Ifaces[0] != "eth-test" || !config.Traps["2222"].Enabled || config.Security.ScanPorts != 31 || config.AdminToken != "synthetic-token" {
		t.Fatalf("operator selections or runtime credential lost: %#v", config)
	}
}
