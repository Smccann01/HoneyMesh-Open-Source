package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveConfigKeepsAdminTokenPrivate(t *testing.T) {
	previousConfig, previousFile, previousState := config, configFile, stateDir
	t.Cleanup(func() { config, configFile, stateDir = previousConfig, previousFile, previousState })
	configFile = filepath.Join(t.TempDir(), "honeymesh.json")
	stateDir = filepath.Dir(configFile)
	config = Config{AdminToken: "synthetic-token"}
	if !saveConfig() {
		t.Fatal("saveConfig failed")
	}
	info, err := os.Stat(runtimeStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state permissions = %o; want 600", info.Mode().Perm())
	}
	var saved runtimeState
	data, err := os.ReadFile(runtimeStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.AdminToken != config.AdminToken {
		t.Fatal("admin token was not persisted")
	}
}
