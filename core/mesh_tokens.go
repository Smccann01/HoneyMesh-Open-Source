package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type joinToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

var joinTokenMu sync.Mutex

func joinTokenDir() string {
	if stateDir != "" {
		return stateDir
	}
	return "."
}

func joinTokensPath() string {
	return filepath.Join(joinTokenDir(), "join_tokens.json")
}

func joinTokenPath() string {
	return filepath.Join(joinTokenDir(), "join.token")
}

func loadJoinTokens() ([]joinToken, error) {
	data, err := os.ReadFile(joinTokensPath())
	if err != nil {
		if os.IsNotExist(err) {
			return []joinToken{}, nil
		}
		return nil, err
	}
	var tokens []joinToken
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

func saveJoinTokens(tokens []joinToken) error {
	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(joinTokensPath(), data, 0600)
}

func addJoinToken(token string, exp time.Time) error {
	joinTokenMu.Lock()
	defer joinTokenMu.Unlock()
	tokens, err := loadJoinTokens()
	if err != nil {
		return err
	}
	tokens = append(tokens, joinToken{Token: token, ExpiresAt: exp, Used: false})
	return saveJoinTokens(tokens)
}

func validateAndUseJoinToken(token string) bool {
	joinTokenMu.Lock()
	defer joinTokenMu.Unlock()
	tokens, err := loadJoinTokens()
	if err != nil {
		return false
	}
	now := time.Now()
	changed := false
	ok := false
	for i := range tokens {
		if tokens[i].Token != token {
			continue
		}
		if tokens[i].Used || now.After(tokens[i].ExpiresAt) {
			continue
		}
		tokens[i].Used = true
		ok = true
		changed = true
		break
	}
	if changed {
		_ = saveJoinTokens(tokens)
	}
	return ok
}

// wiring done in main
