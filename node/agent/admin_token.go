package main

import (
	"crypto/rand"
	"encoding/hex"
)

func generateAdminToken() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}
