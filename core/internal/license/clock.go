package license

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

const clockFile = "license.clock"
const rollbackGrace = 5 * time.Minute

// ClockState tracks last observed wall clock.
type ClockState struct {
	LastCheck time.Time `json:"last_check"`
}

var (
	clockMu    sync.Mutex
	clockState ClockState
	clockValid = true
)

func LoadClockState() {
	clockMu.Lock()
	defer clockMu.Unlock()
	data, err := os.ReadFile(clockFile)
	if err != nil {
		if os.IsNotExist(err) {
			clockState.LastCheck = time.Now()
			_ = persistClockLocked()
			return
		}
		log.Printf("[LICENSE] clock load error: %v", err)
		return
	}
	var st ClockState
	if err := json.Unmarshal(data, &st); err != nil {
		log.Printf("[LICENSE] clock parse error: %v", err)
		return
	}
	clockState = st
	_ = validateClockLocked(time.Now())
}

func StartLicenseMonitor(detach func()) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := validateClock(time.Now()); err != nil {
			Invalidate()
			if detach != nil {
				detach()
			}
		}
		if !ExpiresAt().IsZero() && time.Now().After(ExpiresAt()) {
			Invalidate()
			if detach != nil {
				detach()
			}
		}
	}
}

func validateClock(now time.Time) error {
	clockMu.Lock()
	defer clockMu.Unlock()
	return validateClockLocked(now)
}

func validateClockLocked(now time.Time) error {
	if !clockState.LastCheck.IsZero() {
		if now.Add(rollbackGrace).Before(clockState.LastCheck) {
			clockValid = false
			return fmt.Errorf("clock rollback detected")
		}
	}
	clockState.LastCheck = now
	_ = persistClockLocked()
	clockValid = true
	return nil
}

func persistClockLocked() error {
	data, err := json.Marshal(clockState)
	if err != nil {
		return err
	}
	return os.WriteFile(clockFile, data, 0600)
}

func clockOK() bool {
	clockMu.Lock()
	defer clockMu.Unlock()
	return clockValid
}
