package main

import (
	"errors"
	"time"
)

const (
	minManualBanTTLSeconds        = 30
	maxManualBanTTLSeconds        = 24 * 60 * 60
	defaultAutomaticBanTTLSeconds = 15 * 60
)

// automaticBanDuration applies only to local detector decisions. It is
// independent of manual, mesh, Exchange, and application-owned grants.
func automaticBanDuration(ttlSeconds *int) (time.Duration, error) {
	if ttlSeconds == nil {
		return defaultAutomaticBanTTLSeconds * time.Second, nil
	}
	if *ttlSeconds < minManualBanTTLSeconds || *ttlSeconds > maxManualBanTTLSeconds {
		return 0, errors.New("automatic_ban_ttl_seconds must be between 30 and 86400")
	}
	return time.Duration(*ttlSeconds) * time.Second, nil
}

func getAutomaticBanDuration() time.Duration {
	duration, err := automaticBanDuration(config.Security.AutomaticBanTTLSeconds)
	if err != nil {
		panic(err) // loadConfig rejects this before detectors start.
	}
	return duration
}

// manualBanDuration preserves the mode default when no TTL is requested.
// Explicit values are bounded to prevent accidental permanent or ineffective bans.
func manualBanDuration(ttlSeconds *int) (time.Duration, error) {
	if ttlSeconds == nil {
		return getBanDuration(), nil
	}
	if *ttlSeconds < minManualBanTTLSeconds || *ttlSeconds > maxManualBanTTLSeconds {
		return 0, errors.New("ttl_seconds must be between 30 and 86400")
	}
	return time.Duration(*ttlSeconds) * time.Second, nil
}

// ─────────────────────────────────────────────
// BAN DURATION POLICY
// ─────────────────────────────────────────────

func getBanDuration() time.Duration {
	switch Mode() {
	case ModeTest:
		return 1 * time.Minute
	case ModeEnforce:
		return 5 * time.Hour
	case ModeLockdown:
		return 24 * time.Hour
	default:
		return 5 * time.Minute
	}
}

// ─────────────────────────────────────────────
// ENFORCEMENT GATE
// ─────────────────────────────────────────────

func shouldEnforce(ip string, severity int) bool {
	if Mode() == ModeTest {
		return false
	}
	if Mode() == ModeLockdown {
		return true
	}
	if Mode() == ModeEnforce {
		return severity >= 1
	}
	return false
}

// ─────────────────────────────────────────────
// POLICY-AWARE BAN WRAPPER
// ─────────────────────────────────────────────

func policyBan(
	ip, targetIP, target, service, category, reason string,
	entropy float64,
	severity int,
	iface string,
	duration time.Duration,
) {
	if isWhitelisted(ip) {
		return
	}

	// Count as a threat even if enforcement is disabled.
	localThreats.Add(1)

	if !shouldEnforce(ip, severity) {
		return
	}

	_ = triggerBan(ip, targetIP, target, service, category, reason, entropy, severity, iface, duration)
}
