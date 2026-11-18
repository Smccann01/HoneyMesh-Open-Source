package main

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// reconcileLegacyBanSnapshot is a transition bridge until every ban producer
// uses the unified enforcement engine. The caller holds banMutex so producers
// cannot change the registry between the map update and mode publication.
func reconcileLegacyBanSnapshot(bans map[string]time.Time, from, to ModeType, now time.Time, apply, remove func(string) error) error {
	keys := make([]string, 0, len(bans))
	for ip := range bans {
		keys = append(keys, ip)
	}
	sort.Strings(keys)
	type update struct {
		ip      string
		applied bool
	}
	var completed []update
	for _, ip := range keys {
		active := bans[ip].After(now)
		shouldApply := to != ModeTest && active
		var err error
		if shouldApply {
			err = apply(ip)
		} else {
			err = remove(ip)
		}
		if err != nil {
			var rollback []error
			for i := len(completed) - 1; i >= 0; i-- {
				entry := completed[i]
				priorActive := from != ModeTest && bans[entry.ip].After(now)
				if priorActive && !entry.applied {
					rollback = append(rollback, apply(entry.ip))
				} else if !priorActive && entry.applied {
					rollback = append(rollback, remove(entry.ip))
				}
			}
			return errors.Join(append([]error{fmt.Errorf("reconcile %s: %w", ip, err)}, rollback...)...)
		}
		completed = append(completed, update{ip: ip, applied: shouldApply})
	}
	return nil
}

func reconcileLegacyBansForMode(from, to ModeType) error {
	if from != ModeTest && to != ModeTest {
		return nil
	}
	// Startup and unit tests may change mode before the BPF objects exist.
	if bpfObjs.BanMap == nil && bpfObjs.BanMapV6 == nil {
		return nil
	}
	// Only local and manual bans are stored in the legacy bans table. Remote,
	// app, and Exchange decisions need their own live policy reconciliation.
	// Unknown metadata after restart represents a loaded legacy local record.
	snapshot := make(map[string]time.Time, len(banExpirations))
	banMetaMu.Lock()
	for ip, expiry := range banExpirations {
		category := banMeta[ip].Category
		if to != ModeTest && (category == "REMOTE_MESH" || category == "NETTOOLS_EXCHANGE" || category == "NODE_APP") {
			continue
		}
		snapshot[ip] = expiry
	}
	banMetaMu.Unlock()
	return reconcileLegacyBanSnapshot(snapshot, from, to, time.Now(),
		(ueeKernelAdapter{}).Apply, (ueeKernelAdapter{}).Remove)
}
