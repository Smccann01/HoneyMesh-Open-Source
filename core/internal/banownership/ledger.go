package banownership

import (
	"errors"
	"net/netip"
	"sync"
	"time"
)

type Kind string

const (
	Local    Kind = "local"
	App      Kind = "app"
	Mesh     Kind = "mesh"
	Exchange Kind = "exchange"
)

type Owner struct {
	Kind Kind
	ID   string
}

type Decision struct {
	Active    bool
	ExpiresAt time.Time
	Owners    int
}

// Ledger records independent reasons for enforcing an exact source address.
// Callers persist grants and reconcile the returned decision with the kernel.
type Ledger struct {
	mu     sync.Mutex
	grants map[netip.Addr]map[Owner]time.Time
}

func New() *Ledger {
	return &Ledger{grants: make(map[netip.Addr]map[Owner]time.Time)}
}

func address(raw string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.IsValid() {
		return netip.Addr{}, errors.New("invalid source address")
	}
	return ip.Unmap(), nil
}

func validOwner(owner Owner) bool {
	return (owner.Kind == Local || owner.Kind == App || owner.Kind == Mesh || owner.Kind == Exchange) && owner.ID != ""
}

func (l *Ledger) Put(rawIP string, owner Owner, expiresAt, now time.Time) (Decision, error) {
	ip, err := address(rawIP)
	if err != nil {
		return Decision{}, err
	}
	if !validOwner(owner) || !expiresAt.After(now) {
		return Decision{}, errors.New("invalid owner or expiry")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.grants == nil {
		l.grants = make(map[netip.Addr]map[Owner]time.Time)
	}
	if l.grants[ip] == nil {
		l.grants[ip] = make(map[Owner]time.Time)
	}
	l.grants[ip][owner] = expiresAt
	return l.decisionLocked(ip, now), nil
}

func (l *Ledger) Remove(rawIP string, owner Owner, now time.Time) (Decision, error) {
	ip, err := address(rawIP)
	if err != nil {
		return Decision{}, err
	}
	if !validOwner(owner) {
		return Decision{}, errors.New("invalid owner")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.grants[ip], owner)
	return l.decisionLocked(ip, now), nil
}

func (l *Ledger) Decision(rawIP string, now time.Time) (Decision, error) {
	ip, err := address(rawIP)
	if err != nil {
		return Decision{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.decisionLocked(ip, now), nil
}

func (l *Ledger) decisionLocked(ip netip.Addr, now time.Time) Decision {
	owners := l.grants[ip]
	var result Decision
	for owner, expiry := range owners {
		if !expiry.After(now) {
			delete(owners, owner)
			continue
		}
		result.Owners++
		if expiry.After(result.ExpiresAt) {
			result.ExpiresAt = expiry
		}
	}
	if len(owners) == 0 {
		delete(l.grants, ip)
	}
	result.Active = result.Owners > 0
	return result
}
