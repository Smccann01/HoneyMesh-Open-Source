package banownership

import (
	"testing"
	"time"
)

func TestRetractionPreservesIndependentOwners(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := New()
	a := Owner{Exchange, "signal-a"}
	b := Owner{Exchange, "signal-b"}
	local := Owner{Local, "trap-80"}
	for _, grant := range []struct {
		owner Owner
		secs  int
	}{{a, 60}, {b, 120}, {local, 180}} {
		if _, err := l.Put("2001:db8::1", grant.owner, now.Add(time.Duration(grant.secs)*time.Second), now); err != nil {
			t.Fatal(err)
		}
	}
	decision, err := l.Remove("2001:db8::1", a, now)
	if err != nil || !decision.Active || decision.Owners != 2 || !decision.ExpiresAt.Equal(now.Add(180*time.Second)) {
		t.Fatalf("remove A: %+v err=%v", decision, err)
	}
	decision, err = l.Remove("2001:db8::1", b, now)
	if err != nil || !decision.Active || decision.Owners != 1 {
		t.Fatalf("remove B: %+v err=%v", decision, err)
	}
	decision, err = l.Remove("2001:db8::1", local, now)
	if err != nil || decision.Active {
		t.Fatalf("remove local: %+v err=%v", decision, err)
	}
}

func TestExpiryAndCanonicalAddress(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := New()
	owner := Owner{Exchange, "signal-a"}
	if _, err := l.Put("::ffff:192.0.2.8", owner, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	decision, err := l.Decision("192.0.2.8", now.Add(time.Minute))
	if err != nil || decision.Active {
		t.Fatalf("expired canonical grant: %+v err=%v", decision, err)
	}
	if _, err := l.Put("invalid", owner, now.Add(time.Minute), now); err == nil {
		t.Fatal("invalid address accepted")
	}
	if _, err := l.Put("192.0.2.8", Owner{Exchange, ""}, now.Add(time.Minute), now); err == nil {
		t.Fatal("empty owner identity accepted")
	}
}
