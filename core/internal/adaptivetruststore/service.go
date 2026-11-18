package adaptivetruststore

import (
	"context"
	"time"

	"honeymesh/internal/adaptivetrust"
)

// Preview is an observe-only evaluation. It replaces any caller-provided grant
// or hold with durable local state and requires an audit write before returning
// an allow. Identity and evidence still require a separate trusted adapter.
func (s *Store) Preview(ctx context.Context, input adaptivetrust.Input, now time.Time) (adaptivetrust.Decision, error) {
	input.Grant, input.Hold = nil, nil
	grant, err := s.ActiveGrant(ctx, input.Request, input.Policy.Version, now)
	if err != nil {
		return unavailable(input.Policy.Version, now, "state_unavailable"), err
	}
	hold, err := s.ActiveHold(ctx, input.Request)
	if err != nil {
		return unavailable(input.Policy.Version, now, "state_unavailable"), err
	}
	input.Grant, input.Hold = grant, hold
	decision := adaptivetrust.Evaluate(input, now)
	if err := s.AppendDecision(ctx, input.Request, decision); err != nil {
		return unavailable(input.Policy.Version, now, "audit_unavailable"), err
	}
	return decision, nil
}

func unavailable(version string, now time.Time, reason string) adaptivetrust.Decision {
	return adaptivetrust.Decision{SchemaVersion: adaptivetrust.SchemaVersion,
		State: adaptivetrust.Unknown, Effect: adaptivetrust.Deny,
		Reason: reason, PolicyVersion: version, EvaluatedAt: now.UTC()}
}
