package main

import (
	"testing"

	"honeymesh/internal/enforcementengine"
)

func TestLegacyNodeKernelCallbacksRejectActiveUEE(t *testing.T) {
	previous := liveUEE
	liveUEE = &enforcementengine.Engine{}
	t.Cleanup(func() { liveUEE = previous })

	for name, operation := range map[string]func(string) error{
		"apply":  nodeEdgeKernelApply,
		"remove": nodeEdgeKernelRemove,
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation("192.0.2.80"); err == nil {
				t.Fatal("legacy direct kernel callback accepted while UEE is active")
			}
		})
	}
}
