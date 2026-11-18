// hat-sim evaluates synthetic Adaptive Trust fixtures. It cannot read live
// HoneyMesh state, issue grants, or enforce a decision.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"honeymesh/internal/adaptivetrust"
)

const maximumFixtureBytes = 64 << 10

type fixture struct {
	SchemaVersion int                     `json:"schema_version"`
	Request       adaptivetrust.Request   `json:"request"`
	Identity      *adaptivetrust.Identity `json:"identity"`
	Grant         *adaptivetrust.Grant    `json:"grant"`
	Posture       *adaptivetrust.Posture  `json:"posture"`
	Anomaly       *adaptivetrust.Anomaly  `json:"anomaly"`
	Hold          *adaptivetrust.Hold     `json:"hold"`
	Policy        struct {
		Version         string `json:"version"`
		RequirePosture  bool   `json:"require_posture"`
		MaxLeaseSeconds int    `json:"max_lease_seconds"`
	} `json:"policy"`
}

type output struct {
	Simulation bool                   `json:"simulation"`
	Decision   adaptivetrust.Decision `json:"decision"`
}

func evaluateFixture(data []byte, at time.Time) (output, error) {
	var f fixture
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		return output{}, fmt.Errorf("decode fixture: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return output{}, errors.New("fixture must contain exactly one JSON object")
	}
	if f.Policy.MaxLeaseSeconds < 0 || f.Policy.MaxLeaseSeconds > 300 {
		return output{}, errors.New("max_lease_seconds must be 0-300")
	}
	input := adaptivetrust.Input{
		SchemaVersion: f.SchemaVersion, Request: f.Request, Identity: f.Identity,
		Grant: f.Grant, Posture: f.Posture, Anomaly: f.Anomaly, Hold: f.Hold,
		Policy: adaptivetrust.Policy{Version: f.Policy.Version, RequirePosture: f.Policy.RequirePosture,
			MaxLease: time.Duration(f.Policy.MaxLeaseSeconds) * time.Second},
	}
	return output{Simulation: true, Decision: adaptivetrust.Evaluate(input, at)}, nil
}

func main() {
	atFlag := flag.String("at", "", "required RFC3339 evaluation time")
	flag.Parse()
	if *atFlag == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: hat-sim -at 2030-01-01T00:00:00Z < fixture.json")
		os.Exit(2)
	}
	at, err := time.Parse(time.RFC3339, *atFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid -at timestamp")
		os.Exit(2)
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maximumFixtureBytes+1))
	if err != nil || len(data) > maximumFixtureBytes {
		fmt.Fprintln(os.Stderr, "fixture read failed or exceeds 64 KiB")
		os.Exit(2)
	}
	result, err := evaluateFixture(data, at)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "write simulation result failed")
		os.Exit(1)
	}
}
