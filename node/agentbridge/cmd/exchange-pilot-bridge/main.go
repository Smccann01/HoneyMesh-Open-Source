// exchange-pilot-bridge is an observe-only adapter for a packaged HoneyMesh
// agent that predates the embedded edge-ingest socket. It never writes a ban.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	bridge "github.com/Smccann01/HoneyMesh-Node/agentbridge"
)

type runtimeState struct {
	AdminToken string `json:"admin_token"`
}
type banRecord struct {
	Expires  time.Time `json:"expires"`
	Reason   string    `json:"reason"`
	Category string    `json:"category"`
}

func readRequiredFile(name string) ([]byte, error) {
	value := os.Getenv(name)
	if value == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	return os.ReadFile(value)
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	socketPath := os.Getenv("HM_BRIDGE_SOCKET")
	secret, err := readRequiredFile("HM_BRIDGE_SECRET_FILE")
	if err != nil {
		return err
	}
	secret = []byte(strings.TrimSpace(string(secret)))
	stateBytes, err := readRequiredFile("HM_AGENT_STATE_FILE")
	if err != nil {
		return err
	}
	var state runtimeState
	if err := json.Unmarshal(stateBytes, &state); err != nil || state.AdminToken == "" {
		return errors.New("invalid agent runtime state")
	}
	caBytes, err := readRequiredFile("HM_AGENT_CA_FILE")
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		return errors.New("invalid agent CA")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext:     (&net.Dialer{Timeout: time.Second}).DialContext,
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	const origin = "https://127.0.0.1:8443"
	get := func(ctx context.Context, route string, result any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+route, nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-Honey-Token", state.AdminToken)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("agent API returned HTTP %d", resp.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(result)
	}
	mode := func(ctx context.Context) (string, error) {
		var response struct {
			Mode string `json:"mode"`
		}
		if err := get(ctx, "/api/mode", &response); err != nil {
			return "", err
		}
		if response.Mode != "TEST" {
			return "", fmt.Errorf("pilot requires agent TEST mode, found %s", response.Mode)
		}
		return response.Mode, nil
	}
	if _, err := mode(context.Background()); err != nil {
		return err
	}
	localIPs := make(map[netip.Addr]bool)
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, address := range ifaces {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			localIPs[prefix.Addr().Unmap()] = true
		}
	}
	b, err := bridge.New(bridge.Config{
		Secret:        secret,
		AllowedSource: func(ip netip.Addr) bool { return !localIPs[ip.Unmap()] },
		OnEvent: func(ctx context.Context, event bridge.Event) (string, error) {
			if _, err := mode(ctx); err != nil {
				return "", err
			}
			log.Printf("observed signed app event id=%s reason=%s", event.EventID, event.ReasonCode)
			return "observed", nil
		},
		ActiveBlocks: func(ctx context.Context) ([]bridge.Block, error) {
			if _, err := mode(ctx); err != nil {
				return nil, err
			}
			var records map[string]banRecord
			if err := get(ctx, "/api/bans/meta", &records); err != nil {
				return nil, err
			}
			blocks := make([]bridge.Block, 0)
			for ip, record := range records {
				if record.Category == "EXCHANGE_EDGE" {
					blocks = append(blocks, bridge.Block{IP: ip, ReasonCode: record.Reason, ExpiresAt: record.Expires})
				}
			}
			return blocks, nil
		},
		AgentMode: mode,
	})
	if err != nil {
		return err
	}
	log.Print("observe-only Exchange bridge ready")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return b.ServeUnix(ctx, socketPath, 0660)
}
