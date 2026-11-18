package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"honeymesh/internal/license"
)

const marketplaceLicensePath = "license.json"

var marketplaceHTTPClient = &http.Client{
	Timeout:       12 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
}

func refreshMarketplaceLicense() error {
	endpoint := strings.TrimSpace(config.Marketplace.RefreshURL)
	token := strings.TrimSpace(config.Marketplace.NodeToken)
	if endpoint == "" && token == "" {
		return nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || token == "" {
		return fmt.Errorf("Marketplace requires an HTTPS refresh URL and node token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := marketplaceHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		license.Invalidate()
		_ = os.Remove(marketplaceLicensePath)
		return fmt.Errorf("Marketplace node access revoked (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Marketplace refresh returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil {
		return err
	}
	if len(body) > 4096 {
		return fmt.Errorf("Marketplace license response too large")
	}
	var document license.LicenseFile
	if err := json.Unmarshal(body, &document); err != nil {
		return err
	}
	if document.Tier != "PRO" || document.MaxNodes < 1 || document.ExpiresAt.Before(time.Now().Add(time.Minute)) {
		return fmt.Errorf("Marketplace license is inactive or too close to expiry")
	}
	if err := license.VerifyLicense(&document); err != nil {
		return err
	}
	cluster := license.GetOrGenerateClusterID()
	if cluster != "" && cluster != document.ClusterID {
		return fmt.Errorf("Marketplace cluster ID does not match this node")
	}
	tmp, err := os.CreateTemp(".", ".marketplace-license-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), marketplaceLicensePath); err != nil {
		return err
	}
	if err := license.LoadAndVerify(marketplaceLicensePath, cluster); err != nil {
		return err
	}
	return nil
}

func startMarketplaceLicenseRefresh(shutdown <-chan struct{}) {
	if config.Marketplace.RefreshURL == "" && config.Marketplace.NodeToken == "" {
		return
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-shutdown:
			return
		case <-ticker.C:
			if err := refreshMarketplaceLicense(); err != nil {
				log.Printf("[LICENSE] Marketplace refresh: %v", err)
			}
			handleLicenseRuntimeStateChange()
		}
	}
}
