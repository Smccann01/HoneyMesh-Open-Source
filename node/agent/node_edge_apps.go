package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"honeymesh/internal/agentbridge"
	"honeymesh/internal/banownership"
	"honeymesh/internal/license"
)

var nodeAppID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

type nodeEdgeApp struct {
	AppID      string  `json:"app_id"`
	Source     string  `json:"source"`
	Socket     string  `json:"socket"`
	SecretFile string  `json:"secret_file"`
	UID        *uint32 `json:"uid"`
	AutoBlock  bool    `json:"auto_block"`
	CanaryIPs  string  `json:"canary_ips"`
}

func readNodeEdgeApps(path string) ([]nodeEdgeApp, error) {
	data, err := readProtectedNodeFile(path, 64*1024)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Apps []nodeEdgeApp `json:"apps"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("node edge app config has trailing data")
	}
	if len(doc.Apps) == 0 || len(doc.Apps) > 16 {
		return nil, errors.New("node edge config requires 1-16 apps")
	}
	ids, sockets, uids := map[string]bool{}, map[string]bool{}, map[uint32]bool{}
	for _, app := range doc.Apps {
		if !nodeAppID.MatchString(app.AppID) || !filepath.IsAbs(app.Socket) || !filepath.IsAbs(app.SecretFile) ||
			app.UID == nil || (app.Source != "node_guard" && app.Source != "exchange_guard") ||
			ids[app.AppID] || sockets[app.Socket] || uids[*app.UID] {
			return nil, errors.New("node edge apps require distinct IDs, sockets, UIDs, and valid sources")
		}
		if app.AutoBlock && strings.TrimSpace(app.CanaryIPs) == "" {
			return nil, errors.New("auto_block requires exact canary_ips")
		}
		ids[app.AppID], sockets[app.Socket], uids[*app.UID] = true, true, true
	}
	return doc.Apps, nil
}

func protectedAppSecret(path string) ([]byte, error) {
	data, err := readProtectedNodeFile(path, 4096)
	return []byte(strings.TrimSpace(string(data))), err
}

func nodeProHostEntitled() bool {
	path, unitID := os.Getenv("HM_NODE_PRO_ENTITLEMENT_FILE"), os.Getenv("HM_NODE_PRO_UNIT_ID")
	if path == "" || unitID == "" {
		return false
	}
	data, err := readProtectedNodeFile(path, 4096)
	if err != nil {
		return false
	}
	document, err := license.ParseNodeProEntitlement(data)
	return err == nil && license.VerifyNodeProEntitlement(document, unitID, time.Now()) == nil
}

func readProtectedNodeFile(path string, maxBytes int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("node edge path must be absolute")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBytes || info.Mode().Perm()&0027 != 0 {
		return nil, errors.New("node edge file must be regular, protected, and within its size limit")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Getuid())) {
		return nil, errors.New("node edge file must be owned by root or the agent UID")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		return nil, errors.New("node edge file read exceeded size limit")
	}
	return data, nil
}

func nodeEdgeActiveBlocksForApp(appID string) func(context.Context) ([]agentbridge.Block, error) {
	return func(ctx context.Context) ([]agentbridge.Block, error) {
		if liveUEE != nil {
			grants, err := liveUEE.GrantsByKind(banownership.App, time.Now())
			if err != nil {
				return nil, err
			}
			var blocks []agentbridge.Block
			for _, grant := range grants {
				if strings.HasPrefix(grant.Owner.ID, appOwnerPrefix(appID)) {
					blocks = append(blocks, agentbridge.Block{IP: grant.IP, ReasonCode: grant.Reason, ExpiresAt: grant.ExpiresAt})
				}
			}
			return blocks, nil
		}
		rows, err := db.QueryContext(ctx, `SELECT ip, reason_code, expires_at FROM node_edge_events
			WHERE app_id=? AND status='kernel_applied' AND expires_at > ?`, appID, time.Now().Unix())
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var blocks []agentbridge.Block
		for rows.Next() {
			var ip, reason string
			var expiry int64
			if err := rows.Scan(&ip, &reason, &expiry); err != nil {
				return nil, err
			}
			blocks = append(blocks, agentbridge.Block{IP: ip, ReasonCode: reason, ExpiresAt: time.Unix(expiry, 0)})
		}
		return blocks, rows.Err()
	}
}

func startNodeEdgeApps(shutdown <-chan struct{}, configPath string) error {
	apps, err := readNodeEdgeApps(configPath)
	if err != nil {
		return err
	}
	type running struct {
		server   *http.Server
		listener net.Listener
		path     string
	}
	started := make([]running, 0, len(apps))
	stop := func() {
		for _, item := range started {
			_ = item.server.Close()
			_ = item.listener.Close()
			_ = os.Remove(item.path)
		}
	}
	secrets := map[string]bool{}
	for _, app := range apps {
		secret, err := protectedAppSecret(app.SecretFile)
		if err != nil {
			stop()
			return err
		}
		secretKey := string(secret)
		if secrets[secretKey] {
			stop()
			return errors.New("node edge apps must not share a secret")
		}
		secrets[secretKey] = true
		canarySources, err := parseNodeEdgeCanarySources(app.CanaryIPs)
		if err != nil {
			stop()
			return err
		}
		c := &nodeEdgeController{
			db: db, autoBlock: app.AutoBlock,
			canEnforce:  func() bool { return true },
			modeEnforce: func() bool { return Mode() == ModeEnforce }, attached: nodeEdgeInterfaceAttached,
			allowed: func(ip string) bool {
				addr, err := netip.ParseAddr(ip)
				return err == nil && nodeEdgeSourceAllowed(addr)
			},
			canaryAllowed: func(ip string) bool { _, ok := canarySources[ip]; return ok },
			apply:         nodeEdgeKernelApply, remove: nodeEdgeKernelRemove, now: time.Now,
			lastBySource: make(map[string]time.Time),
		}
		bridge, err := agentbridge.New(agentbridge.Config{
			Secret: secret, ExpectedSource: app.Source, ExpectedAppID: app.AppID, ExpectedUID: app.UID,
			AllowedSource: nodeEdgeSourceAllowed, OnEvent: c.onEvent,
			ActiveBlocks: nodeEdgeActiveBlocksForApp(app.AppID),
			AgentMode:    func(context.Context) (string, error) { return strings.ToUpper(Mode().String()), nil },
		})
		if err != nil {
			stop()
			return err
		}
		if _, err := os.Lstat(app.Socket); err == nil {
			stop()
			return fmt.Errorf("node edge socket already exists: %s", app.Socket)
		} else if !os.IsNotExist(err) {
			stop()
			return err
		}
		listener, err := net.Listen("unix", app.Socket)
		if err != nil {
			stop()
			return err
		}
		if err := os.Chmod(app.Socket, 0660); err != nil {
			listener.Close()
			_ = os.Remove(app.Socket)
			stop()
			return err
		}
		server := &http.Server{Handler: bridge.Handler(), ConnContext: agentbridge.UnixPeerContext,
			ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8 * 1024}
		started = append(started, running{server, listener, app.Socket})
		if liveNodeEdge == nil {
			liveNodeEdge = c
		}
		go func() {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[NODE_EDGE] app socket server failed app=%s: %v", app.AppID, err)
			}
		}()
		log.Printf("[NODE_EDGE] app socket ready app=%s auto_block=%v", app.AppID, app.AutoBlock)
	}
	go func() { <-shutdown; stop() }()
	return nil
}
