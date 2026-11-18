package main

// This file is copied into the verified 2.3.6-rc2 agent source by prepare.py.
// App evidence stays local and never enters the mesh or Exchange publish path.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"honeymesh/internal/agentbridge"
	"honeymesh/internal/banownership"
	"honeymesh/internal/enforcementengine"
)

const nodeEdgeCategory = "NODE_APP"

type nodeEdgeController struct {
	db            *sql.DB
	autoBlock     bool
	modeEnforce   func() bool
	attached      func() bool
	allowed       func(string) bool
	canaryAllowed func(string) bool
	canEnforce    func() bool
	apply         func(string) error
	remove        func(string) error
	now           func() time.Time
	mu            sync.Mutex
	recent        []time.Time
	lastBySource  map[string]time.Time
}

var liveNodeEdge *nodeEdgeController

func initNodeEdgeAudit() error {
	if db == nil {
		return errors.New("node edge audit requires agent database")
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS node_edge_events (
		event_id TEXT PRIMARY KEY,
		source TEXT NOT NULL,
		app_id TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL,
		reason_code TEXT NOT NULL,
		evidence_hash TEXT NOT NULL,
		confidence INTEGER NOT NULL,
		observed_at INTEGER NOT NULL,
		expires_at INTEGER,
		status TEXT NOT NULL,
		detail TEXT NOT NULL,
		release_actor TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_node_edge_events_ip_status ON node_edge_events(ip, status);
	CREATE INDEX IF NOT EXISTS idx_node_edge_events_observed ON node_edge_events(observed_at);`)
	if err != nil {
		return fmt.Errorf("create node edge audit: %w", err)
	}
	if _, err := db.Exec("SELECT app_id FROM node_edge_events LIMIT 0"); err != nil {
		if _, err := db.Exec("ALTER TABLE node_edge_events ADD COLUMN app_id TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("migrate node edge app identity: %w", err)
		}
	}
	// Short app bans are not restored after a process restart. Reflect that in
	// the durable audit, rather than claiming a kernel rule still exists.
	_, err = db.Exec(`UPDATE node_edge_events SET status='released', detail='agent_restart', release_actor='agent_restart'
		WHERE status='kernel_applied';
		UPDATE node_edge_events SET status='rejected', detail='agent_restart_before_ack' WHERE status='armed'`)
	if err != nil {
		return fmt.Errorf("reconcile node edge audit: %w", err)
	}
	_, err = db.Exec(`DELETE FROM node_edge_events WHERE observed_at < ?`, time.Now().Add(-30*24*time.Hour).Unix())
	return err
}

func (c *nodeEdgeController) onEvent(ctx context.Context, event agentbridge.Event) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	cutoff := now.Add(-time.Minute)
	recent := c.recent[:0]
	for _, seen := range c.recent {
		if seen.After(cutoff) {
			recent = append(recent, seen)
		}
	}
	c.recent = recent
	for key, seen := range c.lastBySource {
		if !seen.After(cutoff) {
			delete(c.lastBySource, key)
		}
	}
	key := event.AppID + "|" + event.Source + "|" + event.IP + "|" + event.ReasonCode
	if len(c.recent) >= 100 || c.lastBySource[key].After(cutoff) {
		return "", errors.New("node edge event rate exceeded")
	}
	c.recent = append(c.recent, now)
	c.lastBySource[key] = now
	_, err := c.db.ExecContext(ctx, `INSERT INTO node_edge_events
		(event_id,source,app_id,ip,reason_code,evidence_hash,confidence,observed_at,status,detail)
		VALUES(?,?,?,?,?,?,?,?,'observed','received')`,
		event.EventID, event.Source, event.AppID, event.IP, event.ReasonCode, event.EvidenceHash, event.Confidence, now.Unix())
	if err != nil {
		return "", fmt.Errorf("node edge audit insert: %w", err)
	}
	if !c.autoBlock || !c.modeEnforce() || !c.attached() || !c.allowed(event.IP) || !c.canaryAllowed(event.IP) || (c.canEnforce != nil && !c.canEnforce()) {
		detail := "auto_block_off"
		switch {
		case !c.autoBlock:
		case !c.modeEnforce():
			detail = "mode_not_enforce"
		case !c.attached():
			detail = "no_attached_interface"
		case !c.allowed(event.IP):
			detail = "source_excluded"
		case c.canEnforce != nil && !c.canEnforce():
			detail = "entitlement_inactive"
		default:
			detail = "canary_excluded"
		}
		_, _ = c.db.ExecContext(ctx, `UPDATE node_edge_events SET detail=? WHERE event_id=?`, detail, event.EventID)
		return "observed", nil
	}
	expires := now.Add(time.Duration(event.TTLSeconds) * time.Second)
	if liveUEE != nil {
		if _, err := c.db.ExecContext(ctx, `UPDATE node_edge_events SET status='armed', detail='kernel_pending', expires_at=? WHERE event_id=?`, expires.Unix(), event.EventID); err != nil {
			return "", err
		}
		banMutex.Lock()
		if !c.modeEnforce() || !c.attached() || !c.allowed(event.IP) || !c.canaryAllowed(event.IP) || (c.canEnforce != nil && !c.canEnforce()) {
			banMutex.Unlock()
			_, _ = c.db.ExecContext(ctx, `UPDATE node_edge_events SET status='observed', detail='policy_changed' WHERE event_id=?`, event.EventID)
			return "observed", nil
		}
		err := ueeAppGrant(event.IP, event.AppID, event.EventID, event.ReasonCode, expires)
		if err == nil {
			err = refreshLegacyBanView(now)
		}
		banMutex.Unlock()
		if err != nil {
			_, _ = c.db.ExecContext(ctx, `UPDATE node_edge_events SET status='rejected', detail='enforcement_error' WHERE event_id=?`, event.EventID)
			return "", err
		}
		if _, err := c.db.ExecContext(ctx, `UPDATE node_edge_events SET status='kernel_applied', detail='local_only' WHERE event_id=?`, event.EventID); err != nil {
			_, _ = liveUEE.Remove(event.IP, appGrantOwner(event.AppID, event.EventID), time.Now())
			return "", err
		}
		broadcastBans()
		return "blocked", nil
	}
	banMutex.Lock()
	existing := banExpirations[event.IP]
	banMutex.Unlock()
	if existing.After(now) {
		_, _ = c.db.ExecContext(ctx, `UPDATE node_edge_events SET detail='existing_ban' WHERE event_id=?`, event.EventID)
		return "observed", nil
	}
	if _, err := c.db.ExecContext(ctx, `UPDATE node_edge_events SET status='armed', detail='kernel_pending', expires_at=? WHERE event_id=?`, expires.Unix(), event.EventID); err != nil {
		return "", err
	}
	// Hold the ban registry lock through the kernel operation so another ban
	// owner cannot take over this address between the check and insertion.
	banMutex.Lock()
	if banExpirations[event.IP].After(now) {
		banMutex.Unlock()
		_, _ = c.db.ExecContext(ctx, `UPDATE node_edge_events SET status='observed', detail='existing_ban' WHERE event_id=?`, event.EventID)
		return "observed", nil
	}
	if err := c.apply(event.IP); err != nil {
		if removeErr := c.remove(event.IP); removeErr != nil {
			c.trackBlock(event, expires)
			banMutex.Unlock()
			_, _ = c.db.Exec(`UPDATE node_edge_events SET status='kernel_applied', detail='apply_failed_release_failed' WHERE event_id=?`, event.EventID)
			return "", fmt.Errorf("kernel apply failed and rollback failed: %w; rollback: %v", err, removeErr)
		}
		banMutex.Unlock()
		_, _ = c.db.ExecContext(ctx, `UPDATE node_edge_events SET status='rejected', detail='kernel_error' WHERE event_id=?`, event.EventID)
		return "", err
	}
	if !c.modeEnforce() || !c.attached() || !c.allowed(event.IP) || !c.canaryAllowed(event.IP) || (c.canEnforce != nil && !c.canEnforce()) {
		if err := c.remove(event.IP); err != nil {
			c.trackBlock(event, expires)
			banMutex.Unlock()
			_, _ = c.db.ExecContext(ctx, `UPDATE node_edge_events SET status='kernel_applied', detail='release_failed' WHERE event_id=?`, event.EventID)
			return "", fmt.Errorf("remove rule after policy change: %w", err)
		}
		banMutex.Unlock()
		_, _ = c.db.ExecContext(ctx, `UPDATE node_edge_events SET status='rejected', detail='policy_changed' WHERE event_id=?`, event.EventID)
		return "observed", nil
	}
	if _, err := c.db.ExecContext(ctx, `UPDATE node_edge_events SET status='kernel_applied', detail='local_only', expires_at=? WHERE event_id=?`, expires.Unix(), event.EventID); err != nil {
		if removeErr := c.remove(event.IP); removeErr != nil {
			c.trackBlock(event, expires)
			_, _ = c.db.Exec(`UPDATE node_edge_events SET status='kernel_applied', detail='audit_failed_release_failed' WHERE event_id=?`, event.EventID)
			log.Printf("[NODE_EDGE] audit and rollback failed for event=%s: %v", event.EventID, removeErr)
		}
		banMutex.Unlock()
		return "", err
	}
	c.trackBlock(event, expires)
	banMutex.Unlock()
	broadcastBans() // Dashboard WebSocket only; no mesh or Exchange publication.
	return "blocked", nil
}

// Caller holds banMutex. Keeping a failed rollback in the ordinary expiry
// registry makes the rule visible and gives the cleanup worker a release path.
func (c *nodeEdgeController) trackBlock(event agentbridge.Event, expires time.Time) {
	banExpirations[event.IP] = expires
	banMetaMu.Lock()
	banMeta[event.IP] = BanMeta{Reason: event.ReasonCode, Category: nodeEdgeCategory}
	banMetaMu.Unlock()
}

func parseNodeEdgeCanarySources(raw string) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	if strings.TrimSpace(raw) == "" {
		return result, nil
	}
	for _, item := range strings.Split(raw, ",") {
		ip, err := netip.ParseAddr(strings.TrimSpace(item))
		if err != nil || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return nil, fmt.Errorf("invalid canary source address: %q", item)
		}
		result[ip.String()] = struct{}{}
	}
	return result, nil
}

func releaseNodeEdgeBlocks(actor string) error {
	if liveUEE != nil {
		grants, err := liveUEE.GrantsByKind(banownership.App, time.Now())
		if err != nil {
			return err
		}
		for _, grant := range grants {
			if _, err := liveUEE.Remove(grant.IP, grant.Owner, time.Now()); err != nil {
				return err
			}
			if err := markNodeEdgeReleased(grant.IP, actor); err != nil {
				return err
			}
		}
		banMutex.Lock()
		err = refreshLegacyBanView(time.Now())
		banMutex.Unlock()
		if err == nil {
			broadcastBans()
		}
		return err
	}
	c := liveNodeEdge
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var released []string
	var failures []error
	banMutex.Lock()
	banMetaMu.Lock()
	for ip, meta := range banMeta {
		if meta.Category != nodeEdgeCategory {
			continue
		}
		if err := c.remove(ip); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", ip, err))
			continue
		}
		delete(banExpirations, ip)
		delete(banMeta, ip)
		released = append(released, ip)
	}
	banMetaMu.Unlock()
	banMutex.Unlock()
	for _, ip := range released {
		if err := markNodeEdgeReleased(ip, actor); err != nil {
			failures = append(failures, fmt.Errorf("audit release %s: %w", ip, err))
		}
	}
	if len(released) > 0 {
		broadcastBans()
	}
	return errors.Join(failures...)
}

func nodeEdgeSourceAllowed(ip netip.Addr) bool {
	if !ip.IsValid() || isWhitelisted(ip.String()) || isExchangeLocalIP(ip.String()) {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, address := range addrs {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Unmap() == ip.Unmap() {
			return false
		}
	}
	return true
}

func nodeEdgeInterfaceAttached() bool {
	for _, name := range config.Ifaces {
		if GetIfaceMode(name) == IfaceEnforce {
			return true
		}
	}
	return false
}

func nodeEdgeKernelApply(raw string) error {
	if liveUEE != nil {
		return errors.New("legacy Node Guard kernel apply unavailable while UEE is active")
	}
	ip, err := ueeAddress(raw)
	if err != nil {
		return err
	}
	if err := (ueeKernelAdapter{}).Apply(raw); err != nil {
		return err
	}
	var value uint8
	if ip.Is4() {
		key := ip.As4()
		if err := bpfObjs.BanMap.Lookup(key, &value); err != nil || value != 1 {
			_ = (ueeKernelAdapter{}).Remove(raw)
			return errors.New("IPv4 ban map acknowledgement failed")
		}
		return nil
	}
	key := ip.As16()
	if err := bpfObjs.BanMapV6.Lookup(key, &value); err != nil || value != 1 {
		_ = (ueeKernelAdapter{}).Remove(raw)
		return errors.New("IPv6 ban map acknowledgement failed")
	}
	return nil
}

func nodeEdgeKernelRemove(raw string) error {
	if liveUEE != nil {
		return errors.New("legacy Node Guard kernel remove unavailable while UEE is active")
	}
	return (ueeKernelAdapter{}).Remove(raw)
}

func nodeEdgeRemove(raw string) error {
	if liveNodeEdge != nil {
		return liveNodeEdge.remove(raw)
	}
	return nodeEdgeKernelRemove(raw)
}

func nodeEdgeActiveBlocks(context.Context) ([]agentbridge.Block, error) {
	now := time.Now()
	if liveUEE != nil {
		grants, err := liveUEE.GrantsByKind(banownership.App, now)
		if err != nil {
			return nil, err
		}
		blocks := make([]agentbridge.Block, 0, len(grants))
		for _, grant := range grants {
			blocks = append(blocks, agentbridge.Block{IP: grant.IP, ReasonCode: grant.Reason, ExpiresAt: grant.ExpiresAt})
		}
		return blocks, nil
	}
	blocks := make([]agentbridge.Block, 0)
	banMutex.Lock()
	banMetaMu.Lock()
	for ip, expires := range banExpirations {
		meta, ok := banMeta[ip]
		if ok && meta.Category == nodeEdgeCategory && expires.After(now) {
			blocks = append(blocks, agentbridge.Block{IP: ip, ReasonCode: meta.Reason, ExpiresAt: expires})
		}
	}
	banMetaMu.Unlock()
	banMutex.Unlock()
	return blocks, nil
}

func markNodeEdgeReleased(ip, actor string) error {
	if db == nil {
		return errors.New("node edge audit unavailable")
	}
	_, err := db.Exec(`UPDATE node_edge_events SET status='released', detail='manual_release', release_actor=?
		WHERE ip=? AND status='kernel_applied'`, actor, ip)
	return err
}

func markNodeEdgeExpired(ip string) {
	if db == nil {
		return
	}
	_, _ = db.Exec(`UPDATE node_edge_events SET status='expired', detail='ttl_elapsed'
		WHERE ip=? AND status='kernel_applied'`, ip)
}

// Expire app audit rows only when their contribution has ended. A failed
// final kernel removal remains visible for operator retry and investigation.
func reconcileNodeEdgeAuditExpiry(now time.Time) error {
	if liveUEE == nil || db == nil {
		return nil
	}
	states, err := liveUEE.Snapshot(now)
	if err != nil {
		return err
	}
	stateByIP := make(map[string]enforcementengine.SnapshotEntry, len(states))
	for _, state := range states {
		stateByIP[state.IP] = state
	}
	rows, err := db.Query(`SELECT event_id,ip,app_id FROM node_edge_events WHERE status='kernel_applied' AND expires_at<=?`, now.Unix())
	if err != nil {
		return err
	}
	type eventRow struct{ id, ip, appID string }
	var pending []eventRow
	for rows.Next() {
		var row eventRow
		if err := rows.Scan(&row.id, &row.ip, &row.appID); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, row := range pending {
		grants, err := liveUEE.Grants(row.ip, now)
		if err != nil {
			return err
		}
		stillOwned := false
		for _, grant := range grants {
			if grant.Owner == appGrantOwner(row.appID, row.id) {
				stillOwned = true
				break
			}
		}
		if stillOwned {
			continue
		}
		state := stateByIP[row.ip]
		if state.KernelApplied && state.Owners == 0 {
			continue
		}
		if _, err := db.Exec(`UPDATE node_edge_events SET status='expired',detail='ttl_elapsed' WHERE event_id=? AND status='kernel_applied'`, row.id); err != nil {
			return err
		}
	}
	return nil
}

func startNodeEdgeBridge(shutdown <-chan struct{}) error {
	if appsFile := os.Getenv("HM_EDGE_APPS_FILE"); appsFile != "" {
		if os.Getenv("HM_EDGE_SOCKET") != "" {
			return errors.New("HM_EDGE_APPS_FILE cannot be combined with HM_EDGE_SOCKET")
		}
		return startNodeEdgeApps(shutdown, appsFile)
	}
	socketPath := os.Getenv("HM_EDGE_SOCKET")
	if socketPath == "" {
		return nil
	}
	if !filepath.IsAbs(socketPath) {
		return errors.New("HM_EDGE_SOCKET must be absolute")
	}
	secretPath := os.Getenv("HM_EDGE_SECRET_FILE")
	if secretPath == "" {
		return errors.New("HM_EDGE_SECRET_FILE is required")
	}
	secret, err := os.ReadFile(secretPath)
	if err != nil {
		return err
	}
	secret = []byte(strings.TrimSpace(string(secret)))
	canarySources, err := parseNodeEdgeCanarySources(os.Getenv("HM_EDGE_CANARY_IPS"))
	if err != nil {
		return err
	}
	autoBlock := os.Getenv("HM_EDGE_AUTOBLOCK") == "true"
	if autoBlock && len(canarySources) == 0 {
		return errors.New("HM_EDGE_AUTOBLOCK requires at least one exact HM_EDGE_CANARY_IPS address")
	}
	c := &nodeEdgeController{
		db: db, autoBlock: autoBlock,
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
		Secret: secret, ExpectedSource: os.Getenv("HM_EDGE_APP_SOURCE"), AllowedSource: nodeEdgeSourceAllowed,
		OnEvent: c.onEvent, ActiveBlocks: nodeEdgeActiveBlocks,
		AgentMode: func(context.Context) (string, error) { return strings.ToUpper(Mode().String()), nil },
	})
	if err != nil {
		return err
	}
	if _, err := os.Lstat(socketPath); err == nil {
		return errors.New("node edge socket already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(socketPath, 0660); err != nil {
		listener.Close()
		return err
	}
	liveNodeEdge = c
	server := &http.Server{Handler: bridge.Handler(), ConnContext: agentbridge.UnixPeerContext, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8 * 1024}
	go func() {
		<-shutdown
		_ = server.Close()
		_ = os.Remove(socketPath)
	}()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[NODE_EDGE] socket server failed: %v", err)
		}
	}()
	log.Printf("[NODE_EDGE] local socket ready auto_block=%v", c.autoBlock)
	return nil
}
