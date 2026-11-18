// Package agentbridge validates signed, local application evidence before an
// agent-specific policy callback can observe or enforce it.
package agentbridge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

type Event struct {
	EventID      string `json:"event_id"`
	AppID        string `json:"app_id,omitempty"`
	Source       string `json:"source"`
	IP           string `json:"ip"`
	ReasonCode   string `json:"reason_code"`
	EvidenceHash string `json:"evidence_hash"`
	Confidence   int    `json:"confidence"`
	TTLSeconds   int    `json:"ttl_seconds"`
}

type Block struct {
	IP         string    `json:"ip"`
	ReasonCode string    `json:"reason_code"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type Config struct {
	Secret []byte
	// ExpectedSource binds this socket's credential to one application source.
	ExpectedSource string
	// ExpectedAppID and ExpectedUID bind a provisioned socket to one app.
	// Both are required for multi-application agent deployments.
	ExpectedAppID string
	ExpectedUID   *uint32
	// AllowedSource must check operator, monitor, trusted proxy, and local allowlists.
	AllowedSource func(netip.Addr) bool
	// OnEvent returns observed or blocked only after the corresponding action succeeds.
	OnEvent      func(context.Context, Event) (string, error)
	ActiveBlocks func(context.Context) ([]Block, error)
	AgentMode    func(context.Context) (string, error)
}

type Bridge struct {
	config Config
	mu     sync.Mutex
	seen   map[string]time.Time
}

type peerUIDKey struct{}

// UnixPeerContext records the kernel-provided UID of a Unix socket peer.
// The HTTP server must use this as ConnContext when ExpectedUID is configured.
func UnixPeerContext(ctx context.Context, conn net.Conn) context.Context {
	uid, err := unixPeerUID(conn)
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, peerUIDKey{}, uid)
}

func (b *Bridge) peerAllowed(ctx context.Context) bool {
	if b.config.ExpectedUID == nil {
		return true
	}
	uid, ok := ctx.Value(peerUIDKey{}).(uint32)
	return ok && uid == *b.config.ExpectedUID
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{32,64}$`)
var reasons = map[string]bool{
	"invalid_signature_burst": true, "replay_burst": true,
	"anonymous_rate_burst": true, "oversized_body_burst": true,
	"api_probe_burst": true,
}
var denied = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func New(c Config) (*Bridge, error) {
	if len(c.Secret) < 32 || (c.ExpectedSource != "node_guard" && c.ExpectedSource != "exchange_guard") || c.AllowedSource == nil || c.OnEvent == nil || c.ActiveBlocks == nil {
		return nil, errors.New("bridge requires one bound app source, a separate 32-byte secret, and all policy callbacks")
	}
	if c.ExpectedAppID != "" && !identifier.MatchString(c.ExpectedAppID) {
		return nil, errors.New("invalid expected app ID")
	}
	if (c.ExpectedAppID == "") != (c.ExpectedUID == nil) {
		return nil, errors.New("app ID and peer UID must be configured together")
	}
	if c.ExpectedUID != nil {
		uid := *c.ExpectedUID
		c.ExpectedUID = &uid
	}
	c.Secret = append([]byte(nil), c.Secret...)
	return &Bridge{config: c, seen: make(map[string]time.Time)}, nil
}

func eligible(raw string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return netip.Addr{}, false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return netip.Addr{}, false
	}
	for _, prefix := range denied {
		if prefix.Contains(ip) {
			return netip.Addr{}, false
		}
	}
	return ip, true
}

func validEvent(e Event) bool {
	_, public := eligible(e.IP)
	return (e.Source == "node_guard" || e.Source == "exchange_guard") && identifier.MatchString(e.EventID) &&
		(e.AppID == "" || identifier.MatchString(e.AppID)) && public &&
		reasons[e.ReasonCode] && hashPattern.MatchString(e.EvidenceHash) &&
		e.Confidence >= 80 && e.Confidence <= 100 && e.TTLSeconds >= 60 && e.TTLSeconds <= 300
}

func (b *Bridge) authentic(r *http.Request, body []byte) bool {
	timestamp, nonce, signature := r.Header.Get("X-Edge-Timestamp"), r.Header.Get("X-Edge-Nonce"), r.Header.Get("X-Edge-Signature")
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || time.Since(ts) > time.Minute || time.Until(ts) > time.Minute || !identifier.MatchString(nonce) {
		return false
	}
	provided, err := hex.DecodeString(signature)
	if err != nil || len(provided) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, b.config.Secret)
	_, _ = mac.Write([]byte(timestamp + "\n" + nonce + "\n"))
	_, _ = mac.Write(body)
	return hmac.Equal(mac.Sum(nil), provided)
}

func (b *Bridge) reserve(keys ...string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for key, seen := range b.seen {
		if now.Sub(seen) > 10*time.Minute {
			delete(b.seen, key)
		}
	}
	if len(b.seen)+len(keys) > 20_000 {
		return false
	}
	for _, key := range keys {
		if _, exists := b.seen[key]; exists {
			return false
		}
	}
	for _, key := range keys {
		b.seen[key] = now
	}
	return true
}

func (b *Bridge) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/event", func(w http.ResponseWriter, r *http.Request) {
		if !b.peerAllowed(r.Context()) {
			http.Error(w, "application process mismatch", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2048)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if !b.authentic(r, body) {
			http.Error(w, "invalid authentication", http.StatusForbidden)
			return
		}
		var event Event
		if json.Unmarshal(body, &event) != nil || !validEvent(event) {
			http.Error(w, "invalid event", http.StatusBadRequest)
			return
		}
		if event.Source != b.config.ExpectedSource {
			http.Error(w, "application source mismatch", http.StatusForbidden)
			return
		}
		if b.config.ExpectedAppID != "" && event.AppID != b.config.ExpectedAppID {
			http.Error(w, "application identity mismatch", http.StatusForbidden)
			return
		}
		ip, _ := eligible(event.IP)
		if !b.config.AllowedSource(ip) {
			http.Error(w, "source excluded", http.StatusForbidden)
			return
		}
		if !b.reserve("n:"+r.Header.Get("X-Edge-Nonce"), "e:"+event.EventID) {
			http.Error(w, "duplicate or busy", http.StatusConflict)
			return
		}
		status, err := b.config.OnEvent(r.Context(), event)
		if err != nil || (status != "observed" && status != "blocked") {
			http.Error(w, "agent action failed", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
	})
	mux.HandleFunc("GET /v1/active-blocks", func(w http.ResponseWriter, r *http.Request) {
		if !b.peerAllowed(r.Context()) {
			http.Error(w, "application process mismatch", http.StatusForbidden)
			return
		}
		if !b.authentic(r, nil) {
			http.Error(w, "invalid authentication", http.StatusForbidden)
			return
		}
		if !b.reserve("n:" + r.Header.Get("X-Edge-Nonce")) {
			http.Error(w, "replay or busy", http.StatusConflict)
			return
		}
		blocks, err := b.config.ActiveBlocks(r.Context())
		if err != nil {
			http.Error(w, "agent snapshot failed", http.StatusServiceUnavailable)
			return
		}
		mode := "unknown"
		if b.config.AgentMode != nil {
			mode, err = b.config.AgentMode(r.Context())
			if err != nil || (mode != "TEST" && mode != "ENFORCE" && mode != "LOCKDOWN") {
				http.Error(w, "agent mode unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		now := time.Now()
		filtered := make([]Block, 0, len(blocks))
		for _, block := range blocks {
			ip, ok := eligible(block.IP)
			if ok && b.config.AllowedSource(ip) && reasons[block.ReasonCode] && block.ExpiresAt.After(now) && block.ExpiresAt.Before(now.Add(10*time.Minute)) {
				filtered = append(filtered, block)
			}
		}
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].ExpiresAt.Before(filtered[j].ExpiresAt) })
		total := len(filtered)
		if len(filtered) > 100 {
			filtered = filtered[:100]
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"total": total, "blocks": filtered, "mode": mode})
	})
	return mux
}

// ServeUnix serves only a prearranged local path. It refuses to replace an
// existing file or socket; deployment must create and protect the parent dir.
func (b *Bridge) ServeUnix(ctx context.Context, socketPath string, mode os.FileMode) error {
	if !filepath.IsAbs(socketPath) || mode != 0600 && mode != 0660 {
		return errors.New("invalid socket path or mode")
	}
	if _, err := os.Lstat(socketPath); err == nil {
		return errors.New("socket path already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer os.Remove(socketPath)
	defer listener.Close()
	if err := os.Chmod(socketPath, mode); err != nil {
		return err
	}
	server := &http.Server{Handler: b.Handler(), ConnContext: UnixPeerContext, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8 * 1024}
	go func() { <-ctx.Done(); _ = server.Close() }()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
