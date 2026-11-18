package main

import (
	"context"
	"database/sql"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────
// INIT DB
// ─────────────────────────────────────────────

func initDB() {
	var err error

	db, err = sql.Open("sqlite", "file:honeymesh.db?_pragma=busy_timeout(5000)")
	if err != nil {
		log.Fatalf("[DB] Failed to open database: %v", err)
	}

	// SQLite tuning for production
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Enable WAL mode for concurrent reads/writes
	_, _ = db.Exec("PRAGMA journal_mode=WAL")
	_, _ = db.Exec("PRAGMA synchronous=NORMAL")

	createTables()

	log.Println("[DB] SQLite initialized with WAL mode")
}

// ─────────────────────────────────────────────
// SCHEMA
// ─────────────────────────────────────────────

func createTables() {
	eventTable := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT,
		attacker TEXT,
		target_ip TEXT,
		target TEXT,
		service TEXT,
		node TEXT,
		type TEXT,
		payload TEXT,
		entropy REAL,
		interface TEXT,
		ja4 TEXT,
		ja3 TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_attacker ON events(attacker);
	`

	banTable := `
	CREATE TABLE IF NOT EXISTS bans (
		ip TEXT PRIMARY KEY,
		expires INTEGER
	);
	`
	trustTable := `
	CREATE TABLE IF NOT EXISTS peer_trust (
		peer TEXT PRIMARY KEY,
		score REAL,
		total INTEGER,
		valid INTEGER,
		invalid INTEGER,
		last_report INTEGER
	);
	`

	if _, err := db.Exec(eventTable); err != nil {
		log.Fatalf("[DB] Failed to create events table: %v", err)
	}
	ensureEventColumn("ja4", "TEXT")
	ensureEventColumn("tls_fingerprint_family", "TEXT")
	ensureEventColumn("tls_fingerprint_version", "TEXT")
	ensureEventColumn("tls_fingerprint_confidence", "INTEGER")

	if _, err := db.Exec(banTable); err != nil {
		log.Fatalf("[DB] Failed to create bans table: %v", err)
	}
	if _, err := db.Exec(trustTable); err != nil {
		log.Fatalf("[DB] Failed to create peer_trust table: %v", err)
	}
}

func ensureEventColumn(name string, colType string) {
	rows, err := db.Query("PRAGMA table_info(events)")
	if err != nil {
		log.Printf("[DB] Failed to inspect events schema: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			colName    string
			dataType   string
			notNull    int
			defaultV   sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &colName, &dataType, &notNull, &defaultV, &primaryKey); err != nil {
			log.Printf("[DB] Failed to scan events schema: %v", err)
			return
		}
		if colName == name {
			return
		}
	}

	if _, err := db.Exec("ALTER TABLE events ADD COLUMN " + name + " " + colType); err != nil {
		log.Printf("[DB] Failed to add events.%s: %v", name, err)
	}
}

// ─────────────────────────────────────────────
// EVENT STORAGE
// ─────────────────────────────────────────────

func storeEvent(e Event) {
	if db == nil {
		return
	}

	_, err := db.Exec(`
	INSERT INTO events (
		timestamp, attacker, target_ip, target, service, node, type, payload, entropy, interface, ja4, ja3, tls_fingerprint_family, tls_fingerprint_version, tls_fingerprint_confidence
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp,
		e.Attacker,
		e.TargetIP,
		e.Target,
		e.Service,
		e.Node,
		e.Type,
		e.Payload,
		e.Entropy,
		e.Interface,
		e.JA4,
		e.JA3,
		e.TLSFingerprintFamily,
		e.TLSFingerprintVersion,
		e.TLSFingerprintConfidence,
	)

	if err != nil {
		log.Printf("[DB] Failed to insert event: %v", err)
	}
}

func startDBWriter(shutdown chan struct{}) {
	if db == nil {
		return
	}
	log.Println("[DB] Event writer started")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	batch := make([]Event, 0, 200)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		tx, err := db.Begin()
		if err != nil {
			log.Printf("[DB] Failed to begin tx: %v", err)
			return
		}
		stmt, err := tx.Prepare(`
		INSERT INTO events (
			timestamp, attacker, target_ip, target, service, node, type, payload, entropy, interface, ja4, ja3, tls_fingerprint_family, tls_fingerprint_version, tls_fingerprint_confidence
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			_ = tx.Rollback()
			log.Printf("[DB] Failed to prepare insert: %v", err)
			return
		}
		for _, e := range batch {
			if _, err := stmt.Exec(
				e.Timestamp,
				e.Attacker,
				e.TargetIP,
				e.Target,
				e.Service,
				e.Node,
				e.Type,
				e.Payload,
				e.Entropy,
				e.Interface,
				e.JA4,
				e.JA3,
				e.TLSFingerprintFamily,
				e.TLSFingerprintVersion,
				e.TLSFingerprintConfidence,
			); err != nil {
				log.Printf("[DB] Failed to insert event: %v", err)
			}
		}
		_ = stmt.Close()
		if err := tx.Commit(); err != nil {
			log.Printf("[DB] Failed to commit: %v", err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case e := <-storeChan:
			batch = append(batch, e)
			if len(batch) >= 200 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-shutdown:
			flush()
			return
		}
	}
}

// ─────────────────────────────────────────────
// LOAD EVENT HISTORY (on boot)
// ─────────────────────────────────────────────

func loadHistoryFromDB() {
	if db == nil {
		return
	}

	rows, err := db.Query(`
	SELECT timestamp, attacker, target_ip, target, service, node, type, payload, entropy, interface, ja4, ja3, tls_fingerprint_family, tls_fingerprint_version, tls_fingerprint_confidence
	FROM events
	ORDER BY id DESC
	LIMIT 5000`)

	if err != nil {
		log.Printf("[DB] Failed to load history: %v", err)
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var e Event
		err := rows.Scan(
			&e.Timestamp,
			&e.Attacker,
			&e.TargetIP,
			&e.Target,
			&e.Service,
			&e.Node,
			&e.Type,
			&e.Payload,
			&e.Entropy,
			&e.Interface,
			&e.JA4,
			&e.JA3,
			&e.TLSFingerprintFamily,
			&e.TLSFingerprintVersion,
			&e.TLSFingerprintConfidence,
		)
		if err != nil {
			continue
		}

		addEvent(e)
		count++
	}

	log.Printf("[DB] Loaded %d historical events", count)
}

// ─────────────────────────────────────────────
// PEER TRUST STORAGE
// ─────────────────────────────────────────────

func loadPeerTrustFromDB() {
	if db == nil {
		return
	}
	rows, err := db.Query(`
	SELECT peer, score, total, valid, invalid, last_report
	FROM peer_trust`)
	if err != nil {
		log.Printf("[DB] Failed to load peer trust: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var peer string
		var score float64
		var total, valid, invalid int
		var lastReport int64
		if err := rows.Scan(&peer, &score, &total, &valid, &invalid, &lastReport); err != nil {
			continue
		}
		t := &peerTrust{
			Peer:       peer,
			Score:      score,
			Total:      total,
			Valid:      valid,
			Invalid:    invalid,
			LastReport: time.Unix(lastReport, 0),
		}
		trustByPeer[peer] = t
	}
}

func persistPeerTrust(t *peerTrust) {
	if db == nil || t == nil {
		return
	}
	_, err := db.Exec(`
	INSERT INTO peer_trust (peer, score, total, valid, invalid, last_report)
	VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT(peer) DO UPDATE SET
		score=excluded.score,
		total=excluded.total,
		valid=excluded.valid,
		invalid=excluded.invalid,
		last_report=excluded.last_report
	`, t.Peer, t.Score, t.Total, t.Valid, t.Invalid, t.LastReport.Unix())
	if err != nil {
		log.Printf("[DB] Failed to persist peer trust: %v", err)
	}
}

// ─────────────────────────────────────────────
// BAN STORAGE
// ─────────────────────────────────────────────

func persistBan(ip string, expires time.Time) {
	if db == nil {
		return
	}

	_, err := db.Exec(`
	INSERT OR REPLACE INTO bans (ip, expires)
	VALUES (?, ?)`,
		ip,
		expires.Unix(),
	)

	if err != nil {
		log.Printf("[DB] Failed to persist ban for %s: %v", ip, err)
	}
}

func removeBan(ip string) {
	if db == nil {
		return
	}

	_, _ = db.Exec(`DELETE FROM bans WHERE ip = ?`, ip)
}

// ─────────────────────────────────────────────
// LOAD BANS (on boot)
// ─────────────────────────────────────────────

func loadBansFromDB() {
	if db == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, `SELECT ip, expires FROM bans`)
	if err != nil {
		log.Printf("[DB] Failed to load bans: %v", err)
		return
	}
	defer rows.Close()

	now := time.Now()
	count := 0

	for rows.Next() {
		var ip string
		var exp int64

		if err := rows.Scan(&ip, &exp); err != nil {
			continue
		}

		expTime := time.Unix(exp, 0)

		if now.After(expTime) {
			removeBan(ip)
			continue
		}

		key := normalizeIPKey(ip)
		if key == "" {
			continue
		}
		banExpirations[key] = expTime
		count++
	}

	log.Printf("[DB] Loaded %d active bans", count)
}
