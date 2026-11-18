import path from "node:path";
import { randomUUID, createHash, randomInt, scryptSync } from "node:crypto";

import Database from "better-sqlite3";
import { isPublicIndicator } from "@/lib/discovery-policy";
import { parseFeedCursor } from "@/lib/exchange-validation";

import type {
  AuditLog,
  BanFeedback,
  BanVote,
  CommunityBan,
  DashboardSummary,
  EnrollmentToken,
  LicenseRecord,
  MfaChallenge,
  NodeNonce,
  NodeRecord,
  SessionRecord,
  SyncLog,
  Tenant,
  User,
} from "@/lib/portal-types";

type PortalState = {
  users: User[];
  tenants: Tenant[];
  nodes: NodeRecord[];
  bans: CommunityBan[];
  votes: BanVote[];
  syncLogs: SyncLog[];
  auditLogs: AuditLog[];
  feedback: BanFeedback[];
  sessions: SessionRecord[];
  licenses: LicenseRecord[];
  enrollmentTokens: EnrollmentToken[];
  nodeNonces: NodeNonce[];
  mfaChallenges: MfaChallenge[];
  nodeSecrets: Record<string, string>;
};

type DBHandle = Database.Database;

declare global {
  var __honeymeshPortalDB: DBHandle | undefined;
  var __honeymeshPortalLastPruneAt: number | undefined;
}

const DEFAULT_EXCHANGE_RETENTION_SECONDS = 300;
const DEFAULT_EXCHANGE_MAX_SIGNAL_TTL_SECONDS = 300;
const DEFAULT_SYNC_LOG_RETENTION_SECONDS = 900;
const DEFAULT_AUDIT_LOG_RETENTION_SECONDS = 1800;

function readPositiveInt(input: string | undefined, fallback: number) {
  const parsed = Number(input);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.floor(parsed);
}

export function exchangeRetentionSeconds() {
  return readPositiveInt(process.env.NETTOOLS_EXCHANGE_RETENTION_SECONDS, DEFAULT_EXCHANGE_RETENTION_SECONDS);
}

export function exchangeMaxSignalTTLSeconds() {
  return Math.min(
    readPositiveInt(process.env.NETTOOLS_EXCHANGE_MAX_SIGNAL_TTL_SECONDS, DEFAULT_EXCHANGE_MAX_SIGNAL_TTL_SECONDS),
    exchangeRetentionSeconds(),
  );
}

function syncLogRetentionSeconds() {
  return Math.max(exchangeRetentionSeconds(), readPositiveInt(process.env.NETTOOLS_SYNC_LOG_RETENTION_SECONDS, DEFAULT_SYNC_LOG_RETENTION_SECONDS));
}

function auditLogRetentionSeconds() {
  return Math.max(exchangeRetentionSeconds(), readPositiveInt(process.env.NETTOOLS_AUDIT_LOG_RETENTION_SECONDS, DEFAULT_AUDIT_LOG_RETENTION_SECONDS));
}

function maybePruneExchangeState() {
  const now = Date.now();
  if (globalThis.__honeymeshPortalLastPruneAt && now-globalThis.__honeymeshPortalLastPruneAt < 30_000) {
    return;
  }
  globalThis.__honeymeshPortalLastPruneAt = now;
  pruneExchangeState();
}

function pruneExchangeState() {
  const db = getDB();
  const now = new Date();
  const nowIso = now.toISOString();
  const exchangeCutoff = new Date(now.getTime() - exchangeRetentionSeconds() * 1000).toISOString();
  const syncCutoff = new Date(now.getTime() - syncLogRetentionSeconds() * 1000).toISOString();
  const auditCutoff = new Date(now.getTime() - auditLogRetentionSeconds() * 1000).toISOString();
  const nonceCutoff = new Date(now.getTime() - 10 * 60_000).toISOString();
  const retractionCutoff = new Date(now.getTime() - 7 * 24 * 60 * 60_000).toISOString();
  const tx = db.transaction(() => {
    db.prepare(`
      DELETE FROM bans
      WHERE datetime(last_seen, '+' || ttl || ' seconds') < datetime(?)
         OR datetime(last_seen) < datetime(?)
    `).run(nowIso, exchangeCutoff);
    db.prepare("DELETE FROM sync_logs WHERE datetime(created_at) < datetime(?)").run(syncCutoff);
    db.prepare("DELETE FROM audit_logs WHERE datetime(created_at) < datetime(?)").run(auditCutoff);
    db.prepare("DELETE FROM request_limits WHERE datetime(expires_at) < datetime(?)").run(nowIso);
    db.prepare("DELETE FROM node_nonces WHERE datetime(created_at) < datetime(?)").run(nonceCutoff);
    db.prepare("DELETE FROM signal_retractions WHERE datetime(retracted_at) < datetime(?)").run(retractionCutoff);
    db.prepare(`
      DELETE FROM signal_feed_deliveries
      WHERE datetime(delivered_at) < datetime(?)
        AND signal_id NOT IN (SELECT id FROM bans WHERE status = 'approved')
    `).run(retractionCutoff);
    db.prepare("DELETE FROM mfa_challenges WHERE datetime(expires_at) < datetime(?)").run(nowIso);
    db.prepare("DELETE FROM enrollment_tokens WHERE datetime(expires_at) < datetime(?) AND used_at IS NOT NULL").run(nowIso);
    db.prepare("DELETE FROM exchange_guard_controls WHERE datetime(started_at) < datetime(?)").run(new Date(now.getTime() - 30 * 24 * 60 * 60_000).toISOString());
    db.prepare("DELETE FROM exchange_activity_records WHERE datetime(observed_at) < datetime(?)").run(new Date(now.getTime() - 90 * 24 * 60 * 60_000).toISOString());
    db.prepare("UPDATE exchange_activity_records SET source_ip=NULL WHERE source_ip IS NOT NULL AND datetime(observed_at) < datetime(?)")
      .run(new Date(now.getTime() - 30 * 24 * 60 * 60_000).toISOString());
  });
  tx();
}

function nowPlus(minutes: number) {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function hashPasswordSeed(password: string) {
  return scryptSync(password, "honeymesh-portal", 32).toString("hex");
}

function hashNodeSecretSeed(secret: string) {
  return createHash("sha256").update(secret).digest("hex");
}

function databasePath() {
  const raw = process.env.DATABASE_URL?.trim();
  if (!raw) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("DATABASE_URL must name a durable SQLite file in production");
    }
    return path.resolve(/* turbopackIgnore: true */ process.cwd(), "dev.db");
  }
  if (!raw.startsWith("file:")) {
    throw new Error("Exchange currently supports only a file: SQLite DATABASE_URL");
  }
  return path.resolve(/* turbopackIgnore: true */ process.cwd(), raw.slice(5));
}

export function getDB() {
  if (!globalThis.__honeymeshPortalDB) {
    const db = new Database(databasePath());
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    initializeDB(db);
    globalThis.__honeymeshPortalDB = db;
  }
  return globalThis.__honeymeshPortalDB;
}

function ensureColumn(db: DBHandle, table: string, column: string, definition: string) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (!columns.some((item) => item.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

function initializeDB(db: DBHandle) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      role TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      mfa_enabled INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      plan TEXT NOT NULL,
      sharing_enabled INTEGER NOT NULL DEFAULT 0,
      exchange_kill_switch INTEGER NOT NULL DEFAULT 0,
      review_only_mode INTEGER NOT NULL DEFAULT 0,
      auto_approve_enabled INTEGER NOT NULL DEFAULT 1,
      trust_level INTEGER NOT NULL,
      license_status TEXT NOT NULL,
      local_policy_mode TEXT NOT NULL,
      license_id TEXT
    );

    CREATE TABLE IF NOT EXISTS nodes (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      cluster_id TEXT NOT NULL,
      node_name TEXT NOT NULL,
      api_key_hash TEXT NOT NULL,
      public_key TEXT NOT NULL,
      status TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      trust_level INTEGER NOT NULL,
      software_version TEXT NOT NULL,
      machine_fingerprint TEXT,
      revoked_at TEXT
    );

    CREATE TABLE IF NOT EXISTS node_credentials (
      node_id TEXT PRIMARY KEY,
      shared_secret TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS bans (
      id TEXT PRIMARY KEY,
      source_type TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      node_id TEXT,
      attacker_ip TEXT NOT NULL,
      cidr TEXT,
      ja4 TEXT NOT NULL,
      ja3_legacy TEXT NOT NULL,
      attack_type TEXT NOT NULL,
      protocol TEXT NOT NULL,
      port INTEGER NOT NULL,
      service TEXT NOT NULL,
      confidence INTEGER NOT NULL,
      reason TEXT NOT NULL,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      ttl INTEGER NOT NULL,
      status TEXT NOT NULL,
      evidence_hash TEXT NOT NULL,
      trust_score_at_submission INTEGER NOT NULL,
      publisher TEXT NOT NULL,
      source_channel TEXT NOT NULL,
      action_taken TEXT NOT NULL,
      mode TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS signal_feed_deliveries (
      recipient_tenant_id TEXT NOT NULL,
      signal_id TEXT NOT NULL,
      delivered_at TEXT NOT NULL,
      PRIMARY KEY (recipient_tenant_id, signal_id)
    );

    CREATE TABLE IF NOT EXISTS signal_retractions (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      signal_id TEXT NOT NULL UNIQUE,
      source_tenant_id TEXT NOT NULL,
      cluster_id TEXT NOT NULL,
      attacker_ip TEXT NOT NULL,
      retracted_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_signal_retractions_seq ON signal_retractions(seq);

    CREATE TABLE IF NOT EXISTS votes (
      id TEXT PRIMARY KEY,
      ban_id TEXT NOT NULL,
      reviewer_user_id TEXT NOT NULL,
      action TEXT NOT NULL,
      notes TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sync_logs (
      id TEXT PRIMARY KEY,
      node_id TEXT NOT NULL,
      sync_type TEXT NOT NULL,
      success INTEGER NOT NULL,
      records_count INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      actor_type TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      action TEXT NOT NULL,
      reason_code TEXT,
      details TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS feedback (
      id TEXT PRIMARY KEY,
      node_id TEXT NOT NULL,
      ban_id TEXT NOT NULL,
      useful INTEGER NOT NULL,
      notes TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS licenses (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL UNIQUE,
      tier TEXT NOT NULL,
      status TEXT NOT NULL,
      issued_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      license_fingerprint TEXT NOT NULL,
      raw_metadata_json TEXT NOT NULL,
      mesh_scope_expires_at TEXT,
      last_validated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS enrollment_tokens (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_by_user_id TEXT NOT NULL,
      allowed_ip TEXT,
      node_name_hint TEXT
    );

    CREATE TABLE IF NOT EXISTS node_nonces (
      id TEXT PRIMARY KEY,
      node_id TEXT NOT NULL,
      nonce TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS mfa_challenges (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      code TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS request_limits (
      bucket_key TEXT PRIMARY KEY,
      count INTEGER NOT NULL,
      expires_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS exchange_guard_controls (
      id INTEGER PRIMARY KEY,
      source_id TEXT NOT NULL,
      reason_code TEXT NOT NULL,
      started_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_exchange_guard_controls_started ON exchange_guard_controls(started_at DESC);

    CREATE TABLE IF NOT EXISTS exchange_activity_records (
      id INTEGER PRIMARY KEY,
      external_id TEXT NOT NULL UNIQUE,
      source_id TEXT NOT NULL,
      source_ip TEXT,
      reason_code TEXT NOT NULL,
      protocol TEXT NOT NULL,
      service_class TEXT NOT NULL,
      detector TEXT NOT NULL,
      action TEXT NOT NULL,
      observed_at TEXT NOT NULL,
      expires_at TEXT,
      enforced_at TEXT,
      hit_count INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_exchange_activity_observed ON exchange_activity_records(observed_at DESC, id DESC);
    CREATE INDEX IF NOT EXISTS idx_exchange_activity_reason ON exchange_activity_records(reason_code, observed_at DESC);
    CREATE TABLE IF NOT EXISTS exchange_activity_meta (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      truncated_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_nodes_tenant ON nodes(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_bans_tenant_seen ON bans(tenant_id, last_seen DESC);
    CREATE INDEX IF NOT EXISTS idx_sync_logs_node ON sync_logs(node_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit_logs(tenant_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_node_nonces_node ON node_nonces(node_id, created_at DESC);
  `);

  ensureColumn(db, "tenants", "exchange_kill_switch", "INTEGER NOT NULL DEFAULT 0");
  ensureColumn(db, "tenants", "review_only_mode", "INTEGER NOT NULL DEFAULT 0");
  ensureColumn(db, "tenants", "auto_approve_enabled", "INTEGER NOT NULL DEFAULT 1");
  ensureColumn(db, "audit_logs", "reason_code", "TEXT");
  ensureColumn(db, "licenses", "mesh_scope_expires_at", "TEXT");
  ensureColumn(db, "exchange_activity_records", "source_ip", "TEXT");
  db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_fingerprint ON licenses(license_fingerprint)");
  db.exec(`
    INSERT OR IGNORE INTO exchange_activity_records
      (external_id, source_id, reason_code, protocol, service_class, detector, action, observed_at, expires_at, enforced_at, hit_count)
    SELECT 'legacy-' || id, source_id, reason_code, 'Unknown', 'Exchange machine API', 'Exchange Guard',
      'limit_armed', started_at, expires_at, NULL, 0
    FROM exchange_guard_controls
  `);
  if (process.env.NETTOOLS_SEED_DEMO === "true" && process.env.NODE_ENV !== "production") {
    cleanupLegacyCommunityDemoState(db);
    const hasUsers = db.prepare("SELECT COUNT(*) as count FROM users").get() as { count: number };
    if (!hasUsers.count) seedPortal(db);
  }
}

export function recordExchangeGuardControl(input: { sourceId: string; reasonCode: string; startedAt: string; expiresAt: string }) {
  const db = getDB();
  db.transaction(() => {
    db.prepare("INSERT INTO exchange_guard_controls (source_id, reason_code, started_at, expires_at) VALUES (?, ?, ?, ?)")
      .run(input.sourceId, input.reasonCode, input.startedAt, input.expiresAt);
    db.prepare("DELETE FROM exchange_guard_controls WHERE datetime(started_at) < datetime(?)")
      .run(new Date(Date.now() - 24 * 60 * 60_000).toISOString());
    db.prepare("DELETE FROM exchange_guard_controls WHERE id NOT IN (SELECT id FROM exchange_guard_controls ORDER BY id DESC LIMIT 500)").run();
  })();
}

export function recentExchangeGuardControls() {
  const cutoff = new Date(Date.now() - 24 * 60 * 60_000).toISOString();
  return getDB().prepare("SELECT source_id AS sourceId, reason_code AS reasonCode, started_at AS startedAt, expires_at AS expiresAt FROM exchange_guard_controls WHERE datetime(started_at) >= datetime(?) ORDER BY id DESC LIMIT 30")
    .all(cutoff) as Array<{ sourceId: string; reasonCode: string; startedAt: string; expiresAt: string }>;
}

function cleanupLegacyCommunityDemoState(db: DBHandle) {
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM node_credentials WHERE node_id = 'node-bravo-edge'").run();
    db.prepare("DELETE FROM feedback WHERE node_id = 'node-bravo-edge'").run();
    db.prepare("DELETE FROM sync_logs WHERE node_id = 'node-bravo-edge'").run();
    db.prepare("DELETE FROM node_nonces WHERE node_id = 'node-bravo-edge'").run();
    db.prepare("DELETE FROM nodes WHERE id = 'node-bravo-edge' OR tenant_id = 'tenant-local-bravo'").run();
    db.prepare("DELETE FROM sessions WHERE user_id = 'user-analyst-1'").run();
    db.prepare("DELETE FROM mfa_challenges WHERE user_id = 'user-analyst-1'").run();
    db.prepare("DELETE FROM users WHERE id = 'user-analyst-1' OR tenant_id = 'tenant-local-bravo'").run();
    db.prepare("DELETE FROM votes WHERE reviewer_user_id = 'user-analyst-1'").run();
    db.prepare("DELETE FROM bans WHERE tenant_id = 'tenant-local-bravo'").run();
    db.prepare("DELETE FROM licenses WHERE id = 'license-bravo-1' OR tenant_id = 'tenant-local-bravo'").run();
    db.prepare("DELETE FROM enrollment_tokens WHERE tenant_id = 'tenant-local-bravo'").run();
    db.prepare("DELETE FROM audit_logs WHERE tenant_id = 'tenant-local-bravo'").run();
    db.prepare("DELETE FROM tenants WHERE id = 'tenant-local-bravo'").run();
  });
  tx();
}

function seedPortal(db: DBHandle) {
  const tenantA = "tenant-hive-alpha";
  const nodeA = "node-alpha-east";
  const nodeB = "node-alpha-west";
  const nodeSecretA = "hm_node_alpha_shared_secret";
  const nodeSecretB = "hm_node_beta_shared_secret";

  const insertUser = db.prepare(`
    INSERT INTO users (id, email, name, role, tenant_id, password_hash, mfa_enabled)
    VALUES (@id, @email, @name, @role, @tenantId, @passwordHash, @mfaEnabled)
  `);
  const insertTenant = db.prepare(`
    INSERT INTO tenants (id, name, plan, sharing_enabled, exchange_kill_switch, review_only_mode, auto_approve_enabled, trust_level, license_status, local_policy_mode, license_id)
    VALUES (@id, @name, @plan, @sharingEnabled, @exchangeKillSwitch, @reviewOnlyMode, @autoApproveEnabled, @trustLevel, @licenseStatus, @localPolicyMode, @licenseId)
  `);
  const insertNode = db.prepare(`
    INSERT INTO nodes (id, tenant_id, cluster_id, node_name, api_key_hash, public_key, status, last_seen, trust_level, software_version, machine_fingerprint, revoked_at)
    VALUES (@id, @tenantId, @clusterId, @nodeName, @apiKeyHash, @publicKey, @status, @lastSeen, @trustLevel, @softwareVersion, @machineFingerprint, @revokedAt)
  `);
  const insertNodeSecret = db.prepare(`
    INSERT INTO node_credentials (node_id, shared_secret)
    VALUES (@nodeId, @sharedSecret)
  `);
  const insertBan = db.prepare(`
    INSERT INTO bans (id, source_type, tenant_id, node_id, attacker_ip, cidr, ja4, ja3_legacy, attack_type, protocol, port, service, confidence, reason, first_seen, last_seen, ttl, status, evidence_hash, trust_score_at_submission, publisher, source_channel, action_taken, mode)
    VALUES (@id, @sourceType, @tenantId, @nodeId, @attackerIp, @cidr, @ja4, @ja3Legacy, @attackType, @protocol, @port, @service, @confidence, @reason, @firstSeen, @lastSeen, @ttl, @status, @evidenceHash, @trustScoreAtSubmission, @publisher, @sourceChannel, @actionTaken, @mode)
  `);
  const insertVote = db.prepare(`
    INSERT INTO votes (id, ban_id, reviewer_user_id, action, notes, created_at)
    VALUES (@id, @banId, @reviewerUserId, @action, @notes, @createdAt)
  `);
  const insertSync = db.prepare(`
    INSERT INTO sync_logs (id, node_id, sync_type, success, records_count, created_at)
    VALUES (@id, @nodeId, @syncType, @success, @recordsCount, @createdAt)
  `);
  const insertAudit = db.prepare(`
    INSERT INTO audit_logs (id, actor_type, actor_id, tenant_id, action, reason_code, details, created_at)
    VALUES (@id, @actorType, @actorId, @tenantId, @action, @reasonCode, @details, @createdAt)
  `);
  const insertLicense = db.prepare(`
    INSERT INTO licenses (id, tenant_id, tier, status, issued_at, expires_at, license_fingerprint, raw_metadata_json, last_validated_at)
    VALUES (@id, @tenantId, @tier, @status, @issuedAt, @expiresAt, @licenseFingerprint, @rawMetadataJson, @lastValidatedAt)
  `);

  const tx = db.transaction(() => {
    [
      {
        id: "user-super-1",
        email: "admin@honeymesh.local",
        name: "Platform Super Admin",
        role: "super_admin",
        tenantId: tenantA,
        passwordHash: hashPasswordSeed("ChangeMe!123"),
        mfaEnabled: 1,
      },
      {
        id: "user-tenant-1",
        email: "ops@alpha.example",
        name: "Alpha Tenant Admin",
        role: "tenant_admin",
        tenantId: tenantA,
        passwordHash: hashPasswordSeed("ChangeMe!123"),
        mfaEnabled: 1,
      },
      {
        id: "user-review-1",
        email: "review@alpha.example",
        name: "Alpha Reviewer",
        role: "reviewer",
        tenantId: tenantA,
        passwordHash: hashPasswordSeed("ChangeMe!123"),
        mfaEnabled: 1,
      },
    ].forEach((row) => insertUser.run(row));

    [
      {
        id: tenantA,
        name: "Hive Alpha",
        plan: "pro",
        sharingEnabled: 1,
        exchangeKillSwitch: 0,
        reviewOnlyMode: 0,
        autoApproveEnabled: 1,
        trustLevel: 92,
        licenseStatus: "active",
        localPolicyMode: "auto_high_confidence",
        licenseId: "license-alpha-1",
      },
    ].forEach((row) => insertTenant.run(row));

    [
      {
        id: nodeA,
        tenantId: tenantA,
        clusterId: "cluster-alpha",
        nodeName: "alpha-east-1",
        apiKeyHash: hashNodeSecretSeed(nodeSecretA),
        publicKey: "pub-alpha-east",
        status: "online",
        lastSeen: nowPlus(-2),
        trustLevel: 95,
        softwareVersion: "2.2.3",
        machineFingerprint: "machine-alpha-east",
        revokedAt: null,
        sharedSecret: nodeSecretA,
      },
      {
        id: nodeB,
        tenantId: tenantA,
        clusterId: "cluster-alpha",
        nodeName: "alpha-west-2",
        apiKeyHash: hashNodeSecretSeed(nodeSecretB),
        publicKey: "pub-alpha-west",
        status: "degraded",
        lastSeen: nowPlus(-18),
        trustLevel: 71,
        softwareVersion: "2.2.3",
        machineFingerprint: "machine-alpha-west",
        revokedAt: null,
        sharedSecret: nodeSecretB,
      },
    ].forEach(({ sharedSecret, ...row }) => {
      insertNode.run(row);
      insertNodeSecret.run({ nodeId: row.id, sharedSecret });
    });

    [
      {
        id: "ban-1",
        sourceType: "honeymesh_node",
        tenantId: tenantA,
        nodeId: nodeA,
        attackerIp: "185.203.116.14",
        cidr: null,
        ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1",
        ja3Legacy: "769,4865-4866-4867,0-11-10-35-16-5-13,29-23-24,0",
        attackType: "credential_abuse",
        protocol: "tcp",
        port: 22,
        service: "ssh",
        confidence: 97,
        reason: "Repeated SSH credential stuffing against decoy port",
        firstSeen: nowPlus(-180),
        lastSeen: nowPlus(-12),
        ttl: 7200,
        status: "approved",
        evidenceHash: "evidence-a4e57",
        trustScoreAtSubmission: 95,
        publisher: "alpha-east-1",
        sourceChannel: "local",
        actionTaken: "temporary_ban",
        mode: "auto_high_confidence",
      },
      {
        id: "ban-2",
        sourceType: "honeymesh_node",
        tenantId: tenantA,
        nodeId: nodeB,
        attackerIp: "103.77.192.88",
        cidr: null,
        ja4: "t13d1911h2_7b37ac45c91a_b42d2e5ff1ea",
        ja3Legacy: "",
        attackType: "scan_campaign",
        protocol: "tcp",
        port: 443,
        service: "https",
        confidence: 74,
        reason: "High-rate JA4-linked TLS scanning campaign across multiple services",
        firstSeen: nowPlus(-320),
        lastSeen: nowPlus(-9),
        ttl: 3600,
        status: "pending",
        evidenceHash: "evidence-b2f88",
        trustScoreAtSubmission: 71,
        publisher: "alpha-west-2",
        sourceChannel: "local",
        actionTaken: "stage",
        mode: "suggested",
      },
      {
        id: "ban-3",
        sourceType: "portal",
        tenantId: tenantA,
        nodeId: null,
        attackerIp: "45.146.165.32",
        cidr: null,
        ja4: "t13d1517h2_6a5fa2f20a9c_e7a12d31fe81",
        ja3Legacy: "",
        attackType: "botnet",
        protocol: "tcp",
        port: 8080,
        service: "http-alt",
        confidence: 91,
        reason: "Manually promoted botnet control scanner from analyst review queue",
        firstSeen: nowPlus(-600),
        lastSeen: nowPlus(-45),
        ttl: 14400,
        status: "approved",
        evidenceHash: "evidence-c3a77",
        trustScoreAtSubmission: 88,
        publisher: "Portal Analyst",
        sourceChannel: "community",
        actionTaken: "high_confidence_ban",
        mode: "auto_high_confidence",
      },
      {
        id: "ban-4",
        sourceType: "honeymesh_node",
        tenantId: tenantA,
        nodeId: nodeA,
        attackerIp: "198.51.100.27",
        cidr: null,
        ja4: "t13d1516h2_8daaf6152771_5f67c0bd0d80",
        ja3Legacy: "",
        attackType: "tls_scanner",
        protocol: "tcp",
        port: 443,
        service: "https",
        confidence: 89,
        reason: "Blocked repeated JA4-linked TLS scanner probing HTTPS decoy",
        firstSeen: nowPlus(-90),
        lastSeen: nowPlus(-21),
        ttl: 10800,
        status: "approved",
        evidenceHash: "evidence-d4c11",
        trustScoreAtSubmission: 95,
        publisher: "alpha-east-1",
        sourceChannel: "local",
        actionTaken: "high_confidence_ban",
        mode: "auto_high_confidence",
      },
      {
        id: "ban-5",
        sourceType: "portal",
        tenantId: tenantA,
        nodeId: null,
        attackerIp: "203.0.113.44",
        cidr: "203.0.113.44/32",
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        ja3Legacy: "18ad6e1a77c00d96229ccb62a794860d",
        attackType: "campaign_overlap",
        protocol: "tcp",
        port: 443,
        service: "https",
        confidence: 93,
        reason: "Approved community signal correlating with active JA4 cluster across trusted tenants",
        firstSeen: nowPlus(-75),
        lastSeen: nowPlus(-30),
        ttl: 86400,
        status: "approved",
        evidenceHash: "evidence-e9f31",
        trustScoreAtSubmission: 90,
        publisher: "HoneyMesh Defense Network",
        sourceChannel: "community",
        actionTaken: "temporary_ban",
        mode: "auto_temp",
      },
    ].forEach((row) => insertBan.run(row));

    insertVote.run({
      id: "vote-1",
      banId: "ban-2",
      reviewerUserId: "user-review-1",
      action: "approve",
      notes: "Corroborated by two Alpha nodes and matches known JA4 cluster",
      createdAt: nowPlus(-8),
    });

    [
      { id: "sync-1", nodeId: nodeA, syncType: "pull", success: 1, recordsCount: 42, createdAt: nowPlus(-6) },
      { id: "sync-2", nodeId: nodeB, syncType: "push", success: 1, recordsCount: 3, createdAt: nowPlus(-16) },
    ].forEach((row) => insertSync.run(row));

    insertAudit.run({
      id: "audit-1",
      actorType: "system",
      actorId: "seed",
      tenantId: tenantA,
      action: "bootstrap",
      reasonCode: null,
      details: "Seeded demo state for HoneyMesh Defense Network Portal",
      createdAt: new Date().toISOString(),
    });

    [
      {
        id: "license-alpha-1",
        tenantId: tenantA,
        tier: "pro",
        status: "active",
        issuedAt: "2026-03-01T00:00:00.000Z",
        expiresAt: "2027-03-01T00:00:00.000Z",
        licenseFingerprint: "lic-alpha-fingerprint",
        rawMetadataJson: JSON.stringify({ cluster_id: "cluster-alpha", tier: "pro" }),
        lastValidatedAt: new Date().toISOString(),
      },
    ].forEach((row) => insertLicense.run(row));
  });

  tx();
}

function fromBool(value: unknown) {
  return Boolean(Number(value));
}

function mapUser(row: Record<string, unknown>): User {
  return {
    id: String(row.id),
    email: String(row.email),
    name: String(row.name),
    role: row.role as User["role"],
    tenantId: String(row.tenant_id),
    passwordHash: String(row.password_hash),
    mfaEnabled: fromBool(row.mfa_enabled),
  };
}

function mapTenant(row: Record<string, unknown>): Tenant {
  return {
    id: String(row.id),
    name: String(row.name),
    plan: row.plan as Tenant["plan"],
    sharingEnabled: fromBool(row.sharing_enabled),
    exchangeKillSwitch: fromBool(row.exchange_kill_switch),
    reviewOnlyMode: fromBool(row.review_only_mode),
    autoApproveEnabled: fromBool(row.auto_approve_enabled),
    trustLevel: Number(row.trust_level),
    licenseStatus: row.license_status as Tenant["licenseStatus"],
    localPolicyMode: row.local_policy_mode as Tenant["localPolicyMode"],
    licenseId: row.license_id ? String(row.license_id) : null,
  };
}

function mapNode(row: Record<string, unknown>): NodeRecord {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    clusterId: String(row.cluster_id),
    nodeName: String(row.node_name),
    apiKeyHash: String(row.api_key_hash),
    publicKey: String(row.public_key),
    status: row.status as NodeRecord["status"],
    lastSeen: String(row.last_seen),
    trustLevel: Number(row.trust_level),
    softwareVersion: String(row.software_version),
    machineFingerprint: row.machine_fingerprint ? String(row.machine_fingerprint) : null,
    revokedAt: row.revoked_at ? String(row.revoked_at) : null,
  };
}

function mapBan(row: Record<string, unknown>): CommunityBan {
  return {
    id: String(row.id),
    clusterId: row.source_cluster_id ? String(row.source_cluster_id) : undefined,
    sourceType: row.source_type as CommunityBan["sourceType"],
    tenantId: String(row.tenant_id),
    nodeId: row.node_id ? String(row.node_id) : null,
    attackerIp: String(row.attacker_ip),
    cidr: row.cidr ? String(row.cidr) : null,
    ja4: String(row.ja4),
    ja3Legacy: String(row.ja3_legacy),
    attackType: String(row.attack_type),
    protocol: String(row.protocol),
    port: Number(row.port),
    service: String(row.service),
    confidence: Number(row.confidence),
    reason: String(row.reason),
    firstSeen: String(row.first_seen),
    lastSeen: String(row.last_seen),
    ttl: Number(row.ttl),
    status: row.status as CommunityBan["status"],
    evidenceHash: String(row.evidence_hash),
    trustScoreAtSubmission: Number(row.trust_score_at_submission),
    publisher: String(row.publisher),
    sourceChannel: row.source_channel as CommunityBan["sourceChannel"],
    actionTaken: row.action_taken as CommunityBan["actionTaken"],
    mode: row.mode as CommunityBan["mode"],
  };
}

function mapVote(row: Record<string, unknown>): BanVote {
  return {
    id: String(row.id),
    banId: String(row.ban_id),
    reviewerUserId: String(row.reviewer_user_id),
    action: row.action as BanVote["action"],
    notes: String(row.notes),
    createdAt: String(row.created_at),
  };
}

function mapSyncLog(row: Record<string, unknown>): SyncLog {
  return {
    id: String(row.id),
    nodeId: String(row.node_id),
    syncType: row.sync_type as SyncLog["syncType"],
    success: fromBool(row.success),
    recordsCount: Number(row.records_count),
    createdAt: String(row.created_at),
  };
}

function mapAudit(row: Record<string, unknown>): AuditLog {
  return {
    id: String(row.id),
    actorType: row.actor_type as AuditLog["actorType"],
    actorId: String(row.actor_id),
    tenantId: String(row.tenant_id),
    action: String(row.action),
    reasonCode: row.reason_code ? (String(row.reason_code) as AuditLog["reasonCode"]) : null,
    details: String(row.details),
    createdAt: String(row.created_at),
  };
}

function mapFeedback(row: Record<string, unknown>): BanFeedback {
  return {
    id: String(row.id),
    nodeId: String(row.node_id),
    banId: String(row.ban_id),
    useful: fromBool(row.useful),
    notes: String(row.notes),
    createdAt: String(row.created_at),
  };
}

function mapSession(row: Record<string, unknown>): SessionRecord {
  return {
    id: String(row.id),
    userId: String(row.user_id),
    createdAt: String(row.created_at),
  };
}

function mapLicense(row: Record<string, unknown>): LicenseRecord {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    tier: row.tier as LicenseRecord["tier"],
    status: row.status as LicenseRecord["status"],
    issuedAt: String(row.issued_at),
    expiresAt: String(row.expires_at),
    licenseFingerprint: String(row.license_fingerprint),
    rawMetadataJson: String(row.raw_metadata_json),
    meshScopeExpiresAt: row.mesh_scope_expires_at == null ? null : String(row.mesh_scope_expires_at),
    lastValidatedAt: String(row.last_validated_at),
  };
}

function mapEnrollmentToken(row: Record<string, unknown>): EnrollmentToken {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    tokenHash: String(row.token_hash),
    expiresAt: String(row.expires_at),
    usedAt: row.used_at ? String(row.used_at) : null,
    createdByUserId: String(row.created_by_user_id),
    allowedIp: row.allowed_ip ? String(row.allowed_ip) : null,
    nodeNameHint: row.node_name_hint ? String(row.node_name_hint) : null,
  };
}

function mapNodeNonce(row: Record<string, unknown>): NodeNonce {
  return {
    id: String(row.id),
    nodeId: String(row.node_id),
    nonce: String(row.nonce),
    createdAt: String(row.created_at),
  };
}

function mapMfaChallenge(row: Record<string, unknown>): MfaChallenge {
  return {
    id: String(row.id),
    userId: String(row.user_id),
    code: String(row.code),
    createdAt: String(row.created_at),
    expiresAt: String(row.expires_at),
  };
}

export function getPortalState(): PortalState {
  const db = getDB();
  const nodeSecrets = Object.fromEntries(
    (db.prepare("SELECT node_id, shared_secret FROM node_credentials").all() as Array<Record<string, unknown>>).map((row) => [
      String(row.node_id),
      String(row.shared_secret),
    ]),
  );

  return {
    users: (db.prepare("SELECT * FROM users ORDER BY rowid DESC").all() as Array<Record<string, unknown>>).map(mapUser),
    tenants: (db.prepare("SELECT * FROM tenants ORDER BY rowid DESC").all() as Array<Record<string, unknown>>).map(mapTenant),
    nodes: (db.prepare("SELECT * FROM nodes ORDER BY rowid DESC").all() as Array<Record<string, unknown>>).map(mapNode),
    bans: (db.prepare("SELECT * FROM bans ORDER BY datetime(last_seen) DESC").all() as Array<Record<string, unknown>>).map(mapBan),
    votes: (db.prepare("SELECT * FROM votes ORDER BY datetime(created_at) DESC").all() as Array<Record<string, unknown>>).map(mapVote),
    syncLogs: (db.prepare("SELECT * FROM sync_logs ORDER BY datetime(created_at) DESC").all() as Array<Record<string, unknown>>).map(mapSyncLog),
    auditLogs: (db.prepare("SELECT * FROM audit_logs ORDER BY datetime(created_at) DESC").all() as Array<Record<string, unknown>>).map(mapAudit),
    feedback: (db.prepare("SELECT * FROM feedback ORDER BY datetime(created_at) DESC").all() as Array<Record<string, unknown>>).map(mapFeedback),
    sessions: (db.prepare("SELECT * FROM sessions ORDER BY datetime(created_at) DESC").all() as Array<Record<string, unknown>>).map(mapSession),
    licenses: (db.prepare("SELECT * FROM licenses ORDER BY datetime(last_validated_at) DESC").all() as Array<Record<string, unknown>>).map(mapLicense),
    enrollmentTokens: (db.prepare("SELECT * FROM enrollment_tokens ORDER BY datetime(expires_at) DESC").all() as Array<Record<string, unknown>>).map(mapEnrollmentToken),
    nodeNonces: (db.prepare("SELECT * FROM node_nonces ORDER BY datetime(created_at) DESC").all() as Array<Record<string, unknown>>).map(mapNodeNonce),
    mfaChallenges: (db.prepare("SELECT * FROM mfa_challenges ORDER BY datetime(created_at) DESC").all() as Array<Record<string, unknown>>).map(mapMfaChallenge),
    nodeSecrets,
  };
}

export function findUserByEmail(email: string) {
  const row = getDB().prepare("SELECT * FROM users WHERE lower(email) = lower(?) LIMIT 1").get(email) as Record<string, unknown> | undefined;
  return row ? mapUser(row) : null;
}

export function findUserByID(id: string) {
  const row = getDB().prepare("SELECT * FROM users WHERE id = ? LIMIT 1").get(id) as Record<string, unknown> | undefined;
  return row ? mapUser(row) : null;
}

export function createTenantAdmin(input: { tenantId: string; userId: string; organizationName: string; email: string; name: string; passwordHash: string; mfaEnabled: boolean }) {
  const db = getDB();
  const tx = db.transaction(() => {
    db.prepare(`
      INSERT INTO tenants (id, name, plan, sharing_enabled, exchange_kill_switch, review_only_mode, auto_approve_enabled, trust_level, license_status, local_policy_mode, license_id)
      VALUES (?, ?, 'community', 0, 0, 0, 1, 25, 'active', 'audit_only', NULL)
    `).run(input.tenantId, input.organizationName);
    db.prepare(`
      INSERT INTO users (id, email, name, role, tenant_id, password_hash, mfa_enabled)
      VALUES (?, ?, ?, 'tenant_admin', ?, ?, ?)
    `).run(input.userId, input.email, input.name, input.tenantId, input.passwordHash, input.mfaEnabled ? 1 : 0);
  });
  tx();
}

export function findSession(id: string) {
  const row = getDB().prepare("SELECT * FROM sessions WHERE id = ? LIMIT 1").get(id) as Record<string, unknown> | undefined;
  return row ? mapSession(row) : null;
}

export function saveSession(session: SessionRecord) {
  getDB().prepare("INSERT INTO sessions (id, user_id, created_at) VALUES (?, ?, ?)").run(session.id, session.userId, session.createdAt);
}

export function removeSession(id: string) {
  getDB().prepare("DELETE FROM sessions WHERE id = ?").run(id);
}

export function findNodeByID(id: string) {
  const row = getDB().prepare("SELECT * FROM nodes WHERE id = ? LIMIT 1").get(id) as Record<string, unknown> | undefined;
  return row ? mapNode(row) : null;
}

export function findNodeByFingerprint(tenantId: string, clusterId: string, machineFingerprint: string | null) {
  if (!machineFingerprint) {
    return null;
  }
  const row = getDB()
    .prepare(`
      SELECT * FROM nodes
      WHERE tenant_id = ? AND cluster_id = ? AND machine_fingerprint = ? AND revoked_at IS NULL
      LIMIT 1
    `)
    .get(tenantId, clusterId, machineFingerprint) as Record<string, unknown> | undefined;
  return row ? mapNode(row) : null;
}

export function findNodeSecret(nodeId: string) {
  const row = getDB().prepare("SELECT shared_secret FROM node_credentials WHERE node_id = ? LIMIT 1").get(nodeId) as { shared_secret?: string } | undefined;
  return row?.shared_secret ?? null;
}

export function findTenantByID(id: string) {
  const row = getDB().prepare("SELECT * FROM tenants WHERE id = ? LIMIT 1").get(id) as Record<string, unknown> | undefined;
  return row ? mapTenant(row) : null;
}

export function createMachineTenant(input: {
  id: string;
  name: string;
  licenseStatus: Tenant["licenseStatus"];
  plan: Tenant["plan"];
}) {
  getDB()
    .prepare(`
      INSERT OR IGNORE INTO tenants (id, name, plan, sharing_enabled, exchange_kill_switch, review_only_mode, auto_approve_enabled, trust_level, license_status, local_policy_mode, license_id)
      VALUES (?, ?, ?, 0, 0, 1, 0, 70, ?, 'audit_only', NULL)
    `)
    .run(input.id, input.name, input.plan, input.licenseStatus);
  return findTenantByID(input.id);
}

export function updateTenantExchangeControls(
  tenantId: string,
  controls: Partial<Pick<Tenant, "sharingEnabled" | "exchangeKillSwitch" | "reviewOnlyMode" | "autoApproveEnabled" | "localPolicyMode">>,
) {
  const tenant = findTenantByID(tenantId);
  if (!tenant) {
    return null;
  }
  const next = {
    sharingEnabled: controls.sharingEnabled ?? tenant.sharingEnabled,
    exchangeKillSwitch: controls.exchangeKillSwitch ?? tenant.exchangeKillSwitch,
    reviewOnlyMode: controls.reviewOnlyMode ?? tenant.reviewOnlyMode,
    autoApproveEnabled: controls.autoApproveEnabled ?? tenant.autoApproveEnabled,
    localPolicyMode: controls.localPolicyMode ?? tenant.localPolicyMode,
  };
  getDB()
    .prepare(`
      UPDATE tenants
      SET sharing_enabled = ?,
          exchange_kill_switch = ?,
          review_only_mode = ?,
          auto_approve_enabled = ?,
          local_policy_mode = ?
      WHERE id = ?
    `)
    .run(
      next.sharingEnabled ? 1 : 0,
      next.exchangeKillSwitch ? 1 : 0,
      next.reviewOnlyMode ? 1 : 0,
      next.autoApproveEnabled ? 1 : 0,
      next.localPolicyMode,
      tenantId,
    );
  return findTenantByID(tenantId);
}

export function findLicenseByTenantID(tenantId: string) {
  const row = getDB().prepare("SELECT * FROM licenses WHERE tenant_id = ? LIMIT 1").get(tenantId) as Record<string, unknown> | undefined;
  return row ? mapLicense(row) : null;
}

export function findLicenseByFingerprint(fingerprint: string) {
  const row = getDB().prepare("SELECT * FROM licenses WHERE license_fingerprint = ? LIMIT 1").get(fingerprint) as Record<string, unknown> | undefined;
  return row ? mapLicense(row) : null;
}

export function listBansForTenant(tenantId: string, includePending = true) {
  const rows = getDB()
    .prepare(`SELECT * FROM bans WHERE tenant_id = ? ${includePending ? "" : "AND status = 'approved'"} ORDER BY datetime(last_seen) DESC`)
    .all(tenantId) as Array<Record<string, unknown>>;
  return rows.map(mapBan);
}

export function appendAuditLog(
  input: Omit<AuditLog, "id" | "createdAt" | "reasonCode"> & Partial<Pick<AuditLog, "id" | "createdAt" | "reasonCode">>,
) {
  maybePruneExchangeState();
  const entry: AuditLog = {
    id: input.id ?? randomUUID(),
    createdAt: input.createdAt ?? new Date().toISOString(),
    actorType: input.actorType,
    actorId: input.actorId,
    tenantId: input.tenantId,
    action: input.action,
    reasonCode: input.reasonCode ?? null,
    details: input.details,
  };
  getDB()
    .prepare("INSERT INTO audit_logs (id, actor_type, actor_id, tenant_id, action, reason_code, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .run(entry.id, entry.actorType, entry.actorId, entry.tenantId, entry.action, entry.reasonCode, entry.details, entry.createdAt);
  return entry;
}

export function createManualBan(
  input: Omit<CommunityBan, "id" | "evidenceHash" | "firstSeen" | "lastSeen"> & Partial<Pick<CommunityBan, "id" | "evidenceHash">>,
) {
  maybePruneExchangeState();
  const boundedTTL = Math.max(60, Math.min(input.ttl, exchangeMaxSignalTTLSeconds()));
  const record: CommunityBan = {
    ...input,
    id: input.id ?? randomUUID(),
    firstSeen: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    ttl: boundedTTL,
    evidenceHash: input.evidenceHash ?? `manual-${randomUUID().slice(0, 8)}`,
  };
  getDB()
    .prepare(`
      INSERT INTO bans (id, source_type, tenant_id, node_id, attacker_ip, cidr, ja4, ja3_legacy, attack_type, protocol, port, service, confidence, reason, first_seen, last_seen, ttl, status, evidence_hash, trust_score_at_submission, publisher, source_channel, action_taken, mode)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      record.id,
      record.sourceType,
      record.tenantId,
      record.nodeId,
      record.attackerIp,
      record.cidr,
      record.ja4,
      record.ja3Legacy,
      record.attackType,
      record.protocol,
      record.port,
      record.service,
      record.confidence,
      record.reason,
      record.firstSeen,
      record.lastSeen,
      record.ttl,
      record.status,
      record.evidenceHash,
      record.trustScoreAtSubmission,
      record.publisher,
      record.sourceChannel,
      record.actionTaken,
      record.mode,
    );
  return record;
}

export function recentBlocksForTenant(tenantId: string, limit = 500) {
  const rows = getDB()
    .prepare(`
      SELECT * FROM bans
      WHERE tenant_id = ? AND status NOT IN ('rejected', 'expired')
      ORDER BY datetime(last_seen) DESC
      LIMIT ?
    `)
    .all(tenantId, Math.max(1, Math.min(limit, 500))) as Array<Record<string, unknown>>;
  return rows.map(mapBan);
}

export function findRecentDuplicateBan(tenantId: string, evidenceHash: string, withinSeconds = 3600) {
  maybePruneExchangeState();
  const cutoff = new Date(Date.now() - Math.min(withinSeconds, exchangeRetentionSeconds()) * 1000).toISOString();
  const row = getDB()
    .prepare(`
      SELECT * FROM bans
      WHERE tenant_id = ? AND evidence_hash = ? AND datetime(last_seen) >= datetime(?)
      ORDER BY datetime(last_seen) DESC
      LIMIT 1
    `)
    .get(tenantId, evidenceHash, cutoff) as Record<string, unknown> | undefined;
  return row ? mapBan(row) : null;
}

export function findBanByID(banId: string) {
  const row = getDB().prepare("SELECT * FROM bans WHERE id = ? LIMIT 1").get(banId) as Record<string, unknown> | undefined;
  return row ? mapBan(row) : null;
}

export function consumeRateLimit(bucketKey: string, limit: number, windowSeconds: number) {
  const db = getDB();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + windowSeconds * 1000).toISOString();
  maybePruneExchangeState();
  db.prepare("DELETE FROM request_limits WHERE datetime(expires_at) < datetime(?)").run(now.toISOString());
  const current = db.prepare("SELECT count, expires_at FROM request_limits WHERE bucket_key = ? LIMIT 1").get(bucketKey) as { count: number; expires_at: string } | undefined;
  if (!current || Date.parse(current.expires_at) <= now.getTime()) {
    db.prepare("INSERT OR REPLACE INTO request_limits (bucket_key, count, expires_at) VALUES (?, ?, ?)").run(bucketKey, 1, expiresAt);
    return { allowed: true as const, remaining: Math.max(limit - 1, 0) };
  }
  if (current.count >= limit) {
    return { allowed: false as const, remaining: 0 };
  }
  db.prepare("UPDATE request_limits SET count = count + 1 WHERE bucket_key = ?").run(bucketKey);
  return { allowed: true as const, remaining: Math.max(limit - current.count - 1, 0) };
}

export function listCommunityFeedForTenant(tenantId: string, input: { after?: string | null; trustThreshold?: number; limit?: number }) {
  const limit = Math.max(1, Math.min(input.limit ?? 100, 250));
  const rows = getDB()
    .prepare(`
      SELECT * FROM bans
      WHERE tenant_id = ?
        AND status = 'approved'
        AND source_channel = 'community'
        AND trust_score_at_submission >= ?
        AND (
          ? IS NULL OR datetime(last_seen) > datetime(json_extract(?, '$.lastSeen'))
          OR (
            datetime(last_seen) = datetime(json_extract(?, '$.lastSeen'))
            AND id > json_extract(?, '$.id')
          )
        )
      ORDER BY datetime(last_seen) ASC, id ASC
      LIMIT ?
    `)
    .all(
      tenantId,
      input.trustThreshold ?? 0,
      input.after ?? null,
      input.after ?? null,
      input.after ?? null,
      input.after ?? null,
      limit,
    ) as Array<Record<string, unknown>>;
  const records = rows.map(mapBan);
  const tail = records.at(-1);
  const cursor = tail
    ? Buffer.from(JSON.stringify({ lastSeen: tail.lastSeen, id: tail.id }), "utf8").toString("base64url")
    : input.after ?? null;
  return { records, cursor };
}

export function listLocalNodeFeedForTenant(
  tenantId: string,
  input: { limit?: number; status?: CommunityBan["status"] | "any" },
) {
  maybePruneExchangeState();
  const limit = Math.max(1, Math.min(input.limit ?? 100, 250));
  const rows = getDB()
    .prepare(`
      SELECT * FROM bans
      WHERE tenant_id = ?
        AND source_channel = 'local'
        AND datetime(last_seen, '+' || ttl || ' seconds') >= datetime('now')
        AND datetime(last_seen) >= datetime(?)
        AND (? = 'any' OR status = ?)
      ORDER BY datetime(last_seen) DESC
      LIMIT ?
    `)
    .all(
      tenantId,
      new Date(Date.now() - exchangeRetentionSeconds() * 1000).toISOString(),
      input.status ?? "approved",
      input.status ?? "approved",
      limit,
    ) as Array<Record<string, unknown>>;
  return rows.map(mapBan);
}

export function listConnectedMeshFeedForTenant(
  tenantId: string,
  input: { limit?: number; trustThreshold?: number; status?: CommunityBan["status"] | "any" },
) {
  maybePruneExchangeState();
  const limit = Math.max(1, Math.min(input.limit ?? 100, 250));
  const rows = getDB()
    .prepare(`
      SELECT * FROM bans
      WHERE tenant_id = ?
        AND source_channel = 'community'
        AND datetime(last_seen, '+' || ttl || ' seconds') >= datetime('now')
        AND datetime(last_seen) >= datetime(?)
        AND trust_score_at_submission >= ?
        AND (? = 'any' OR status = ?)
      ORDER BY datetime(last_seen) DESC
      LIMIT ?
    `)
    .all(
      tenantId,
      new Date(Date.now() - exchangeRetentionSeconds() * 1000).toISOString(),
      input.trustThreshold ?? 0,
      input.status ?? "approved",
      input.status ?? "approved",
      limit,
    ) as Array<Record<string, unknown>>;
  return rows.map(mapBan);
}

export function listAttackExchangeFeedForTenant(
  tenantId: string,
  input: { limit?: number; trustThreshold?: number; minSignalConfidence?: number; includePending?: boolean; after?: string | null; approvedSourceTenants?: string[] },
) {
  maybePruneExchangeState();
  const status = input.includePending ? "any" : "approved";
  const limit = Math.max(1, Math.min(input.limit ?? 100, 250));
  const sourceTenants = (input.approvedSourceTenants ?? []).filter((id) => id !== tenantId).slice(0, 100);
  const externalClause = sourceTenants.length
    ? `OR (b.tenant_id IN (${sourceTenants.map(() => "?").join(",")}) AND b.source_type = 'honeymesh_node' AND n.revoked_at IS NULL)`
    : "";
  const rows = getDB()
    .prepare(`
      SELECT b.*, n.cluster_id AS source_cluster_id FROM bans b
      LEFT JOIN nodes n ON n.id = b.node_id
      WHERE ((b.tenant_id = ? AND b.source_channel IN ('local', 'community')) ${externalClause})
        AND datetime(b.last_seen, '+' || b.ttl || ' seconds') >= datetime('now')
        AND datetime(b.last_seen) >= datetime(?)
        AND (b.tenant_id = ? OR b.status = 'approved')
        AND (? = 'any' OR b.status = ?)
        AND (b.tenant_id = ? OR b.trust_score_at_submission >= ?)
        AND (b.tenant_id = ? OR b.confidence >= ?)
        AND (
          ? IS NULL OR datetime(b.last_seen) > datetime(json_extract(?, '$.lastSeen'))
          OR (
            datetime(b.last_seen) = datetime(json_extract(?, '$.lastSeen'))
            AND b.id > json_extract(?, '$.id')
          )
        )
      ORDER BY datetime(b.last_seen) ASC, b.id ASC
      LIMIT ?
    `)
    .all(
      tenantId,
      ...sourceTenants,
      new Date(Date.now() - exchangeRetentionSeconds() * 1000).toISOString(),
      tenantId,
      status,
      status,
      tenantId,
      input.trustThreshold ?? 0,
      tenantId,
      input.minSignalConfidence ?? 0,
      input.after ?? null,
      input.after ?? null,
      input.after ?? null,
      input.after ?? null,
      limit,
    ) as Array<Record<string, unknown>>;
  const feedAsOf = Date.now();
  const mergedFeed = rows.filter((row) => String(row.tenant_id) === tenantId ||
    (!!row.source_cluster_id && isPublicIndicator(String(row.attacker_ip)))).map((row) => {
    const signal = mapBan(row);
    // Send the remaining lifetime, not the original TTL. A recipient that
    // first sees a near-expired signal must not extend its enforcement.
    const remaining = Math.min(signal.ttl, Math.ceil((Date.parse(signal.lastSeen) + signal.ttl * 1000 - feedAsOf) / 1000));
    if (signal.tenantId === tenantId) return { ...signal, ttl: remaining };
    return {
      id: signal.id,
      clusterId: signal.clusterId,
      attackerIp: signal.attackerIp,
      ja4: signal.ja4,
      ja3Legacy: signal.ja3Legacy,
      attackType: signal.attackType,
      protocol: signal.protocol,
      port: 0,
      service: "shared",
      confidence: signal.confidence,
      reason: "Approved shared defensive signal",
      lastSeen: signal.lastSeen,
      ttl: remaining,
      status: signal.status,
      publisher: signal.clusterId,
      sourceChannel: "community" as const,
    };
  }).filter((record) => record.ttl > 0);
  const localNodeAttacks = mergedFeed.filter((record) => record.sourceChannel === "local");
  const connectedMeshAttacks = mergedFeed.filter((record) => record.sourceChannel === "community");
  const tail = rows.at(-1);
  const cursor = tail
    ? Buffer.from(JSON.stringify({ lastSeen: tail.last_seen, id: tail.id }), "utf8").toString("base64url")
    : input.after ?? null;

  return {
    localNodeAttacks,
    connectedMeshAttacks,
    mergedFeed,
    cursor,
    pageSize: rows.length,
  };
}

export function snapshotAttackExchangeFeedForTenant(
  tenantId: string,
  input: { trustThreshold: number; minSignalConfidence: number; approvedSourceTenants: string[] },
) {
  const db = getDB();
  return db.transaction(() => {
    const asOf = new Date();
    const records: ReturnType<typeof listAttackExchangeFeedForTenant>["mergedFeed"] = [];
    let scanned = 0;
    let cursor: string | null = null;
    for (;;) {
      const page = listAttackExchangeFeedForTenant(tenantId, { ...input, limit: 250, after: parseFeedCursor(cursor) });
      scanned += page.pageSize;
      if (scanned > 2500 || records.length + page.mergedFeed.length > 2500) {
        return { complete: false as const, records: [], cursor: null, retractionCursor: 0, asOf: asOf.toISOString() };
      }
      records.push(...page.mergedFeed);
      recordSignalFeedDeliveries(tenantId, page.mergedFeed.map((record) => record.id));
      if (page.pageSize < 250 || !page.cursor || page.cursor === cursor) {
        cursor = page.cursor;
        break;
      }
      cursor = page.cursor;
    }
    const row = db.prepare("SELECT COALESCE(MAX(seq), 0) AS seq FROM signal_retractions").get() as { seq: number };
    const active = records.flatMap((record) => {
      const remaining = Math.min(record.ttl, Math.ceil((Date.parse(record.lastSeen) + record.ttl * 1000 - asOf.getTime()) / 1000));
      return remaining > 0 ? [{ ...record, ttl: remaining }] : [];
    });
    return { complete: true as const, records: active, cursor, retractionCursor: row.seq, asOf: asOf.toISOString() };
  })();
}

export function recordSignalFeedDeliveries(recipientTenantId: string, signalIds: string[]) {
  const ids = [...new Set(signalIds)].slice(0, 250);
  const insert = getDB().prepare(`
    INSERT OR IGNORE INTO signal_feed_deliveries
      (recipient_tenant_id, signal_id, delivered_at) VALUES (?, ?, ?)
  `);
  const now = new Date().toISOString();
  getDB().transaction(() => {
    for (const id of ids) insert.run(recipientTenantId, id, now);
  })();
}

export function retractPublishedSignal(tenantId: string, signalId: string) {
  const db = getDB();
  return db.transaction(() => {
    const row = db.prepare(`
      SELECT b.*, n.cluster_id AS source_cluster_id FROM bans b
      LEFT JOIN nodes n ON n.id = b.node_id
      WHERE b.id = ? AND b.tenant_id = ? LIMIT 1
    `).get(signalId, tenantId) as Record<string, unknown> | undefined;
    if (!row || row.source_type !== "honeymesh_node" || !row.source_cluster_id ||
        (row.status !== "approved" && row.status !== "rejected")) return null;
    const now = new Date().toISOString();
    if (row.status === "approved") {
      db.prepare("UPDATE bans SET status = 'rejected', last_seen = ? WHERE id = ?").run(now, signalId);
    }
    db.prepare(`
      INSERT OR IGNORE INTO signal_retractions
        (signal_id, source_tenant_id, cluster_id, attacker_ip, retracted_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(signalId, tenantId, row.source_cluster_id, row.attacker_ip, now);
    const updated = db.prepare("SELECT * FROM bans WHERE id = ?").get(signalId) as Record<string, unknown>;
    return mapBan(updated);
  })();
}

export function listSignalRetractionsForTenant(recipientTenantId: string, after: number, limit: number) {
  const rows = getDB().prepare(`
    SELECT r.seq, r.signal_id, r.cluster_id, r.attacker_ip, r.retracted_at
    FROM signal_retractions r
    JOIN signal_feed_deliveries d ON d.signal_id = r.signal_id
    WHERE d.recipient_tenant_id = ? AND r.seq > ?
    ORDER BY r.seq ASC LIMIT ?
  `).all(recipientTenantId, after, Math.max(1, Math.min(limit, 250))) as Array<Record<string, unknown>>;
  return {
    retractions: rows.map((row) => ({
      seq: Number(row.seq), signalId: String(row.signal_id), clusterId: String(row.cluster_id),
      attackerIp: String(row.attacker_ip), retractedAt: String(row.retracted_at),
    })),
    cursor: rows.length ? Number(rows.at(-1)?.seq) : after,
  };
}

export function updateBanStatus(banId: string, status: CommunityBan["status"]) {
  getDB().prepare("UPDATE bans SET status = ?, last_seen = ? WHERE id = ?").run(status, new Date().toISOString(), banId);
  const row = getDB().prepare("SELECT * FROM bans WHERE id = ? LIMIT 1").get(banId) as Record<string, unknown> | undefined;
  return row ? mapBan(row) : null;
}

export function updateBanStatusForTenant(tenantId: string, banId: string, status: CommunityBan["status"]) {
  const ban = findBanByID(banId);
  if (!ban || ban.tenantId !== tenantId) {
    return null;
  }
  return updateBanStatus(banId, status);
}

export function addVote(vote: BanVote) {
  getDB()
    .prepare("INSERT INTO votes (id, ban_id, reviewer_user_id, action, notes, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(vote.id, vote.banId, vote.reviewerUserId, vote.action, vote.notes, vote.createdAt);
}

export function countActiveNodesForTenant(tenantId: string) {
  const row = getDB().prepare("SELECT COUNT(*) AS count FROM nodes WHERE tenant_id = ? AND revoked_at IS NULL").get(tenantId) as { count: number };
  return row.count;
}

export function registerNode(input: Omit<NodeRecord, "lastSeen" | "status" | "apiKeyHash">, secret: string, maxNodes: number) {
  const node: NodeRecord = {
    ...input,
    status: "online",
    lastSeen: new Date().toISOString(),
    apiKeyHash: hashNodeSecretSeed(secret),
  };
  const db = getDB();
  const tx = db.transaction(() => {
    // Keep the license limit and identity check in the same write transaction
    // as registration. Concurrent bootstrap requests cannot consume the same
    // final slot or recover an existing node's secret.
    const active = db.prepare("SELECT COUNT(*) AS count FROM nodes WHERE tenant_id = ? AND revoked_at IS NULL")
      .get(node.tenantId) as { count: number };
    const existing = db.prepare(`SELECT 1 FROM nodes WHERE id = ? OR
      (tenant_id = ? AND cluster_id = ? AND machine_fingerprint IS NOT NULL AND machine_fingerprint = ?) LIMIT 1`)
      .get(node.id, node.tenantId, node.clusterId, node.machineFingerprint);
    if (!Number.isSafeInteger(maxNodes) || maxNodes < 1 || active.count >= maxNodes || existing) {
      throw new Error("node_limit_or_identity_conflict");
    }
    db.prepare(`
      INSERT INTO nodes (id, tenant_id, cluster_id, node_name, api_key_hash, public_key, status, last_seen, trust_level, software_version, machine_fingerprint, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      node.id,
      node.tenantId,
      node.clusterId,
      node.nodeName,
      node.apiKeyHash,
      node.publicKey,
      node.status,
      node.lastSeen,
      node.trustLevel,
      node.softwareVersion,
      node.machineFingerprint,
      node.revokedAt,
    );
    db.prepare("INSERT OR REPLACE INTO node_credentials (node_id, shared_secret) VALUES (?, ?)").run(node.id, secret);
  });
  tx();
  return node;
}

export function revokeNode(nodeId: string) {
  getDB().prepare("UPDATE nodes SET revoked_at = ?, status = 'offline' WHERE id = ?").run(new Date().toISOString(), nodeId);
  return findNodeByID(nodeId);
}

export function revokeNodeForTenant(tenantId: string, nodeId: string) {
  const node = findNodeByID(nodeId);
  if (!node || node.tenantId !== tenantId) {
    return null;
  }
  return revokeNode(nodeId);
}

export function createEnrollmentToken(input: Omit<EnrollmentToken, "id" | "tokenHash" | "usedAt"> & { rawToken: string }) {
  const record: EnrollmentToken = {
    id: randomUUID(),
    tenantId: input.tenantId,
    tokenHash: hashNodeSecretSeed(input.rawToken),
    expiresAt: input.expiresAt,
    usedAt: null,
    createdByUserId: input.createdByUserId,
    allowedIp: input.allowedIp,
    nodeNameHint: input.nodeNameHint,
  };
  getDB()
    .prepare(`
      INSERT INTO enrollment_tokens (id, tenant_id, token_hash, expires_at, used_at, created_by_user_id, allowed_ip, node_name_hint)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(record.id, record.tenantId, record.tokenHash, record.expiresAt, record.usedAt, record.createdByUserId, record.allowedIp, record.nodeNameHint);
  return record;
}

export function findEnrollmentToken(rawToken: string) {
  const row = getDB().prepare("SELECT * FROM enrollment_tokens WHERE token_hash = ? LIMIT 1").get(hashNodeSecretSeed(rawToken)) as Record<string, unknown> | undefined;
  return row ? mapEnrollmentToken(row) : null;
}

export function markEnrollmentTokenUsed(id: string) {
  getDB().prepare("UPDATE enrollment_tokens SET used_at = ? WHERE id = ?").run(new Date().toISOString(), id);
  const row = getDB().prepare("SELECT * FROM enrollment_tokens WHERE id = ? LIMIT 1").get(id) as Record<string, unknown> | undefined;
  return row ? mapEnrollmentToken(row) : null;
}

export function registerNodeWithEnrollmentToken(rawToken: string, clusterId: string, input: Omit<NodeRecord, "lastSeen" | "status" | "apiKeyHash" | "tenantId" | "clusterId">, secret: string) {
  const db = getDB();
  const now = new Date().toISOString();
  return db.transaction(() => {
    const row = db.prepare(`SELECT e.id, e.tenant_id AS tenantId, e.node_name_hint AS nodeNameHint
      FROM enrollment_tokens e JOIN network_admins a ON a.id = e.created_by_user_id
      WHERE e.token_hash = ? AND e.used_at IS NULL AND e.expires_at > ?
        AND a.tenant_id = e.tenant_id AND a.cluster_id = ? AND a.disabled_at IS NULL
      LIMIT 1`).get(hashNodeSecretSeed(rawToken), now, clusterId) as { id: string; tenantId: string; nodeNameHint: string | null } | undefined;
    if (!row || (row.nodeNameHint && row.nodeNameHint !== input.nodeName)) throw new Error("invalid_enrollment_token");
    const tenant = findTenantByID(row.tenantId);
    if (!tenant || tenant.exchangeKillSwitch) throw new Error("enrollment_disabled");
    const node = registerNode({ ...input, tenantId: row.tenantId, clusterId }, secret, 1000);
    const consumed = db.prepare("UPDATE enrollment_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL").run(now, row.id);
    if (consumed.changes !== 1) throw new Error("invalid_enrollment_token");
    return node;
  })();
}

export function saveNodeNonce(nodeId: string, nonce: string) {
  maybePruneExchangeState();
  const record: NodeNonce = {
    id: randomUUID(),
    nodeId,
    nonce,
    createdAt: new Date().toISOString(),
  };
  const db = getDB();
  const cutoff = new Date(Date.now() - 10 * 60_000).toISOString();
  const tx = db.transaction(() => {
    db.prepare("INSERT INTO node_nonces (id, node_id, nonce, created_at) VALUES (?, ?, ?, ?)").run(record.id, record.nodeId, record.nonce, record.createdAt);
    db.prepare("DELETE FROM node_nonces WHERE datetime(created_at) < datetime(?)").run(cutoff);
  });
  tx();
  return record;
}

export function hasNodeNonce(nodeId: string, nonce: string) {
  const row = getDB().prepare("SELECT 1 as found FROM node_nonces WHERE node_id = ? AND nonce = ? LIMIT 1").get(nodeId, nonce) as { found?: number } | undefined;
  return Boolean(row?.found);
}

export function createMfaChallenge(userId: string) {
  const record: MfaChallenge = {
    id: randomUUID(),
    userId,
    code: String(randomInt(100000, 999999)),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
  };
  getDB()
    .prepare("INSERT INTO mfa_challenges (id, user_id, code, created_at, expires_at) VALUES (?, ?, ?, ?, ?)")
    .run(record.id, record.userId, record.code, record.createdAt, record.expiresAt);
  return record;
}

export function findMfaChallenge(id: string) {
  const row = getDB().prepare("SELECT * FROM mfa_challenges WHERE id = ? LIMIT 1").get(id) as Record<string, unknown> | undefined;
  return row ? mapMfaChallenge(row) : null;
}

export function clearMfaChallenge(id: string) {
  getDB().prepare("DELETE FROM mfa_challenges WHERE id = ?").run(id);
}

export function upsertLicense(record: LicenseRecord) {
  const db = getDB();
  const tx = db.transaction(() => {
    db.prepare(`
      INSERT INTO licenses (id, tenant_id, tier, status, issued_at, expires_at, license_fingerprint, raw_metadata_json, mesh_scope_expires_at, last_validated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(tenant_id) DO UPDATE SET
        id = excluded.id,
        tier = excluded.tier,
        status = excluded.status,
        issued_at = excluded.issued_at,
        expires_at = excluded.expires_at,
        license_fingerprint = excluded.license_fingerprint,
        raw_metadata_json = excluded.raw_metadata_json,
        mesh_scope_expires_at = excluded.mesh_scope_expires_at,
        last_validated_at = excluded.last_validated_at
    `).run(
      record.id,
      record.tenantId,
      record.tier,
      record.status,
      record.issuedAt,
      record.expiresAt,
      record.licenseFingerprint,
      record.rawMetadataJson,
      record.meshScopeExpiresAt ?? null,
      record.lastValidatedAt,
    );
    db.prepare(`
      UPDATE tenants
      SET license_id = ?,
          license_status = ?,
          plan = ?,
          sharing_enabled = CASE WHEN ? = 'pro' THEN sharing_enabled ELSE 0 END
      WHERE id = ?
    `).run(record.id, record.status, record.tier === "pro" ? "pro" : "community", record.tier, record.tenantId);
  });
  tx();
  return record;
}

export function logSync(entry: Omit<SyncLog, "id" | "createdAt"> & Partial<Pick<SyncLog, "id" | "createdAt">>) {
  maybePruneExchangeState();
  const record: SyncLog = {
    id: entry.id ?? randomUUID(),
    createdAt: entry.createdAt ?? new Date().toISOString(),
    nodeId: entry.nodeId,
    syncType: entry.syncType,
    success: entry.success,
    recordsCount: entry.recordsCount,
  };
  getDB()
    .prepare("INSERT INTO sync_logs (id, node_id, sync_type, success, records_count, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(record.id, record.nodeId, record.syncType, record.success ? 1 : 0, record.recordsCount, record.createdAt);
  return record;
}

export function logFeedback(entry: Omit<BanFeedback, "id" | "createdAt"> & Partial<Pick<BanFeedback, "id" | "createdAt">>) {
  const record: BanFeedback = {
    id: entry.id ?? randomUUID(),
    createdAt: entry.createdAt ?? new Date().toISOString(),
    nodeId: entry.nodeId,
    banId: entry.banId,
    useful: entry.useful,
    notes: entry.notes,
  };
  getDB()
    .prepare("INSERT INTO feedback (id, node_id, ban_id, useful, notes, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(record.id, record.nodeId, record.banId, record.useful ? 1 : 0, record.notes, record.createdAt);
  return record;
}

export function heartbeatNode(nodeId: string, status: NodeRecord["status"]) {
  getDB().prepare("UPDATE nodes SET status = ?, last_seen = ? WHERE id = ?").run(status, new Date().toISOString(), nodeId);
  return findNodeByID(nodeId);
}

export function dashboardSummaryForTenant(tenantId: string): DashboardSummary {
  const state = getPortalState();
  const tenantBans = state.bans.filter((ban) => ban.tenantId === tenantId);
  const approved = tenantBans.filter((ban) => ban.status === "approved");
  const pending = tenantBans.filter((ban) => ban.status === "pending");
  const quarantined = tenantBans.filter((ban) => ban.status === "quarantined");
  const activeWindowCutoff = Date.now() - 24 * 60 * 60_000;
  const activeRecent = tenantBans.filter(
    (ban) => ban.status !== "rejected" && ban.status !== "expired" && Date.parse(ban.lastSeen) >= activeWindowCutoff,
  );
  const nodes = state.nodes.filter((node) => node.tenantId === tenantId);
  const pushes = state.syncLogs.filter((log) => nodes.some((node) => node.id === log.nodeId));

  const topJA4s = [...approved]
    .reduce<Map<string, number>>((acc, ban) => {
      if (ban.ja4) {
        acc.set(ban.ja4, (acc.get(ban.ja4) ?? 0) + 1);
      }
      return acc;
    }, new Map())
    .entries();

  const topAttackerIps = [...approved]
    .reduce<Map<string, number>>((acc, ban) => {
      acc.set(ban.attackerIp, (acc.get(ban.attackerIp) ?? 0) + 1);
      return acc;
    }, new Map())
    .entries();

  const topAttackType = Array.from(
    activeRecent.reduce<Map<string, number>>((acc, ban) => {
      acc.set(ban.attackType, (acc.get(ban.attackType) ?? 0) + 1);
      return acc;
    }, new Map()),
  ).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "n/a";

  const topRecentJA4 = Array.from(
    activeRecent.reduce<Map<string, number>>((acc, ban) => {
      if (ban.ja4) {
        acc.set(ban.ja4, (acc.get(ban.ja4) ?? 0) + 1);
      }
      return acc;
    }, new Map()),
  ).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "n/a";

  return {
    communityBansReceived: approved.length,
    bansPublishedByOrg: tenantBans.length,
    localNodeSignals24h: activeRecent.filter((ban) => ban.sourceChannel === "local").length,
    connectedMeshSignals24h: activeRecent.filter((ban) => ban.sourceChannel === "community").length,
    topJA4s: Array.from(topJA4s).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([value, count]) => ({ value, count })),
    topAttackerIps: Array.from(topAttackerIps).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([value, count]) => ({ value, count })),
    trustHealth: Math.round(nodes.reduce((acc, node) => acc + node.trustLevel, 0) / Math.max(nodes.length, 1)),
    syncHealth: Math.round((pushes.filter((log) => log.success).length / Math.max(pushes.length, 1)) * 100),
    pendingReviews: pending.length,
    totalBlocks24h: activeRecent.length,
    uniqueAttackers24h: new Set(activeRecent.map((ban) => ban.attackerIp)).size,
    topAttackType,
    topJA4: topRecentJA4,
    localBlocks24h: activeRecent.filter((ban) => ban.sourceChannel === "local").length,
    networkBlocks24h: activeRecent.filter((ban) => ban.sourceChannel === "community").length,
    quarantinedSignals: quarantined.length,
    rejectedSignals24h: tenantBans.filter((ban) => ban.status === "rejected" && Date.parse(ban.lastSeen) >= activeWindowCutoff).length,
  };
}
