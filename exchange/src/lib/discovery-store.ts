import { randomUUID } from "node:crypto";

import { getDB } from "@/lib/portal-store";
import type { NodeRecord } from "@/lib/portal-types";

export type DirectoryProfile = {
  clusterId: string;
  displayName: string;
  discoverable: boolean;
  allowInvites: boolean;
  allowSignals: boolean;
  capabilities: string[];
  lastSeen: string;
  updatedAt: string;
};

export type DirectoryRequest = {
  id: string;
  fromClusterId: string;
  toClusterId: string;
  scope: "signals" | "mesh";
  status: "pending" | "approved" | "rejected" | "revoked";
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
};

const DIRECTORY_TTL_MS = 24 * 60 * 60 * 1000;
let schemaReady = false;

function db() {
  const handle = getDB();
  if (!schemaReady) {
    handle.exec(`
      CREATE TABLE IF NOT EXISTS cluster_directory (
        tenant_id TEXT PRIMARY KEY,
        cluster_id TEXT NOT NULL UNIQUE,
        admin_node_id TEXT NOT NULL,
        display_name TEXT NOT NULL,
        discoverable INTEGER NOT NULL DEFAULT 0,
        allow_invites INTEGER NOT NULL DEFAULT 0,
        allow_signals INTEGER NOT NULL DEFAULT 0,
        capabilities_json TEXT NOT NULL DEFAULT '[]',
        last_seen TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS cluster_directory_visible
        ON cluster_directory(discoverable, cluster_id);
      CREATE TABLE IF NOT EXISTS directory_requests (
        id TEXT PRIMARY KEY,
        from_tenant_id TEXT NOT NULL,
        to_tenant_id TEXT NOT NULL,
        from_cluster_id TEXT NOT NULL,
        to_cluster_id TEXT NOT NULL,
        scope TEXT NOT NULL CHECK(scope IN ('signals', 'mesh')),
        status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected', 'revoked')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS directory_requests_to_status
        ON directory_requests(to_tenant_id, status, created_at);
      CREATE INDEX IF NOT EXISTS directory_requests_from_status
        ON directory_requests(from_tenant_id, status, created_at);
      CREATE UNIQUE INDEX IF NOT EXISTS directory_requests_active_pair
        ON directory_requests(from_tenant_id, to_tenant_id, scope)
        WHERE status IN ('pending', 'approved');
      CREATE TABLE IF NOT EXISTS directory_audit (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        actor_node_id TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS directory_audit_tenant_time
        ON directory_audit(tenant_id, created_at);
    `);
    schemaReady = true;
  }
  return handle;
}

export function logDirectoryEvent(node: NodeRecord, action: string, details: string) {
  const handle = db();
  handle.prepare("INSERT INTO directory_audit (id, tenant_id, actor_node_id, action, details, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(randomUUID(), node.tenantId, node.id, action, details, new Date().toISOString());
  handle.prepare("DELETE FROM directory_audit WHERE created_at < ?")
    .run(new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString());
}

export function listDirectoryAudit(node: NodeRecord, action: string, before: string, limit: number) {
  return db().prepare(`
    SELECT id, action, details, created_at AS createdAt FROM directory_audit
    WHERE tenant_id = ? AND (? = '' OR action = ?) AND created_at < ?
    ORDER BY created_at DESC, id DESC LIMIT ?
  `).all(node.tenantId, action, action, before || "9999-12-31T23:59:59.000Z", Math.min(Math.max(limit, 1), 100));
}

export function rotateDirectoryAdmin(node: NodeRecord, newAdminNodeId: string) {
  if (!isDirectoryAdmin(node)) return false;
  const target = db().prepare("SELECT id, tenant_id, cluster_id, revoked_at, status FROM nodes WHERE id = ?")
    .get(newAdminNodeId) as { id: string; tenant_id: string; cluster_id: string; revoked_at: string | null; status: string } | undefined;
  if (!target || target.tenant_id !== node.tenantId || target.cluster_id !== node.clusterId || target.revoked_at || target.status === "offline") return false;
  db().prepare("UPDATE cluster_directory SET admin_node_id = ?, updated_at = ? WHERE tenant_id = ? AND admin_node_id = ?")
    .run(newAdminNodeId, new Date().toISOString(), node.tenantId, node.id);
  return true;
}

type ProfileRow = {
  tenant_id: string;
  cluster_id: string;
  admin_node_id: string;
  display_name: string;
  discoverable: number;
  allow_invites: number;
  allow_signals: number;
  capabilities_json: string;
  last_seen: string;
  updated_at: string;
};

function profileFromRow(row: ProfileRow): DirectoryProfile {
  return {
    clusterId: row.cluster_id,
    displayName: row.display_name,
    discoverable: row.discoverable === 1,
    allowInvites: row.allow_invites === 1,
    allowSignals: row.allow_signals === 1,
    capabilities: JSON.parse(row.capabilities_json) as string[],
    lastSeen: row.last_seen,
    updatedAt: row.updated_at,
  };
}

export function getOwnProfile(tenantId: string) {
  const row = db().prepare("SELECT * FROM cluster_directory WHERE tenant_id = ?").get(tenantId) as ProfileRow | undefined;
  return row ? { ...profileFromRow(row), adminNodeId: row.admin_node_id } : null;
}

export function claimDirectoryAdmin(node: NodeRecord) {
  const existing = getOwnProfile(node.tenantId);
  if (existing) {
    return existing.adminNodeId === node.id ? existing : null;
  }
  const now = new Date().toISOString();
  db().prepare(`
    INSERT OR IGNORE INTO cluster_directory
      (tenant_id, cluster_id, admin_node_id, display_name, last_seen, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(node.tenantId, node.clusterId, node.id, `HoneyMesh ${node.clusterId}`, now, now);
  const claimed = getOwnProfile(node.tenantId);
  return claimed?.adminNodeId === node.id ? claimed : null;
}

export function isDirectoryAdmin(node: NodeRecord) {
  const row = db().prepare("SELECT admin_node_id, cluster_id FROM cluster_directory WHERE tenant_id = ?")
    .get(node.tenantId) as { admin_node_id: string; cluster_id: string } | undefined;
  return !!row && row.admin_node_id === node.id && row.cluster_id === node.clusterId;
}

export function updateOwnProfile(node: NodeRecord, input: {
  displayName: string;
  discoverable: boolean;
  allowInvites: boolean;
  allowSignals: boolean;
  capabilities: string[];
}) {
  if (!isDirectoryAdmin(node)) return null;
  const now = new Date().toISOString();
  db().prepare(`
    UPDATE cluster_directory SET display_name = ?, discoverable = ?, allow_invites = ?,
      allow_signals = ?, capabilities_json = ?, last_seen = ?, updated_at = ?
    WHERE tenant_id = ? AND admin_node_id = ?
  `).run(input.displayName, Number(input.discoverable), Number(input.allowInvites), Number(input.allowSignals),
    JSON.stringify(input.capabilities), now, now, node.tenantId, node.id);
  return getOwnProfile(node.tenantId);
}

export function touchDirectoryCluster(node: NodeRecord) {
  db().prepare("UPDATE cluster_directory SET last_seen = ? WHERE tenant_id = ? AND cluster_id = ?")
    .run(new Date().toISOString(), node.tenantId, node.clusterId);
}

export function listDirectoryClusters(ownTenantId: string, after: string, limit: number) {
  const cutoff = new Date(Date.now() - DIRECTORY_TTL_MS).toISOString();
  const rows = db().prepare(`
    SELECT d.* FROM cluster_directory d
    JOIN tenants t ON t.id = d.tenant_id
    LEFT JOIN licenses l ON l.tenant_id = d.tenant_id
    WHERE d.tenant_id != ? AND d.cluster_id > ? AND d.discoverable = 1
      AND d.last_seen >= ? AND t.license_status = 'active' AND t.exchange_kill_switch = 0
      AND ((t.plan = 'community' AND t.sharing_enabled = 1 AND t.review_only_mode = 1
        AND t.auto_approve_enabled = 0)
        OR (t.plan = 'pro' AND l.tier = 'pro' AND l.status = 'active'
          AND datetime(l.expires_at) > datetime('now')))
    ORDER BY d.cluster_id ASC LIMIT ?
  `).all(ownTenantId, after, cutoff, Math.min(Math.max(limit, 1), 100) + 1) as ProfileRow[];
  const page = rows.slice(0, limit);
  return { clusters: page.map(profileFromRow), cursor: rows.length > limit ? page.at(-1)?.cluster_id ?? null : null };
}

export function getVisibleCluster(ownTenantId: string, clusterId: string) {
  const row = db().prepare(`
    SELECT d.* FROM cluster_directory d
    JOIN tenants t ON t.id = d.tenant_id
    LEFT JOIN licenses l ON l.tenant_id = d.tenant_id
    WHERE d.tenant_id != ? AND d.cluster_id = ? AND d.discoverable = 1
      AND d.last_seen >= ? AND t.license_status = 'active' AND t.exchange_kill_switch = 0
      AND ((t.plan = 'community' AND t.sharing_enabled = 1 AND t.review_only_mode = 1
        AND t.auto_approve_enabled = 0)
        OR (t.plan = 'pro' AND l.tier = 'pro' AND l.status = 'active'
          AND datetime(l.expires_at) > datetime('now')))
  `).get(ownTenantId, clusterId, new Date(Date.now() - DIRECTORY_TTL_MS).toISOString()) as ProfileRow | undefined;
  return row ? profileFromRow(row) : null;
}

type RequestRow = {
  id: string; from_tenant_id: string; to_tenant_id: string; from_cluster_id: string;
  to_cluster_id: string; scope: "signals" | "mesh";
  status: DirectoryRequest["status"]; created_at: string; updated_at: string; expires_at: string;
};

function requestFromRow(row: RequestRow): DirectoryRequest {
  return { id: row.id, fromClusterId: row.from_cluster_id, toClusterId: row.to_cluster_id,
    scope: row.scope, status: row.status, createdAt: row.created_at,
    updatedAt: row.updated_at, expiresAt: row.expires_at };
}

export function createDirectoryRequest(from: NodeRecord, toClusterId: string, scope: "signals" | "mesh") {
  if (!isDirectoryAdmin(from)) return { error: "admin_required" as const };
  db().prepare("UPDATE directory_requests SET status = 'rejected', updated_at = ? WHERE status = 'pending' AND expires_at <= ?")
    .run(new Date().toISOString(), new Date().toISOString());
  const target = db().prepare("SELECT tenant_id, allow_invites, allow_signals FROM cluster_directory WHERE cluster_id = ?")
    .get(toClusterId) as { tenant_id: string; allow_invites: number; allow_signals: number } | undefined;
  if (!target || !getVisibleCluster(from.tenantId, toClusterId) ||
    (scope === "mesh" ? target.allow_invites !== 1 : target.allow_signals !== 1)) {
    return { error: "target_unavailable" as const };
  }
  const existing = db().prepare(`
    SELECT * FROM directory_requests WHERE from_tenant_id = ? AND to_tenant_id = ?
      AND scope = ? AND status IN ('pending', 'approved') AND expires_at > ?
    ORDER BY created_at DESC LIMIT 1
  `).get(from.tenantId, target.tenant_id, scope, new Date().toISOString()) as RequestRow | undefined;
  if (existing) return { request: requestFromRow(existing) };
  const now = new Date().toISOString();
  const record: RequestRow = { id: randomUUID(), from_tenant_id: from.tenantId,
    to_tenant_id: target.tenant_id, from_cluster_id: from.clusterId, to_cluster_id: toClusterId,
    scope, status: "pending", created_at: now, updated_at: now,
    expires_at: new Date(Date.now() + DIRECTORY_TTL_MS).toISOString() };
  db().prepare(`INSERT INTO directory_requests
    (id, from_tenant_id, to_tenant_id, from_cluster_id, to_cluster_id, scope, status, created_at, updated_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(record.id, record.from_tenant_id, record.to_tenant_id, record.from_cluster_id,
      record.to_cluster_id, record.scope, record.status, record.created_at, record.updated_at, record.expires_at);
  return { request: requestFromRow(record) };
}

export function listDirectoryRequests(node: NodeRecord) {
  const rows = db().prepare(`
    SELECT * FROM directory_requests WHERE from_tenant_id = ? OR to_tenant_id = ?
    ORDER BY created_at DESC LIMIT 100
  `).all(node.tenantId, node.tenantId) as RequestRow[];
  return rows.map((row) => ({ ...requestFromRow(row), direction: row.to_tenant_id === node.tenantId ? "incoming" : "outgoing" }));
}

export function approvedSignalSourceTenants(consumerTenantId: string) {
  const rows = db().prepare(`
    SELECT DISTINCT r.from_tenant_id AS tenant_id FROM directory_requests r
    JOIN tenants t ON t.id = r.from_tenant_id
    LEFT JOIN licenses l ON l.tenant_id = r.from_tenant_id
    WHERE r.to_tenant_id = ? AND r.scope = 'signals' AND r.status = 'approved'
      AND t.sharing_enabled = 1 AND t.exchange_kill_switch = 0 AND t.license_status = 'active'
      AND ((t.plan = 'community' AND t.review_only_mode = 1 AND t.auto_approve_enabled = 0)
        OR (t.plan = 'pro' AND l.tier = 'pro' AND l.status = 'active'
          AND datetime(l.expires_at) > datetime('now')))
  `).all(consumerTenantId) as Array<{ tenant_id: string }>;
  return rows.map((row) => row.tenant_id);
}

export function decideDirectoryRequest(node: NodeRecord, id: string, decision: "approved" | "rejected" | "revoked") {
  if (!isDirectoryAdmin(node)) return null;
  const row = db().prepare("SELECT * FROM directory_requests WHERE id = ?").get(id) as RequestRow | undefined;
  if (!row || (row.to_tenant_id !== node.tenantId && !(decision === "revoked" && row.from_tenant_id === node.tenantId))) return null;
  if (decision === "revoked" ? row.status !== "approved" : row.status !== "pending") return null;
  if (row.expires_at <= new Date().toISOString() && row.status === "pending") return null;
  const now = new Date().toISOString();
  const expiresAt = decision === "approved" ? "9999-12-31T23:59:59.000Z" : row.expires_at;
  db().prepare("UPDATE directory_requests SET status = ?, updated_at = ?, expires_at = ? WHERE id = ?")
    .run(decision, now, expiresAt, id);
  return requestFromRow({ ...row, status: decision, updated_at: now, expires_at: expiresAt });
}
