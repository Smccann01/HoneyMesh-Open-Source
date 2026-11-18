import { createHmac, randomBytes, randomUUID, scryptSync, timingSafeEqual, createHash } from "node:crypto";

import { getDB } from "@/lib/portal-store";

const SESSION_SECONDS = 8 * 60 * 60;
const COOKIE_NAME = "__Host-hm_admin";
const CLUSTER_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{1,127}$/;

type AccountRow = { id: string; email: string; tenant_id: string; cluster_id: string; password_salt: string; password_hash: string; totp_secret: string; disabled_at: string | null };
export type Admin = { id: string; email: string; tenantId: string; clusterId: string };
export type ReceivePolicy = { receiveEnabled: boolean; exchangeOriginEnabled: boolean; mode: "observe" | "review" | "temporary"; minConfidence: number; maxTTL: number; updatedAt: string | null };

let initialized = false;
function db() {
  const handle = getDB();
  if (!initialized) {
    handle.exec(`
      CREATE TABLE IF NOT EXISTS network_admins (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL, cluster_id TEXT NOT NULL, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL, disabled_at TEXT);
      CREATE TABLE IF NOT EXISTS network_admin_sessions (token_hash TEXT PRIMARY KEY, admin_id TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS network_admin_sessions_expiry ON network_admin_sessions(expires_at);
      CREATE TABLE IF NOT EXISTS network_receive_policy (tenant_id TEXT PRIMARY KEY, receive_enabled INTEGER NOT NULL DEFAULT 0, exchange_origin_enabled INTEGER NOT NULL DEFAULT 0, mode TEXT NOT NULL DEFAULT 'observe', min_confidence INTEGER NOT NULL DEFAULT 90, max_ttl INTEGER NOT NULL DEFAULT 120, updated_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS network_source_trust (tenant_id TEXT NOT NULL, source_cluster_id TEXT NOT NULL, trusted INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL, PRIMARY KEY (tenant_id, source_cluster_id));
      CREATE TABLE IF NOT EXISTS network_policy_audit (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL, details_json TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS network_policy_audit_tenant_time ON network_policy_audit(tenant_id, created_at DESC);
      CREATE TABLE IF NOT EXISTS network_login_limits (email TEXT PRIMARY KEY, failures INTEGER NOT NULL, locked_until TEXT NOT NULL);
    `);
    initialized = true;
  }
  return handle;
}

function base32Bytes(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, current = 0;
  const bytes: number[] = [];
  for (const char of value.toUpperCase().replace(/\s|=/g, "")) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) return null;
    current = (current << 5) | digit;
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((current >> bits) & 255); }
  }
  return Buffer.from(bytes);
}

function validTotp(secret: string, submitted: string) {
  if (!/^\d{6}$/.test(submitted)) return false;
  const key = base32Bytes(secret);
  if (!key || key.length < 16) return false;
  const step = Math.floor(Date.now() / 30_000);
  for (let offset = -1; offset <= 1; offset++) {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(step + offset));
    const digest = createHmac("sha1", key).update(counter).digest();
    const index = digest[digest.length - 1] & 15;
    const number = (digest.readUInt32BE(index) & 0x7fffffff) % 1_000_000;
    const expected = Buffer.from(String(number).padStart(6, "0"));
    if (timingSafeEqual(expected, Buffer.from(submitted))) return true;
  }
  return false;
}

function tokenHash(token: string) { return createHash("sha256").update(token).digest("hex"); }
function passwordHash(password: string, salt: string) { return scryptSync(password, Buffer.from(salt, "hex"), 64).toString("hex"); }

export function loginAdmin(emailInput: string, password: string, code: string) {
  const email = emailInput.trim().toLowerCase();
  if (email.length > 254 || password.length > 512) return null;
  const handle = db();
  const limit = handle.prepare("SELECT failures, locked_until FROM network_login_limits WHERE email = ?").get(email) as { failures: number; locked_until: string } | undefined;
  if (limit && limit.failures >= 5 && Date.parse(limit.locked_until) > Date.now()) return null;
  const row = handle.prepare("SELECT * FROM network_admins WHERE email = ?").get(email) as AccountRow | undefined;
  const fakeSalt = "916f4d86d4fa77385c9f3c7600a55bf5";
  const candidate = Buffer.from(passwordHash(password, row?.password_salt ?? fakeSalt), "hex");
  const target = Buffer.from(row?.password_hash ?? passwordHash("invalid-password", fakeSalt), "hex");
  const valid = !!row && !row.disabled_at && timingSafeEqual(candidate, target) && validTotp(row.totp_secret, code);
  if (!valid) {
    const failures = (limit && Date.parse(limit.locked_until) > Date.now() ? limit.failures : 0) + 1;
    handle.prepare("INSERT INTO network_login_limits(email, failures, locked_until) VALUES(?, ?, ?) ON CONFLICT(email) DO UPDATE SET failures=excluded.failures, locked_until=excluded.locked_until")
      .run(email, failures, new Date(Date.now() + 15 * 60_000).toISOString());
    return null;
  }
  handle.prepare("DELETE FROM network_login_limits WHERE email = ?").run(email);
  const token = randomBytes(32).toString("base64url");
  handle.prepare("INSERT INTO network_admin_sessions(token_hash, admin_id, created_at, expires_at) VALUES(?, ?, ?, ?)")
    .run(tokenHash(token), row.id, new Date().toISOString(), new Date(Date.now() + SESSION_SECONDS * 1000).toISOString());
  handle.prepare("DELETE FROM network_admin_sessions WHERE expires_at < ?").run(new Date().toISOString());
  return { token, admin: { id: row.id, email: row.email, tenantId: row.tenant_id, clusterId: row.cluster_id } satisfies Admin };
}

function cookieToken(request: Request) {
  const raw = request.headers.get("cookie") ?? "";
  return raw.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${COOKIE_NAME}=`))?.slice(COOKIE_NAME.length + 1) ?? "";
}

export function getAdmin(request: Request): Admin | null {
  const token = cookieToken(request);
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const row = db().prepare(`SELECT a.* FROM network_admin_sessions s JOIN network_admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at > ? AND a.disabled_at IS NULL`)
    .get(tokenHash(token), new Date().toISOString()) as AccountRow | undefined;
  return row ? { id: row.id, email: row.email, tenantId: row.tenant_id, clusterId: row.cluster_id } : null;
}

export function logoutAdmin(request: Request) {
  const token = cookieToken(request);
  if (token) db().prepare("DELETE FROM network_admin_sessions WHERE token_hash=?").run(tokenHash(token));
}

export function sessionCookie(token: string) { return `${COOKIE_NAME}=${token}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Strict`; }
export function clearSessionCookie() { return `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`; }

export function sameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  const expected = process.env.EXCHANGE_PUBLIC_ORIGIN || new URL(request.url).origin;
  return origin === expected && request.headers.get("content-type")?.startsWith("application/json") === true;
}

export function getReceivePolicy(tenantId: string): ReceivePolicy {
  const row = db().prepare("SELECT * FROM network_receive_policy WHERE tenant_id=?").get(tenantId) as Record<string, unknown> | undefined;
  return { receiveEnabled: row?.receive_enabled === 1, exchangeOriginEnabled: row?.exchange_origin_enabled === 1,
    mode: row?.mode === "temporary" ? "temporary" : row?.mode === "review" ? "review" : "observe",
    minConfidence: Number(row?.min_confidence ?? 90), maxTTL: Number(row?.max_ttl ?? 120), updatedAt: row ? String(row.updated_at) : null };
}

function audit(handle: ReturnType<typeof db>, admin: Admin, action: string, details: object) {
  handle.prepare("INSERT INTO network_policy_audit(id, tenant_id, actor_id, action, details_json, created_at) VALUES(?, ?, ?, ?, ?, ?)")
    .run(randomUUID(), admin.tenantId, admin.id, action, JSON.stringify(details), new Date().toISOString());
}

export function updateReceivePolicy(admin: Admin, input: Omit<ReceivePolicy, "updatedAt">) {
  const handle = db();
  const previous = getReceivePolicy(admin.tenantId);
  const now = new Date().toISOString();
  handle.transaction(() => {
    handle.prepare(`INSERT INTO network_receive_policy(tenant_id, receive_enabled, exchange_origin_enabled, mode, min_confidence, max_ttl, updated_at)
      VALUES(?, ?, ?, ?, ?, ?, ?) ON CONFLICT(tenant_id) DO UPDATE SET receive_enabled=excluded.receive_enabled, exchange_origin_enabled=excluded.exchange_origin_enabled, mode=excluded.mode, min_confidence=excluded.min_confidence, max_ttl=excluded.max_ttl, updated_at=excluded.updated_at`)
      .run(admin.tenantId, Number(input.receiveEnabled), Number(input.exchangeOriginEnabled), input.mode, input.minConfidence, input.maxTTL, now);
    audit(handle, admin, "receive_policy.update", { previous, next: input });
  })();
  return getReceivePolicy(admin.tenantId);
}

export function listTrustedSources(tenantId: string) {
  return db().prepare("SELECT source_cluster_id AS clusterId, trusted, updated_at AS updatedAt FROM network_source_trust WHERE tenant_id=? ORDER BY source_cluster_id LIMIT 200")
    .all(tenantId).map((row) => ({ ...(row as { clusterId: string; trusted: number; updatedAt: string }), trusted: (row as { trusted: number }).trusted === 1 }));
}

export function setTrustedSource(admin: Admin, clusterId: string, trusted: boolean) {
  if (!CLUSTER_ID.test(clusterId) || clusterId === admin.clusterId || clusterId.toLowerCase() === "honeymesh-exchange") return false;
  const handle = db();
  const previous = handle.prepare("SELECT trusted FROM network_source_trust WHERE tenant_id=? AND source_cluster_id=?").get(admin.tenantId, clusterId) as { trusted: number } | undefined;
  handle.transaction(() => {
    handle.prepare(`INSERT INTO network_source_trust(tenant_id, source_cluster_id, trusted, updated_at) VALUES(?, ?, ?, ?)
      ON CONFLICT(tenant_id, source_cluster_id) DO UPDATE SET trusted=excluded.trusted, updated_at=excluded.updated_at`)
      .run(admin.tenantId, clusterId, Number(trusted), new Date().toISOString());
    audit(handle, admin, "source_trust.update", { clusterId, previous: previous?.trusted === 1, trusted });
  })();
  return true;
}

export function trustedSourceTenantIds(tenantId: string, approvedSourceTenants: string[]) {
  if (!getReceivePolicy(tenantId).receiveEnabled || !approvedSourceTenants.length) return [];
  const handle = db();
  return approvedSourceTenants.filter((sourceTenant) => {
    const row = handle.prepare(`SELECT 1 FROM cluster_directory d JOIN network_source_trust t
      ON t.tenant_id=? AND t.source_cluster_id=d.cluster_id AND t.trusted=1 WHERE d.tenant_id=? LIMIT 1`)
      .get(tenantId, sourceTenant);
    return !!row;
  });
}

export function listNetworkPolicyAudit(tenantId: string) {
  return db().prepare("SELECT id, actor_id AS actorId, action, details_json AS details, created_at AS createdAt FROM network_policy_audit WHERE tenant_id=? ORDER BY created_at DESC, id DESC LIMIT 100")
    .all(tenantId) as Array<{ id: string; actorId: string; action: string; details: string; createdAt: string }>;
}
