import { randomBytes, randomUUID, scryptSync } from "node:crypto";
import { openSync, writeFileSync, closeSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Database from "better-sqlite3";

const args = Object.fromEntries(process.argv.slice(2).map((arg) => {
  const at = arg.indexOf("=");
  if (!arg.startsWith("--") || at < 0) throw new Error("Use --name=value arguments");
  return [arg.slice(2, at), arg.slice(at + 1)];
}));
const dbPath = args.db;
const out = args["credentials-out"];
const email = args.email?.trim().toLowerCase();
const tenantId = args.tenant?.trim();
const clusterId = args.cluster?.trim();
const origin = args.origin;
if (!origin) throw new Error("Required: --origin=https://your-exchange.example");
const parsedOrigin = new URL(origin);
if (parsedOrigin.protocol !== "https:" || parsedOrigin.username || parsedOrigin.password || parsedOrigin.pathname !== "/" || parsedOrigin.search || parsedOrigin.hash) {
  throw new Error("--origin must be an HTTPS origin without path or credentials");
}
if (!dbPath || !out || !path.isAbsolute(dbPath) || !path.isAbsolute(out) || !email || !tenantId || !clusterId || !/^\S+@\S+\.\S+$/.test(email) || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{1,127}$/.test(clusterId)) {
  throw new Error("Required: --db=/absolute/path --credentials-out=/absolute/path --email=admin@example.com --tenant=tenant-id --cluster=cluster-id --origin=https://your-exchange.example");
}
const sourceRoot = fileURLToPath(new URL("../", import.meta.url));
const relativeOut = path.relative(sourceRoot, out);
if (relativeOut === "" || (relativeOut !== ".." && !relativeOut.startsWith(`..${path.sep}`) && !path.isAbsolute(relativeOut))) {
  throw new Error("--credentials-out must be outside the source repository");
}
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32(bytes) {
  let value = 0, bits = 0, result = "";
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { result += alphabet[(value >>> (bits -= 5)) & 31]; }
  }
  if (bits) result += alphabet[(value << (5 - bits)) & 31];
  return result;
}
const password = randomBytes(32).toString("base64url");
const totp = base32(randomBytes(20));
const salt = randomBytes(16).toString("hex");
const hash = scryptSync(password, Buffer.from(salt, "hex"), 64).toString("hex");
const handle = new Database(path.resolve(dbPath));
handle.pragma("journal_mode = WAL");
handle.exec(`
  CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL, sharing_enabled INTEGER NOT NULL DEFAULT 0, exchange_kill_switch INTEGER NOT NULL DEFAULT 0, review_only_mode INTEGER NOT NULL DEFAULT 0, auto_approve_enabled INTEGER NOT NULL DEFAULT 1, trust_level INTEGER NOT NULL, license_status TEXT NOT NULL, local_policy_mode TEXT NOT NULL, license_id TEXT);
  CREATE TABLE IF NOT EXISTS network_admins (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL, cluster_id TEXT NOT NULL, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL, disabled_at TEXT);
`);
const existing = handle.prepare("SELECT id FROM network_admins WHERE email=? OR tenant_id=?").get(email, tenantId);
if (existing) throw new Error("Admin already exists for this email or tenant; refusing to rotate credentials silently");
const file = openSync(out, "wx", 0o600);
try {
  const tx = handle.transaction(() => {
    handle.prepare("INSERT OR IGNORE INTO tenants(id, name, plan, sharing_enabled, exchange_kill_switch, review_only_mode, auto_approve_enabled, trust_level, license_status, local_policy_mode, license_id) VALUES(?, ?, 'community', 0, 0, 1, 0, 0, 'active', 'audit_only', NULL)").run(tenantId, `HoneyMesh ${clusterId}`);
    handle.prepare("INSERT INTO network_admins(id, email, tenant_id, cluster_id, password_salt, password_hash, totp_secret, disabled_at) VALUES(?, ?, ?, ?, ?, ?, ?, NULL)").run(randomUUID(), email, tenantId, clusterId, salt, hash, totp);
  });
  tx();
  const issuer = "HoneyMesh Exchange";
  const uri = `otpauth://totp/${encodeURIComponent(`${issuer}:${email}`)}?secret=${totp}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  writeFileSync(file, `HoneyMesh Exchange pilot admin\nURL: ${parsedOrigin.origin}/console\nEmail: ${email}\nPassword: ${password}\nAuthenticator setup key: ${totp}\nAuthenticator URI: ${uri}\n`, { encoding: "utf8" });
} finally { closeSync(file); handle.close(); }
console.log(`Admin provisioned; credentials written to ${out}`);
