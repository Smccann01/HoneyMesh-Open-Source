import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHmac, createHash, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const directory = mkdtempSync(path.join(tmpdir(), "honeymesh-admin-test-"));
const dbPath = path.join(directory, "exchange.db");
const port = 32000 + Math.floor(Math.random() * 20000);
const base = `http://127.0.0.1:${port}`;
let server;

function bytesFromBase32(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let current = 0, bits = 0;
  const bytes = [];
  for (const letter of value) {
    current = (current << 5) | alphabet.indexOf(letter); bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((current >> bits) & 255); }
  }
  return Buffer.from(bytes);
}
function codeFor(secret) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const digest = createHmac("sha1", bytesFromBase32(secret)).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
function provision(email, tenant, cluster, file) {
  const result = spawnSync(process.execPath, ["scripts/provision-network-admin.mjs", `--db=${dbPath}`, `--credentials-out=${file}`, `--email=${email}`, `--tenant=${tenant}`, `--cluster=${cluster}`, "--origin=https://exchange.example.test"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const content = readFileSync(file, "utf8");
  return { email, password: content.match(/^Password: (.+)$/m)?.[1], secret: content.match(/^Authenticator setup key: (.+)$/m)?.[1] };
}
async function login(credentials) {
  const response = await fetch(`${base}/api/admin/session`, { method: "POST", headers: { origin: base, "content-type": "application/json" }, body: JSON.stringify({ email: credentials.email, password: credentials.password, code: codeFor(credentials.secret) }) });
  assert.equal(response.status, 200);
  const cookie = response.headers.get("set-cookie")?.split(";")[0];
  assert.match(cookie ?? "", /^__Host-hm_admin=/);
  return cookie;
}
async function call(route, cookie, method = "GET", payload, origin = base) {
  return fetch(`${base}${route}`, { method, headers: { cookie, origin, "content-type": "application/json" }, body: payload ? JSON.stringify(payload) : undefined });
}

try {
  const unsafeOutput = path.join(process.cwd(), "admin-credentials-test.txt");
  const unsafe = spawnSync(process.execPath, ["scripts/provision-network-admin.mjs", `--db=${dbPath}`, `--credentials-out=${unsafeOutput}`, "--email=unsafe@example.test", "--tenant=unsafe", "--cluster=unsafe", "--origin=https://exchange.example.test"], { encoding: "utf8" });
  assert.notEqual(unsafe.status, 0, "admin credentials must not be written into the source tree");
  const first = provision("admin-a@example.test", "tenant-a", "cluster-a", path.join(directory, "a.txt"));
  const second = provision("admin-b@example.test", "tenant-b", "cluster-b", path.join(directory, "b.txt"));
  server = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "-p", String(port)], {
    cwd: process.cwd(), env: { ...process.env, DATABASE_URL: `file:${dbPath}`, EXCHANGE_PUBLIC_ORIGIN: base, NETWORK_ADMIN_POLICY_ENFORCED: "true", NETTOOLS_TEST_INSECURE_LOOPBACK: "true" }, stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  server.stdout.on("data", (chunk) => { output += chunk.toString(); });
  server.stderr.on("data", (chunk) => { output += chunk.toString(); });
  let ready = false;
  for (let i = 0; i < 80; i++) {
    if (server.exitCode !== null) throw new Error(`server exited: ${output}`);
    try { await fetch(base); ready = true; break; } catch { await new Promise((resolve) => setTimeout(resolve, 100)); }
  }
  assert.ok(ready, output);
  assert.equal((await fetch(`${base}/api/admin/policy`)).status, 401);
  const consoleResponse = await fetch(`${base}/console`);
  assert.equal(consoleResponse.status, 200);
  assert.match(consoleResponse.headers.get("x-robots-tag") ?? "", /noindex/);
  const cookieA = await login(first);
  const status = await (await call("/api/admin/status", cookieA)).json();
  assert.equal(status.enrolledNodes, 0);
  assert.equal(status.accessActive, true);
  assert.equal((await call("/api/admin/policy", cookieA, "PUT", { receiveEnabled: true, exchangeOriginEnabled: false, mode: "observe", minConfidence: 92, maxTTL: 120 }, "https://evil.example")).status, 403);
  const policy = { receiveEnabled: true, exchangeOriginEnabled: false, mode: "observe", minConfidence: 92, maxTTL: 120 };
  assert.equal((await call("/api/admin/policy", cookieA, "PUT", policy)).status, 200);
  assert.equal((await call("/api/admin/sources", cookieA, "PUT", { clusterId: "cluster-b", trusted: true })).status, 200);
  const firstSources = await (await call("/api/admin/sources", cookieA)).json();
  assert.equal(firstSources.sources.length, 1);
  assert.equal(firstSources.sources[0].trusted, true);
  const firstLog = await (await call("/api/admin/audit", cookieA)).json();
  assert.equal(firstLog.events.length, 2);
  const cookieB = await login(second);
  assert.equal((await call("/api/admin/enrollment-token", cookieA, "POST", {}, "https://evil.example")).status, 403);
  const tokenResponse = await call("/api/admin/enrollment-token", cookieA, "POST", { nodeNameHint: "new-node" });
  assert.equal(tokenResponse.status, 201);
  const invitation = await tokenResponse.json();
  assert.match(invitation.token, /^[A-Za-z0-9_-]{43}$/);
  const enrollment = { nodeName: "new-node", clusterId: "cluster-a", enrollToken: invitation.token, publicKey: "test-public-key" };
  const wrongCluster = await fetch(`${base}/api/hm/enroll`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...enrollment, clusterId: "cluster-b" }) });
  assert.equal(wrongCluster.status, 403);
  const joined = await fetch(`${base}/api/hm/enroll`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(enrollment) });
  assert.equal(joined.status, 201);
  const joinedNode = await joined.json();
  assert.equal(joinedNode.tenant_id, "tenant-a");
  assert.match(joinedNode.secret, /^[A-Za-z0-9_-]{43}$/);
  async function nodeFeed() {
    const timestamp = new Date().toISOString(), nonce = randomUUID();
    const signature = createHmac("sha256", joinedNode.secret).update(["GET", "/api/hm/attack-feed", timestamp, nonce, ""].join("\n")).digest("hex");
    return fetch(`${base}/api/hm/attack-feed`, { headers: {
      "x-hm-node-id": joinedNode.node_id, "x-hm-timestamp": timestamp, "x-hm-nonce": nonce,
      "x-hm-body-sha256": createHash("sha256").update("").digest("hex"), "x-hm-signature": signature,
    } });
  }
  assert.equal((await nodeFeed()).status, 403, "new nodes must not receive a feed before admin opt-in");
  assert.equal((await call("/api/admin/sharing", cookieA, "POST", { enabled: true }, "https://evil.example")).status, 403);
  assert.equal((await call("/api/admin/sharing", cookieA, "POST", { enabled: true })).status, 200);
  assert.equal((await nodeFeed()).status, 200, "free admin opt-in should enable observation feed");
  assert.equal((await call("/api/admin/sharing", cookieA, "POST", { enabled: false })).status, 200);
  assert.equal((await nodeFeed()).status, 403, "admin opt-out should immediately disable the feed");
  const replay = await fetch(`${base}/api/hm/enroll`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...enrollment, id: "replay-node" }) });
  assert.equal(replay.status, 403);
  const afterEnroll = await (await call("/api/admin/status", cookieA)).json();
  assert.equal(afterEnroll.enrolledNodes, 1);
  const otherTenant = await (await call("/api/admin/status", cookieB)).json();
  assert.equal(otherTenant.enrolledNodes, 0);
  const secondSources = await (await call("/api/admin/sources", cookieB)).json();
  assert.equal(secondSources.sources.length, 0, "network admins must not see another tenant's trust list");
  const secondPolicy = await (await call("/api/admin/policy", cookieB)).json();
  assert.equal(secondPolicy.policy.receiveEnabled, false);
  assert.equal((await call("/api/admin/session", cookieA, "DELETE")).status, 200);
  assert.equal((await call("/api/admin/policy", cookieA)).status, 401);
  console.log("Network admin integration passed: MFA login, CSRF, tenant isolation, trust controls, audit, and logout.");
} finally {
  server?.kill("SIGTERM");
  rmSync(directory, { recursive: true, force: true });
}
