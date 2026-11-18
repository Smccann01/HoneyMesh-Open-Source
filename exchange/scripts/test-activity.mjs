import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import Database from "better-sqlite3";

const directory = mkdtempSync(path.join(tmpdir(), "exchange-activity-test-"));
const socketPath = path.join(directory, "agent.sock");
const secret = "test-only-edge-secret-with-at-least-32-characters";
const attackerIp = "8.8.8.8";
const port = 32000 + Math.floor(Math.random() * 20000);
const base = `http://127.0.0.1:${port}`;
let snapshotCalls = 0;

const agent = http.createServer((request, response) => {
  const timestamp = request.headers["x-edge-timestamp"];
  const nonce = request.headers["x-edge-nonce"];
  const signature = request.headers["x-edge-signature"];
  const expected = createHmac("sha256", secret).update(`${timestamp}\n${nonce}\n`).digest("hex");
  if (request.url !== "/v1/active-blocks" || request.method !== "GET" || signature !== expected) {
    response.writeHead(403).end();
    return;
  }
  snapshotCalls += 1;
  response.setHeader("content-type", "application/json");
  response.end(JSON.stringify({ total: 1, blocks: [{ ip: attackerIp, reason_code: "invalid_signature_burst", expires_at: new Date(Date.now() + 120_000).toISOString() }] }));
});
await new Promise((resolve) => agent.listen(socketPath, resolve));

const server = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "-p", String(port)], {
  cwd: process.cwd(),
  env: { ...process.env, DATABASE_URL: `file:${path.join(directory, "exchange.db")}`, EXCHANGE_ACTIVITY_ENABLED: "true",
    EXCHANGE_ACTIVITY_SALT: "test-only-public-pseudonym-secret", EXCHANGE_EDGE_SOCKET: socketPath, EXCHANGE_EDGE_SECRET: secret,
    EXCHANGE_GUARD_MODE: "enforce", EXCHANGE_TRUST_PROXY: "true" },
  stdio: ["ignore", "pipe", "pipe"],
});
let output = "";
server.stdout.on("data", (chunk) => { output += chunk.toString(); });
server.stderr.on("data", (chunk) => { output += chunk.toString(); });

try {
  let ready = false;
  for (let i = 0; i < 80; i++) {
    if (server.exitCode !== null) throw new Error(`server exited: ${output}`);
    try { await fetch(base); ready = true; break; } catch { await new Promise((resolve) => setTimeout(resolve, 100)); }
  }
  assert.ok(ready, `server not ready: ${output}`);
  const home = await fetch(base);
  assert.equal(home.status, 200);
  const homeHtml = await home.text();
  assert.match(homeHtml, /Stronger defense/);
  assert.match(homeHtml, /\/activity/);
  assert.match(homeHtml, /\/downloads/);
  assert.equal(home.headers.get("x-robots-tag"), null);
  const page = await fetch(`${base}/activity`);
  assert.equal(page.status, 200);
  assert.match(page.headers.get("x-robots-tag") ?? "", /noindex/);
  const html = await page.text();
  assert.match(html, /The Exchange protects/);
  assert.doesNotMatch(html, /8\.8\.8\.8/);
  const downloads = await fetch(`${base}/downloads`);
  assert.equal(downloads.status, 200);
  assert.equal(downloads.headers.get("x-robots-tag"), null);
  const downloadsHtml = await downloads.text();
  assert.match(downloadsHtml, /2\.3\.6-rc3/);
  assert.match(downloadsHtml, /4d0054126bb5faa394f8baaae6743e5f47a2638b48a48e473bd56e48b0f0702b/);
  const api = await fetch(`${base}/api/public/exchange-activity`);
  assert.equal(api.status, 200);
  assert.match(api.headers.get("x-robots-tag") ?? "", /noindex/);
  assert.match(api.headers.get("cache-control") ?? "", /no-store/);
  const body = await api.text();
  assert.equal(snapshotCalls, 1, "public API must authenticate to local agent socket");
  assert.match(body, /8\.8\.8\.8/, "active agent block should show its source IP");
  const data = JSON.parse(body);
  assert.equal(data.activeSources, 1);
  assert.equal(data.records.length, 1);
  assert.equal(data.records[0].layer, "HoneyMesh agent");
  assert.equal(data.records[0].sourceIp, attackerIp);
  assert.match(data.records[0].sourceId, /^HM-[A-F0-9]{10}$/);
  const second = await fetch(`${base}/api/public/exchange-activity`);
  assert.equal(second.status, 200);
  assert.equal(snapshotCalls, 1, "public refreshes must not flood the local agent socket");
  for (let i = 0; i < 40; i++) {
    const attempt = await fetch(`${base}/api/hm/attack-feed`, { headers: { "x-real-ip": "8.8.4.4", "x-forwarded-proto": "https" } });
    assert.equal(attempt.status, 401);
  }
  const rejected = await fetch(`${base}/api/hm/attack-feed`, { headers: { "x-real-ip": "8.8.4.4", "x-forwarded-proto": "https" } });
  assert.equal(rejected.status, 429, "the armed control must reject a subsequent request");
  await new Promise((resolve) => setTimeout(resolve, 5100));
  const afterControl = await fetch(`${base}/api/public/exchange-activity`);
  const activityText = await afterControl.text();
  assert.match(activityText, /8\.8\.4\.4/, "confirmed live control should show its source IP");
  const activity = JSON.parse(activityText);
  assert.equal(activity.activeControls, 2, "the agent fixture and real temporary control should be live");
  assert.match(activity.records[0].sourceId, /^HM-[A-F0-9]{10}$/);
  const historyResponse = await fetch(`${base}/api/public/exchange-history?days=30&protocol=HTTPS&outcome=controlled`);
  assert.equal(historyResponse.status, 200);
  assert.match(historyResponse.headers.get("cache-control") ?? "", /no-store/);
  const historyText = await historyResponse.text();
  assert.match(historyText, /8\.8\.4\.4/, "confirmed history should show the blocked source IP");
  const history = JSON.parse(historyText);
  assert.equal(history.records.length, 1);
  assert.equal(history.records[0].behavior, "Excessive unauthenticated requests");
  assert.equal(history.records[0].protocol, "HTTPS");
  assert.equal(history.records[0].outcome, "Blocked");
  assert.equal(history.records[0].sourceIp, "8.8.4.4");
  assert.equal(history.records[0].hitCount, 40);
  assert.equal(history.daily.reduce((sum, day) => sum + day.controlled, 0), 1);
  const wrongFilter = await fetch(`${base}/api/public/exchange-history?protocol=TCP`);
  assert.equal(wrongFilter.status, 400);
  const db = new Database(path.join(directory, "exchange.db"));
  try {
    const insert = db.prepare(`INSERT INTO exchange_activity_records
      (external_id, source_id, reason_code, protocol, service_class, detector, action, observed_at, expires_at, enforced_at, hit_count)
      VALUES (?, 'HM-ABCDEF1234', 'replay_burst', 'HTTPS', 'Exchange machine API', 'Exchange Guard', 'observed', ?, NULL, NULL, 12)`);
    const observedAt = new Date().toISOString();
    for (let i = 0; i < 55; i++) insert.run(`test-page-${i}`, observedAt);
    insert.run("test-outside-window", new Date(Date.now() - 31 * 86_400_000).toISOString());
  } finally { db.close(); }
  const pageOne = await (await fetch(`${base}/api/public/exchange-history?days=30`)).json();
  assert.equal(pageOne.records.length, 50);
  assert.equal(pageOne.records[0].sourceIp, null, "observations must not expose source IPs");
  assert.ok(pageOne.nextCursor);
  const pageTwo = await (await fetch(`${base}/api/public/exchange-history?days=30&cursor=${pageOne.nextCursor}`)).json();
  assert.equal(pageTwo.records.length, 6);
  assert.equal(pageTwo.nextCursor, null);
  assert.ok(!pageTwo.records.some((record) => record.id === "test-outside-window"));
  console.log("Exchange activity integration passed: signed agent snapshot, confirmed block IPs, private observations, and no-store response.");
} finally {
  server.kill("SIGTERM");
  agent.close();
  rmSync(directory, { recursive: true, force: true });
}
