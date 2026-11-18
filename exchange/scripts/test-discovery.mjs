import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, createHmac, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import Database from "better-sqlite3";

const directory = mkdtempSync(path.join(tmpdir(), "hm-discovery-test-"));
const dbPath = path.join(directory, "exchange.db");
const port = 31000 + Math.floor(Math.random() * 20000);
const base = `http://127.0.0.1:${port}`;
const server = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "-p", String(port)], {
  cwd: process.cwd(),
  env: { ...process.env, DATABASE_URL: `file:${dbPath}`, NETTOOLS_DISCOVERY_ENABLED: "true", NETTOOLS_SEED_DEMO: "false", NETTOOLS_TEST_INSECURE_LOOPBACK: "true" },
  stdio: ["ignore", "pipe", "pipe"],
});
let serverOutput = "";
server.stdout.on("data", (chunk) => { serverOutput += chunk.toString(); });
server.stderr.on("data", (chunk) => { serverOutput += chunk.toString(); });

function nodeIdentity(clusterId, tenantId) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { id: randomUUID(), clusterId, tenantId, secret: randomUUID(),
    publicKey: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64"), privateKey };
}

const alpha = nodeIdentity("cid_alpha", "tenant-alpha");
const beta = nodeIdentity("cid_beta", "tenant-beta");
const alphaSuccessor = nodeIdentity("cid_alpha", "tenant-alpha");

function verifyReceivingGoClient(ips, retracted) {
  const agentDirectory = process.env.HM_GO_AGENT_DIR;
  if (!agentDirectory) return;
  execFileSync("go", ["test", ".", "-run", "^TestExchangeDisposableServerContract$", "-count=1"], {
    cwd: agentDirectory,
    env: {
      ...process.env,
      HM_EXCHANGE_TEST_ORIGIN: base,
      HM_EXCHANGE_TEST_NODE_ID: alpha.id,
      HM_EXCHANGE_TEST_SECRET: alpha.secret,
      HM_EXCHANGE_TEST_IPS: ips.join(","),
      HM_EXCHANGE_TEST_RETRACTED: retracted ? "true" : "false",
    },
    stdio: "pipe",
  });
}

async function waitForServer() {
  for (let attempt = 0; attempt < 80; attempt++) {
    if (server.exitCode !== null) throw new Error(`server exited: ${serverOutput}`);
    try { await fetch(`${base}/api/hm/discovery/profile`); return; } catch { /* startup */ }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`server did not start: ${serverOutput}`);
}

function seedNode(db, node) {
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + 86400_000).toISOString();
  db.prepare(`INSERT INTO tenants (id, name, plan, sharing_enabled, exchange_kill_switch, review_only_mode,
    auto_approve_enabled, trust_level, license_status, local_policy_mode, license_id)
    VALUES (?, ?, 'pro', 1, 0, 1, 0, 90, 'active', 'audit_only', ?)`)
    .run(node.tenantId, node.clusterId, `license-${node.tenantId}`);
  db.prepare(`INSERT INTO licenses (id, tenant_id, tier, status, issued_at, expires_at, license_fingerprint,
    raw_metadata_json, mesh_scope_expires_at, last_validated_at) VALUES (?, ?, 'pro', 'active', ?, ?, ?, '{}', ?, ?)`)
    .run(`license-${node.tenantId}`, node.tenantId, now, expires, `fp-${node.tenantId}`, expires, now);
  seedAdditionalNode(db, node);
}

function seedAdditionalNode(db, node) {
  db.prepare(`INSERT INTO nodes (id, tenant_id, cluster_id, node_name, api_key_hash, public_key, status,
    last_seen, trust_level, software_version, machine_fingerprint, revoked_at)
    VALUES (?, ?, ?, ?, ?, ?, 'online', ?, 95, 'test', NULL, NULL)`)
    .run(node.id, node.tenantId, node.clusterId, node.clusterId,
      createHash("sha256").update(node.secret).digest("hex"), node.publicKey, new Date().toISOString());
  db.prepare("INSERT INTO node_credentials (node_id, shared_secret) VALUES (?, ?)").run(node.id, node.secret);
}

async function call(node, method, urlPath, payload, identity = false) {
  const body = payload === undefined ? "" : JSON.stringify(payload);
  const timestamp = new Date().toISOString();
  const nonce = randomUUID();
  const bodyHash = createHash("sha256").update(body).digest("hex");
  const signature = createHmac("sha256", node.secret).update([method, urlPath, timestamp, nonce, body].join("\n")).digest("hex");
  const headers = { "x-hm-node-id": node.id, "x-hm-timestamp": timestamp, "x-hm-nonce": nonce,
    "x-hm-body-sha256": bodyHash, "x-hm-signature": signature };
  if (identity) {
    headers["x-hm-identity-signature"] = sign(null,
      Buffer.from([method, urlPath, timestamp, nonce, bodyHash].join("\n")), node.privateKey).toString("base64");
  }
  if (body) headers["content-type"] = "application/json";
  const response = await fetch(base + urlPath, { method, headers, body: body || undefined });
  const responseText = await response.text();
  const responseSignature = response.headers.get("x-hm-response-signature");
  if (responseSignature) {
    const responseTimestamp = response.headers.get("x-hm-response-timestamp");
    const responseBodyHash = response.headers.get("x-hm-response-body-sha256");
    assert.ok(responseTimestamp && responseBodyHash);
    assert.equal(responseBodyHash, createHash("sha256").update(responseText).digest("hex"));
    assert.equal(responseSignature, createHmac("sha256", node.secret)
      .update(["response", String(response.status), responseTimestamp, responseBodyHash].join("\n")).digest("hex"));
  }
  let data;
  try {
    data = JSON.parse(responseText);
  } catch {
    throw new Error(`Non-JSON discovery response: ${method} ${urlPath}, status=${response.status}, content-type=${response.headers.get("content-type")}, bytes=${responseText.length}`);
  }
  return { status: response.status, data, signed: !!responseSignature };
}

try {
  await waitForServer();
  await call(alpha, "GET", "/api/hm/discovery/profile"); // Initialize the isolated database.
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  seedNode(db, alpha);
  seedNode(db, beta);
  seedAdditionalNode(db, alphaSuccessor);

  assert.equal((await call(alpha, "POST", "/api/hm/heartbeat", { status: "offline" })).status, 200);
  assert.equal((await call(alpha, "GET", "/api/hm/config")).status, 403,
    "offline nodes must not use ordinary machine routes");
  const recovered = await call(alpha, "POST", "/api/hm/heartbeat", { status: "online" });
  assert.equal(recovered.status, 200, JSON.stringify(recovered.data));
  assert.equal(recovered.signed, true);
  assert.equal((await call(alpha, "GET", "/api/hm/config")).status, 200,
    "signed heartbeat must restore an offline node without re-enrollment");

  for (const node of [alpha, beta]) {
    assert.equal((await call(node, "POST", "/api/hm/discovery/profile", {}, true)).status, 200);
    assert.equal((await call(node, "PUT", "/api/hm/discovery/profile", {
      displayName: node.clusterId, discoverable: true, allowInvites: true,
      allowSignals: true, capabilities: ["mesh-v2", "exchange-signals-v1"],
    }, true)).status, 200);
  }
  assert.equal((await call(alpha, "PUT", "/api/hm/discovery/profile", {
    displayName: "Unauthorized", discoverable: false, allowInvites: false,
    allowSignals: false, capabilities: [],
  })).status, 403, "routine machine secret cannot change directory profile");

  const discovered = await call(alpha, "GET", "/api/hm/discovery/clusters?limit=50");
  assert.equal(discovered.status, 200, JSON.stringify(discovered.data));
  assert.deepEqual(discovered.data.clusters.map((item) => item.clusterId), ["cid_beta"]);
  const now = new Date().toISOString();
  const publicSignalId = randomUUID();
  db.prepare(`INSERT INTO bans (id, source_type, tenant_id, node_id, attacker_ip, cidr, ja4, ja3_legacy,
    attack_type, protocol, port, service, confidence, reason, first_seen, last_seen, ttl, status,
    evidence_hash, trust_score_at_submission, publisher, source_channel, action_taken, mode)
    VALUES (?, 'honeymesh_node', ?, ?, '8.8.8.8', NULL, 'ja4-test', '', 'probe', 'tcp', 80, 'http',
    95, 'test signal', ?, ?, 300, 'approved', ?, 95, 'beta', 'local', 'temporary_ban', 'audit_only')`)
    .run(publicSignalId, beta.tenantId, beta.id, now, now, randomUUID());
  db.prepare(`INSERT INTO bans (id, source_type, tenant_id, node_id, attacker_ip, cidr, ja4, ja3_legacy,
    attack_type, protocol, port, service, confidence, reason, first_seen, last_seen, ttl, status,
    evidence_hash, trust_score_at_submission, publisher, source_channel, action_taken, mode)
    VALUES (?, 'honeymesh_node', ?, ?, '1.1.1.1', NULL, 'ja4-test', '', 'probe', 'tcp', 80, 'http',
    95, 'second test signal', ?, ?, 300, 'approved', ?, 95, 'beta', 'local', 'temporary_ban', 'audit_only')`)
    .run(randomUUID(), beta.tenantId, beta.id, now, now, randomUUID());
  db.prepare(`INSERT INTO bans (id, source_type, tenant_id, node_id, attacker_ip, cidr, ja4, ja3_legacy,
    attack_type, protocol, port, service, confidence, reason, first_seen, last_seen, ttl, status,
    evidence_hash, trust_score_at_submission, publisher, source_channel, action_taken, mode)
    VALUES (?, 'honeymesh_node', ?, ?, '10.0.0.9', NULL, 'ja4-test', '', 'probe', 'tcp', 80, 'http',
    95, 'private test signal', ?, ?, 300, 'approved', ?, 95, 'beta', 'local', 'temporary_ban', 'audit_only')`)
    .run(randomUUID(), beta.tenantId, beta.id, now, now, randomUUID());
  const feedPath = "/api/hm/attack-feed?limit=50";
  assert.equal((await call(alpha, "GET", feedPath)).data.mergedFeed.length, 0,
    "unapproved source must not enter the feed");
  const requested = await call(beta, "POST", "/api/hm/discovery/requests", { toClusterId: alpha.clusterId, scope: "signals" }, true);
  assert.equal(requested.status, 201, JSON.stringify(requested.data));
  const requestId = requested.data.request.id;
  const duplicateRequest = await call(beta, "POST", "/api/hm/discovery/requests", { toClusterId: alpha.clusterId, scope: "signals" }, true);
  assert.equal(duplicateRequest.data.request.id, requestId, "duplicate request must be idempotent");
  assert.equal((await call(alpha, "POST", `/api/hm/discovery/requests/${requestId}`, { decision: "approved" }, true)).status, 200);
  const approvedFeed = await call(alpha, "GET", feedPath);
  assert.equal(approvedFeed.status, 200, JSON.stringify(approvedFeed.data));
  assert.equal(approvedFeed.signed, true);
  assert.equal(approvedFeed.data.mergedFeed.length, 2, JSON.stringify(approvedFeed));
  assert.equal(approvedFeed.data.retractionCursor, 0);
  assert.deepEqual(approvedFeed.data.retractions, []);
  assert.equal(approvedFeed.data.mergedFeed.every((item) => item.clusterId === beta.clusterId && item.sourceChannel === "community"), true);
  assert.equal(approvedFeed.data.mergedFeed.every((item) => !("tenantId" in item) && !("nodeId" in item) && item.reason === "Approved shared defensive signal"), true,
    "cross-cluster feed must exclude tenant and node details");
  assert.deepEqual(approvedFeed.data.mergedFeed.map((item) => item.attackerIp).sort(), ["1.1.1.1", "8.8.8.8"],
    "private indicators must stay within their tenant");
  const approvedSnapshot = await call(alpha, "GET", "/api/hm/attack-snapshot?trustThreshold=50");
  assert.equal(approvedSnapshot.status, 200);
  assert.equal(approvedSnapshot.signed, true);
  assert.equal(approvedSnapshot.data.complete, true);
  assert.deepEqual(approvedSnapshot.data.records.map((item) => item.attackerIp).sort(), ["1.1.1.1", "8.8.8.8"]);
  assert.equal(approvedSnapshot.data.records.every((item) => item.ttl > 0 && item.ttl <= 300), true);
  verifyReceivingGoClient(["1.1.1.1", "8.8.8.8"], false);
  const expiredSignalId = randomUUID();
  const expiredSeen = new Date(Date.now() - 310_000).toISOString();
  db.prepare(`INSERT INTO bans (id, source_type, tenant_id, node_id, attacker_ip, cidr, ja4, ja3_legacy,
    attack_type, protocol, port, service, confidence, reason, first_seen, last_seen, ttl, status,
    evidence_hash, trust_score_at_submission, publisher, source_channel, action_taken, mode)
    VALUES (?, 'honeymesh_node', ?, ?, '9.9.9.9', NULL, '', '', 'probe', 'tcp', 80, 'http',
    95, 'expired signal', ?, ?, 300, 'approved', ?, 95, 'beta', 'local', 'temporary_ban', 'audit_only')`)
    .run(expiredSignalId, beta.tenantId, beta.id, expiredSeen, expiredSeen, randomUUID());
  assert.equal((await call(alpha, "GET", feedPath)).data.mergedFeed.some((item) => item.id === expiredSignalId), false,
    "expired cross-cluster signal must not enter the feed");
  assert.equal((await call(alpha, "GET", "/api/hm/attack-snapshot?trustThreshold=50")).data.records.some((item) => item.id === expiredSignalId), false,
    "expired cross-cluster signal must not enter a complete snapshot");
  db.prepare("DELETE FROM bans WHERE id = ?").run(expiredSignalId);
  assert.equal((await call(alpha, "GET", "/api/hm/attack-snapshot?trustThreshold=invalid")).status, 400);
  assert.equal((await call(beta, "POST", `/api/hm/discovery/signals/${publicSignalId}/retract`, {}, true)).status, 200);
  const afterRetractionSnapshot = await call(alpha, "GET", "/api/hm/attack-snapshot?trustThreshold=50");
  assert.deepEqual(afterRetractionSnapshot.data.records.map((item) => item.attackerIp), ["1.1.1.1"]);
  assert.equal(afterRetractionSnapshot.data.retractionCursor > 0, true);
  const retractedFeed = await call(alpha, "GET", `${feedPath}&retractionAfter=0`);
  assert.equal(retractedFeed.signed, true);
  assert.equal((await call(beta, "GET", `${feedPath}&retractionAfter=0`)).data.retractions.length, 0,
    "retractions are visible only to tenants that received the signal");
  assert.equal((await call(alpha, "GET", `${feedPath}&retractionAfter=invalid`)).status, 400);
  assert.equal((await call(alpha, "GET", "/api/hm/attack-feed?trustThreshold=invalid")).status, 400);
  assert.equal((await call(alpha, "GET", "/api/hm/attack-feed?limit=NaN")).status, 400);
  assert.deepEqual(retractedFeed.data.retractions.map((item) => ({ id: item.signalId, ip: item.attackerIp, cluster: item.clusterId })),
    [{ id: publicSignalId, ip: "8.8.8.8", cluster: beta.clusterId }]);
  assert.equal(retractedFeed.data.retractionCursor > 0, true);
  verifyReceivingGoClient(["1.1.1.1"], true);
  assert.deepEqual((await call(alpha, "GET", `${feedPath}&retractionAfter=${retractedFeed.data.retractionCursor}`)).data.retractions, [],
    "retraction cursor must not replay an acknowledged event");
  assert.equal((await call(beta, "POST", `/api/hm/discovery/signals/${publicSignalId}/retract`, {}, true)).status, 200);
  assert.equal((await call(alpha, "GET", `${feedPath}&retractionAfter=0`)).data.retractions.length, 1,
    "repeat retraction must be idempotent");
  assert.deepEqual((await call(alpha, "GET", feedPath)).data.mergedFeed.map((item) => item.attackerIp), ["1.1.1.1"],
    "retracted signal must leave the feed");
  assert.equal((await call(alpha, "POST", `/api/hm/discovery/requests/${requestId}`, { decision: "revoked" }, true)).status, 200);
  assert.equal((await call(alpha, "GET", `${feedPath}&retractionAfter=0`)).data.retractions.length, 1,
    "retraction remains available to a prior recipient after trust revocation");
  assert.equal((await call(alpha, "GET", feedPath)).data.mergedFeed.length, 0,
    "revocation must remove the source from future feeds");
  assert.deepEqual((await call(alpha, "GET", "/api/hm/attack-snapshot?trustThreshold=50")).data.records, [],
    "revoked source must leave a complete snapshot");
  db.prepare("UPDATE licenses SET expires_at = ? WHERE tenant_id = ?")
    .run(new Date(Date.now() - 1000).toISOString(), beta.tenantId);
  assert.deepEqual((await call(alpha, "GET", "/api/hm/discovery/clusters?limit=50")).data.clusters, [],
    "expired tenants must disappear from discovery");
  assert.equal((await call(alpha, "POST", "/api/hm/discovery/admin", { newAdminNodeId: alphaSuccessor.id }, true)).status, 200);
  const profileChange = { displayName: "Alpha transferred", discoverable: true, allowInvites: true,
    allowSignals: true, capabilities: ["mesh-v2"] };
  assert.equal((await call(alpha, "PUT", "/api/hm/discovery/profile", profileChange, true)).status, 403);
  assert.equal((await call(alphaSuccessor, "PUT", "/api/hm/discovery/profile", profileChange, true)).status, 200);
  const audit = await call(alphaSuccessor, "GET", "/api/hm/discovery/audit?action=admin.rotate", undefined, true);
  assert.equal(audit.status, 200);
  assert.equal(audit.data.events.length, 1);
  assert.equal((db.prepare("SELECT COUNT(*) AS n FROM directory_audit").get()).n >= 5, true);
  const agingSignalId = randomUUID();
  const agingSeen = new Date(Date.now() - 280_000).toISOString();
  db.prepare(`INSERT INTO bans (id, source_type, tenant_id, node_id, attacker_ip, cidr, ja4, ja3_legacy,
    attack_type, protocol, port, service, confidence, reason, first_seen, last_seen, ttl, status,
    evidence_hash, trust_score_at_submission, publisher, source_channel, action_taken, mode)
    VALUES (?, 'honeymesh_node', ?, ?, '8.8.4.4', NULL, '', '', 'probe', 'tcp', 80, 'http',
    95, 'aging signal', ?, ?, 300, 'approved', ?, 95, 'alpha', 'local', 'temporary_ban', 'audit_only')`)
    .run(agingSignalId, alpha.tenantId, alpha.id, agingSeen, agingSeen, randomUUID());
  const agingFeed = await call(alpha, "GET", feedPath);
  const agingRecord = agingFeed.data.mergedFeed.find((record) => record.id === agingSignalId);
  assert.ok(agingRecord && agingRecord.ttl > 0 && agingRecord.ttl <= 21,
    "near-expired feed signal must not regain its original 300-second TTL");
  db.prepare("DELETE FROM bans WHERE id = ?").run(agingSignalId);
  const backupPath = path.join(directory, "verified-backup.db");
  execFileSync(process.execPath, ["scripts/backup-exchange.mjs", backupPath], {
    cwd: process.cwd(), env: { ...process.env, DATABASE_URL: `file:${dbPath}` }, stdio: "pipe",
  });
  const restored = new Database(backupPath, { readonly: true });
  assert.equal(restored.pragma("integrity_check", { simple: true }), "ok");
  assert.equal(restored.prepare("SELECT COUNT(*) AS n FROM directory_requests").get().n, 1);
  assert.equal(restored.prepare("SELECT COUNT(*) AS n FROM signal_retractions").get().n, 1);
  assert.equal(restored.prepare("SELECT COUNT(*) AS n FROM signal_feed_deliveries WHERE recipient_tenant_id = ?").get(alpha.tenantId).n >= 2, true);
  restored.close();
  const insertBoundarySignal = db.prepare(`INSERT INTO bans (id, source_type, tenant_id, node_id, attacker_ip, cidr, ja4, ja3_legacy,
    attack_type, protocol, port, service, confidence, reason, first_seen, last_seen, ttl, status,
    evidence_hash, trust_score_at_submission, publisher, source_channel, action_taken, mode)
    VALUES (?, 'honeymesh_node', ?, ?, '192.0.2.99', NULL, '', '', 'probe', 'tcp', 80, 'http',
    95, 'snapshot boundary test', ?, ?, 300, 'approved', ?, 95, 'alpha', 'local', 'temporary_ban', 'audit_only')`);
  const boundaryNow = new Date().toISOString();
  db.transaction(() => {
    for (let i = 0; i < 2500; i++) {
      insertBoundarySignal.run(randomUUID(), alpha.tenantId, alpha.id, boundaryNow, boundaryNow, randomUUID());
    }
  })();
  const completeBoundary = await call(alpha, "GET", "/api/hm/attack-snapshot?trustThreshold=50");
  assert.equal(completeBoundary.status, 200);
  assert.equal(completeBoundary.data.complete, true);
  assert.equal(completeBoundary.data.records.length, 2500);
  insertBoundarySignal.run(randomUUID(), alpha.tenantId, alpha.id, boundaryNow, boundaryNow, randomUUID());
  const overflow = await call(alpha, "GET", "/api/hm/attack-snapshot?trustThreshold=50");
  assert.equal(overflow.status, 409);
  assert.equal(overflow.signed, true);
  assert.equal(overflow.data.error, "snapshot_too_large");
  assert.equal("records" in overflow.data, false, "incomplete snapshot must not look usable");
  db.prepare("DELETE FROM bans WHERE attacker_ip = '192.0.2.99'").run();
  const community = nodeIdentity("cid_community", "tenant-community");
  db.prepare(`INSERT INTO tenants (id, name, plan, sharing_enabled, exchange_kill_switch, review_only_mode,
    auto_approve_enabled, trust_level, license_status, local_policy_mode, license_id)
    VALUES (?, ?, 'community', 1, 0, 1, 0, 50, 'active', 'audit_only', NULL)`)
    .run(community.tenantId, community.clusterId);
  seedAdditionalNode(db, community);
  assert.equal((await call(community, "POST", "/api/hm/discovery/profile", {}, true)).status, 200);
  assert.equal((await call(community, "PUT", "/api/hm/discovery/profile", {
    displayName: "Community", discoverable: true, allowInvites: false,
    allowSignals: true, capabilities: ["exchange-signals-v1"],
  }, true)).status, 200);
  const communityDirectory = await call(alpha, "GET", "/api/hm/discovery/clusters?limit=50");
  assert.deepEqual(communityDirectory.data.clusters.map((item) => item.clusterId), [community.clusterId]);
  const communityRequest = await call(community, "POST", "/api/hm/discovery/requests", {
    toClusterId: alpha.clusterId, scope: "signals",
  }, true);
  assert.equal(communityRequest.status, 201, JSON.stringify(communityRequest.data));
  assert.equal((await call(alphaSuccessor, "POST", `/api/hm/discovery/requests/${communityRequest.data.request.id}`,
    { decision: "approved" }, true)).status, 200);
  const communitySignalId = randomUUID();
  const communityNow = new Date().toISOString();
  db.prepare(`INSERT INTO bans (id, source_type, tenant_id, node_id, attacker_ip, cidr, ja4, ja3_legacy,
    attack_type, protocol, port, service, confidence, reason, first_seen, last_seen, ttl, status,
    evidence_hash, trust_score_at_submission, publisher, source_channel, action_taken, mode)
    VALUES (?, 'honeymesh_node', ?, ?, '8.8.8.9', NULL, 'ja4-test', '', 'probe', 'tcp', 80, 'http',
    95, 'community signal', ?, ?, 300, 'approved', ?, 95, 'community', 'local', 'temporary_ban', 'audit_only')`)
    .run(communitySignalId, community.tenantId, community.id, communityNow, communityNow, randomUUID());
  assert.equal((await call(alpha, "GET", feedPath)).data.mergedFeed.some((item) => item.id === communitySignalId), true,
    "approved community signal source must enter the observation feed");
  db.prepare("UPDATE tenants SET sharing_enabled = 0 WHERE id = ?").run(community.tenantId);
  assert.deepEqual((await call(alpha, "GET", "/api/hm/discovery/clusters?limit=50")).data.clusters, [],
    "community opt-out must remove directory visibility");
  assert.equal((await call(alpha, "GET", feedPath)).data.mergedFeed.some((item) => item.id === communitySignalId), false,
    "community opt-out must remove shared signals");
  db.close();
  process.stdout.write(`Discovery integration passed: opt-in, signed snapshots, 2,500-row boundary, revocation, admin transfer${process.env.HM_GO_AGENT_DIR ? ", and receiving Go client" : ""}.\n`);
} finally {
  if (server.exitCode === null) {
    server.kill("SIGTERM");
    await new Promise((resolve) => server.once("exit", resolve));
  }
  rmSync(directory, { recursive: true, force: true });
}
