import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createAgentBridge } from "./bridge.mjs";

const secret = "test-only-bridge-secret-with-32-plus-bytes";
const event = {
  sourceIp: "8.8.8.8", reasonCode: "invalid_signature_burst",
  evidenceHash: "a".repeat(64), confidence: 90, ttlSeconds: 120,
};

async function withAgent(handler, run, options = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), "hm-node-bridge-"));
  const socketPath = path.join(directory, "agent.sock");
  const server = http.createServer(handler);
  try {
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(socketPath, resolve); });
    await run(createAgentBridge({ socketPath, secret, ...options }));
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
}

function signedBody(request, body) {
  const { "x-edge-timestamp": timestamp, "x-edge-nonce": nonce, "x-edge-signature": signature } = request.headers;
  assert.match(timestamp, /^\d{4}-\d\d-\d\dT/);
  assert.match(nonce, /^[a-f0-9]{32}$/);
  const expected = createHmac("sha256", secret).update(`${timestamp}\n${nonce}\n${body}`).digest("hex");
  assert.equal(signature, expected);
}

test("sends signed, bounded events and reads an authenticated agent snapshot", async () => {
  const nonces = new Set();
  await withAgent(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    signedBody(request, body);
    assert.equal(nonces.has(request.headers["x-edge-nonce"]), false);
    nonces.add(request.headers["x-edge-nonce"]);
    response.setHeader("content-type", "application/json");
    if (request.url === "/v1/event") {
      assert.equal(request.method, "POST");
      assert.equal(request.headers["content-length"], String(Buffer.byteLength(body)));
      assert.deepEqual(Object.keys(JSON.parse(body)).sort(), ["confidence", "event_id", "evidence_hash", "ip", "reason_code", "source", "ttl_seconds"].sort());
      assert.equal(JSON.parse(body).ip, "8.8.8.8");
      assert.equal(JSON.parse(body).source, "node_guard");
      response.end(JSON.stringify({ status: "observed" }));
    } else {
      assert.equal(request.url, "/v1/active-blocks");
      assert.equal(request.method, "GET");
      response.end(JSON.stringify({ total: 1, mode: "TEST", blocks: [{ ip: "8.8.8.8", reason_code: "invalid_signature_burst", expires_at: new Date(Date.now() + 60_000).toISOString() }] }));
    }
  }, async (bridge) => {
    assert.match((await bridge.sendEvent(event)).eventId, /^[a-f0-9]{32}$/);
    const snapshot = await bridge.activeBlocks();
    assert.equal(snapshot.total, 1);
    assert.equal(snapshot.mode, "TEST");
    assert.equal(snapshot.blocks[0].sourceIp, "8.8.8.8");
  });
  assert.equal(nonces.size, 2);
});

test("binds a signed event to a configured app ID", async () => {
  await withAgent(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    signedBody(request, body);
    assert.equal(JSON.parse(body).app_id, "app_test_01");
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ status: "observed" }));
  }, async (bridge) => {
    assert.equal((await bridge.sendEvent(event)).status, "observed");
  }, { appId: "app_test_01" });
});

test("rejects unsafe event input before opening the socket", async () => {
  const bridge = createAgentBridge({ socketPath: "/run/honeymesh/edge.sock", secret });
  await assert.rejects(bridge.sendEvent({ ...event, sourceIp: "127.0.0.1" }), /verified eligible public IP/);
  await assert.rejects(bridge.sendEvent({ ...event, confidence: 20 }), /80-100/);
  await assert.rejects(bridge.sendEvent({ ...event, ttlSeconds: 3_600 }), /60-300/);
  await assert.rejects(bridge.sendEvent({ ...event, reasonCode: "arbitrary" }), /unknown reasonCode/);
  assert.throws(() => createAgentBridge({ socketPath: "relative.sock", secret }), /absolute/);
  assert.throws(() => createAgentBridge({ socketPath: "/run/honeymesh/edge.sock", secret: "short" }), /32-byte/);
  assert.throws(() => createAgentBridge({ socketPath: "/run/honeymesh/edge.sock", secret, appId: "bad" }), /appId/);
});

test("rejects false success and malformed agent snapshots", async () => {
  await withAgent(async (request, response) => {
    for await (const _ of request) { /* consume */ }
    response.setHeader("content-type", "application/json");
    if (request.url === "/v1/event") response.end(JSON.stringify({ status: "blocked-but-unconfirmed" }));
    else response.end(JSON.stringify({ total: 1, blocks: [{ ip: "127.0.0.1", reason_code: "invalid_signature_burst", expires_at: new Date().toISOString() }] }));
  }, async (bridge) => {
    await assert.rejects(bridge.sendEvent(event), /invalid agent event status/);
    await assert.rejects(bridge.activeBlocks(), /invalid agent block/);
  });
});
