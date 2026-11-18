import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import { createReferenceService, verifiedSourceResolver } from "./app.mjs";

const key = Buffer.alloc(32, 7);

async function runningService(options = {}) {
  const app = createReferenceService({ signingKey: key, verifiedSource: () => "8.8.8.8", threshold: 2, ...options });
  app.server.listen(0, "127.0.0.1");
  await once(app.server, "listening");
  const url = `http://127.0.0.1:${app.server.address().port}`;
  return { ...app, url, close: () => new Promise((resolve) => app.server.close(resolve)) };
}

test("direct peers cannot forge a proxy source", () => {
  const resolve = verifiedSourceResolver({ trustedProxyPeers: ["127.0.0.1"] });
  assert.equal(resolve({ socket: { remoteAddress: "9.9.9.9" }, headers: { "x-real-ip": "8.8.8.8", "x-forwarded-for": "8.8.8.8" } }), "9.9.9.9");
  assert.equal(resolve({ socket: { remoteAddress: "127.0.0.1" }, headers: { "x-real-ip": "8.8.8.8" } }), "8.8.8.8");
  assert.equal(resolve({ socket: { remoteAddress: "127.0.0.1" }, headers: { "x-real-ip": "8.8.8.8, 1.1.1.1" } }), null);
  assert.equal(resolve({ socket: { remoteAddress: "127.0.0.1" }, headers: { "x-forwarded-for": "8.8.8.8" } }), null);
});

test("reference service rejects enforcement without a paid Guard entitlement", () => {
  assert.throws(() => createReferenceService({ signingKey: key, mode: "enforce", canaryIps: ["8.8.8.8"] }), /entitlement/);
});

test("observe mode records without limiting and agent outage does not break the app", async () => {
  const app = await runningService({ mode: "observe", bridge: { sendEvent: async () => { throw new Error("agent down"); } } });
  try {
    const request = () => fetch(`${app.url}/v1/signed`, { method: "POST", body: "{}" });
    assert.equal((await request()).status, 401);
    assert.equal((await request()).status, 401);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(app.decisions.length, 1);
    assert.equal(app.decisions[0].action, "observed");
    assert.equal((await request()).status, 401);
    assert.equal((await fetch(`${app.url}/healthz`)).status, 200);
  } finally { await app.close(); }
});
