import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { verifyEntitlementWithKey, verifyNodeEntitlement } from "./entitlement.mjs";

test("signed Node entitlement is scoped to product, unit and expiry", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const key = publicKey.export({ type: "spki", format: "pem" });
  const doc = { schema_version: 1, product: "node_guard", subscription_id: "sub_test_1",
    unit_id: "svc_0123456789abcdef01234567", expires_at: "2030-01-01T00:00:00Z" };
  const payload = `HoneyMesh-Node-Entitlement-v1\n${doc.product}\n${doc.subscription_id}\n${doc.unit_id}\n${doc.expires_at}`;
  doc.signature = sign(null, Buffer.from(payload), privateKey).toString("base64");
  const at = Date.parse("2029-01-01T00:00:00Z");
  assert.equal(verifyEntitlementWithKey(doc, "node_guard", doc.unit_id, key, at), true);
  assert.equal(verifyEntitlementWithKey(doc, "node_pro", doc.unit_id, key, at), false);
  assert.equal(verifyEntitlementWithKey(doc, "node_guard", "svc_ffffffffffffffffffffffff", key, at), false);
  assert.equal(verifyEntitlementWithKey(doc, "node_guard", doc.unit_id, key, Date.parse("2030-01-01T00:00:00Z")), false);
  assert.equal(verifyNodeEntitlement(doc, "node_guard", doc.unit_id, at), false);
  assert.equal(verifyEntitlementWithKey({ ...doc, product: "node_pro" }, "node_pro", doc.unit_id, key, at), false);
  assert.equal(verifyEntitlementWithKey({ ...doc, signature: "bad" }, "node_guard", doc.unit_id, key, at), false);
});
