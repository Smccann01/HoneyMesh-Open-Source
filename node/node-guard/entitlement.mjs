import { createPublicKey, verify } from "node:crypto";

const LICENSE_KEYS = [`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAg2RJCQObk6HJsoEC5fdvxFWWtOlNNv23gmi42WZS5tM=
-----END PUBLIC KEY-----`, `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAuHkja1vrS7YZbxaaClM5sVO4xnrNlv9A4r3KrwJkT38=
-----END PUBLIC KEY-----`];
const DOMAIN = "HoneyMesh-Node-Entitlement-v1";
const PRODUCTS = Object.freeze({ node_guard: "svc", node_pro: "host" });

export function verifyEntitlementWithKey(document, expectedProduct, expectedUnitId, publicKey, now = Date.now()) {
  if (!document || typeof document !== "object" || Array.isArray(document) ||
      !Object.hasOwn(PRODUCTS, expectedProduct) || document.schema_version !== 1 ||
      document.product !== expectedProduct || document.unit_id !== expectedUnitId ||
      typeof document.subscription_id !== "string" || !/^sub_[A-Za-z0-9_]+$/.test(document.subscription_id) ||
      typeof document.unit_id !== "string" || !new RegExp(`^${PRODUCTS[expectedProduct]}_[a-f0-9]{24}$`).test(document.unit_id) ||
      typeof document.expires_at !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(document.expires_at) ||
      typeof document.signature !== "string" || !/^[A-Za-z0-9+/]{86}==$/.test(document.signature) ||
      !Number.isFinite(now)) return false;
  const expires = Date.parse(document.expires_at);
  if (!Number.isFinite(expires) || expires <= now) return false;
  const payload = `${DOMAIN}\n${document.product}\n${document.subscription_id}\n${document.unit_id}\n${document.expires_at}`;
  try {
    return verify(null, Buffer.from(payload, "ascii"), createPublicKey(publicKey), Buffer.from(document.signature, "base64"));
  } catch {
    return false;
  }
}

export function verifyNodeEntitlement(document, expectedProduct, expectedUnitId, now = Date.now()) {
  return LICENSE_KEYS.some((key) => verifyEntitlementWithKey(document, expectedProduct, expectedUnitId, key, now));
}
