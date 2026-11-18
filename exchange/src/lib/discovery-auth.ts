import { createPublicKey, verify } from "node:crypto";

import type { NodeRecord } from "@/lib/portal-types";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function parseDiscoveryJson(body: string): unknown {
  try { return JSON.parse(body); } catch { return null; }
}

export function verifyDiscoveryIdentity(request: Request, node: NodeRecord) {
  const encodedSignature = request.headers.get("x-hm-identity-signature") ?? "";
  const timestamp = request.headers.get("x-hm-timestamp") ?? "";
  const nonce = request.headers.get("x-hm-nonce") ?? "";
  const url = new URL(request.url);
  const rawPublicKey = Buffer.from(node.publicKey, "base64");
  const signature = Buffer.from(encodedSignature, "base64");
  if (rawPublicKey.length !== 32 || signature.length !== 64 || !timestamp || !nonce) return false;
  const bodyHash = request.headers.get("x-hm-body-sha256") ?? "";
  const message = Buffer.from([request.method, url.pathname + url.search, timestamp, nonce, bodyHash].join("\n"));
  try {
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]), format: "der", type: "spki" });
    return verify(null, message, key, signature);
  } catch {
    return false;
  }
}
