import { randomBytes, randomUUID } from "node:crypto";

import { json } from "@/app/api/_lib";
import { nodeRegistrationSchema } from "@/lib/exchange-validation";
import { appendAuditLog, consumeRateLimit, registerNodeWithEnrollmentToken } from "@/lib/portal-store";
import { trustedClientIP } from "@/lib/edge-guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const url = new URL(request.url);
  const proto = process.env.EXCHANGE_TRUST_PROXY === "true" ? request.headers.get("x-forwarded-proto") : url.protocol.slice(0, -1);
  const localDev = (process.env.NODE_ENV !== "production" || process.env.NETTOOLS_TEST_INSECURE_LOOPBACK === "true") &&
    (url.hostname === "localhost" || url.hostname === "127.0.0.1");
  if (proto !== "https" && !localDev) return json({ error: "insecure_transport" }, { status: 403 });
  const ip = trustedClientIP(request);
  if (!consumeRateLimit(`enroll:${ip ?? "unattributed"}`, ip ? 10 : 100, 60).allowed) return json({ error: "rate_limited" }, { status: 429 });
  const reader = request.body?.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  if (reader) {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > 8192) {
        await reader.cancel();
        return json({ error: "invalid_payload" }, { status: 413 });
      }
      chunks.push(chunk.value);
    }
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  const parsed = nodeRegistrationSchema.safeParse((() => { try { return JSON.parse(raw); } catch { return null; } })());
  if (!parsed.success) return json({ error: "invalid_payload" }, { status: 400 });
  const payload = parsed.data;
  const secret = randomBytes(32).toString("base64url");
  let node;
  try {
    node = registerNodeWithEnrollmentToken(payload.enrollToken, payload.clusterId, {
      id: payload.id ?? randomUUID(), nodeName: payload.nodeName, trustLevel: 25,
      publicKey: payload.publicKey, softwareVersion: payload.softwareVersion ?? "unknown",
      machineFingerprint: payload.machineFingerprint ?? null, revokedAt: null,
    }, secret);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "enrollment_failed";
    if (reason === "invalid_enrollment_token" || reason === "enrollment_disabled" || reason === "node_limit_or_identity_conflict") {
      return json({ error: reason }, { status: reason === "node_limit_or_identity_conflict" ? 409 : 403 });
    }
    throw error;
  }
  appendAuditLog({ actorType: "node", actorId: node.id, tenantId: node.tenantId, action: "node.enroll",
    reasonCode: null, details: `Admin token enrolled node ${node.nodeName}` });
  return json({ node_id: node.id, tenant_id: node.tenantId, api_base_url: url.origin,
    secret, enrollment_mode: "admin_token" }, { status: 201, headers: { "cache-control": "no-store" } });
}
