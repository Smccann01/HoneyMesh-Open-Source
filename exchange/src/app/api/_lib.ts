import { NextResponse } from "next/server";

import { findNodeWithSecret, hashNodeBody, signNodeResponse, tenantCanUseCommunityFeed, trustPathForBan, verifyNodeRequest } from "@/lib/auth";
import { appendAuditLog, consumeRateLimit, findTenantByID } from "@/lib/portal-store";
import { edgeGuardBlocked, recordEdgeGuardFailure, trustedClientIP } from "@/lib/edge-guard";

export function json(data: unknown, init?: ResponseInit) {
  return NextResponse.json(data, init);
}

export function signedNodeJson(data: unknown, secret: string, init?: ResponseInit) {
  const body = JSON.stringify(data);
  const status = init?.status ?? 200;
  const timestamp = new Date().toISOString();
  const bodyHash = hashNodeBody(body);
  const response = new NextResponse(body, {
    ...init,
    status,
    headers: {
      "content-type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  response.headers.set("x-hm-response-timestamp", timestamp);
  response.headers.set("x-hm-response-body-sha256", bodyHash);
  response.headers.set("x-hm-response-signature", signNodeResponse(secret, status, timestamp, bodyHash));
  return response;
}

export async function requireNodeAuth(request: Request, options?: { requireCommunityAccess?: boolean; allowOffline?: boolean }) {
  if (edgeGuardBlocked(request)) {
    return { ok: false as const, response: json({ error: "temporarily_blocked" }, { status: 429, headers: { "retry-after": "120" } }) };
  }
  const nodeId = request.headers.get("x-hm-node-id");
  const timestamp = request.headers.get("x-hm-timestamp");
  const nonce = request.headers.get("x-hm-nonce");
  const signature = request.headers.get("x-hm-signature");
  const bodyHash = request.headers.get("x-hm-body-sha256");
  const sourceIp = trustedClientIP(request);
  const proto = process.env.EXCHANGE_TRUST_PROXY === "true"
    ? request.headers.get("x-forwarded-proto")
    : new URL(request.url).protocol.replace(":", "");
  const host = new URL(request.url).hostname;
  const isLocalDev = (process.env.NODE_ENV !== "production" || process.env.NETTOOLS_TEST_INSECURE_LOOPBACK === "true") &&
    (host === "localhost" || host === "127.0.0.1");
  if (!nodeId || !timestamp || !nonce || !signature || !bodyHash) {
    recordEdgeGuardFailure(request, "anonymous_rate_burst");
    return { ok: false as const, response: json({ error: "missing_node_auth" }, { status: 401 }) };
  }
  if (!isLocalDev && proto !== "https") {
    return { ok: false as const, response: json({ error: "insecure_transport" }, { status: 403 }) };
  }
  const record = findNodeWithSecret(nodeId);
  if (!record) {
    recordEdgeGuardFailure(request, "anonymous_rate_burst");
    return { ok: false as const, response: json({ error: "unknown_node" }, { status: 401 }) };
  }
  const ipLimit = sourceIp
    ? consumeRateLimit(`ip:${sourceIp}:${request.method}:${new URL(request.url).pathname}`, 120, 60)
    : null;
  if (ipLimit && !ipLimit.allowed) {
    appendAuditLog({
      actorType: "node",
      actorId: record.node.id,
      tenantId: record.node.tenantId,
      action: "node.auth.reject",
      reasonCode: "exchange.rate_limited",
      details: `Rejected node request from ${sourceIp}: per-IP rate limit exceeded`,
    });
    return { ok: false as const, response: json({ error: "rate_limited" }, { status: 429 }) };
  }
  const cloned = request.clone();
  const body = await cloned.text();
  const signedUrl = new URL(request.url);
  const result = verifyNodeRequest(record.node, request.method, signedUrl.pathname + signedUrl.search, timestamp, nonce, body, signature, bodyHash, options?.allowOffline ?? false);
  if (!result.ok) {
    if (result.reason === "invalid_signature") recordEdgeGuardFailure(request, "invalid_signature_burst");
    if (result.reason === "replay_detected") recordEdgeGuardFailure(request, "replay_burst");
    appendAuditLog({
      actorType: "node",
      actorId: record.node.id,
      tenantId: record.node.tenantId,
      action: "node.auth.reject",
      reasonCode:
        result.reason === "invalid_signature"
          ? "auth.invalid_signature"
          : result.reason === "stale_request"
            ? "auth.stale_request"
            : result.reason === "replay_detected"
              ? "auth.replay_detected"
              : result.reason === "node_inactive"
                ? "auth.node_inactive"
                : result.reason === "invalid_body_hash"
                  ? "auth.invalid_signature"
                : null,
      details: `Rejected node request: ${result.reason}`,
    });
    return { ok: false as const, response: json({ error: result.reason }, { status: 403 }) };
  }
  const tenantLimit = consumeRateLimit(`tenant:${record.node.tenantId}:${request.method}:${new URL(request.url).pathname}`, 500, 60);
  const nodeLimit = consumeRateLimit(`node:${record.node.id}:${request.method}:${new URL(request.url).pathname}`, 120, 60);
  if (!tenantLimit.allowed || !nodeLimit.allowed) {
    appendAuditLog({
      actorType: "node",
      actorId: record.node.id,
      tenantId: record.node.tenantId,
      action: "node.auth.reject",
      reasonCode: "exchange.rate_limited",
      details: `Rejected node request: ${!nodeLimit.allowed ? "node" : "tenant"} rate limit exceeded`,
    });
    return { ok: false as const, response: json({ error: "rate_limited" }, { status: 429 }) };
  }
  if ((options?.requireCommunityAccess ?? true) && !tenantCanUseCommunityFeed(record.node.tenantId)) {
    const tenant = findTenantByID(record.node.tenantId);
    appendAuditLog({
      actorType: "node",
      actorId: record.node.id,
      tenantId: record.node.tenantId,
      action: "node.license.reject",
      reasonCode: tenant?.exchangeKillSwitch ? "exchange.kill_switch" : "auth.community_feed_not_allowed",
      details: "Rejected node request because tenant is not eligible for the community feed",
    });
    return { ok: false as const, response: json({ error: "community_feed_not_allowed" }, { status: 403 }) };
  }
  return { ok: true as const, node: record.node, body, secret: record.secret ?? "" };
}

export function moderationPathForNode(nodeId: string, confidence: number, ja4: string, attackType: string) {
  return trustPathForBan(
    {
      id: nodeId,
      tenantId: "",
      clusterId: "",
      nodeName: "",
      apiKeyHash: "",
      publicKey: "",
      status: "online",
      lastSeen: "",
      trustLevel: 50,
      softwareVersion: "",
      machineFingerprint: null,
      revokedAt: null,
    },
    { confidence, ja4, attackType },
  );
}
