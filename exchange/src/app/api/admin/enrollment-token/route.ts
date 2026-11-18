import { randomBytes } from "node:crypto";

import { getAdmin, sameOrigin } from "@/lib/network-admin";
import { appendAuditLog, consumeRateLimit, createEnrollmentToken, findTenantByID } from "@/lib/portal-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const headers = { "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" };

export async function POST(request: Request) {
  const admin = getAdmin(request);
  if (!admin) return Response.json({ error: "unauthorized" }, { status: 401, headers });
  if (!sameOrigin(request)) return Response.json({ error: "origin_required" }, { status: 403, headers });
  if (!consumeRateLimit(`admin:enrollment:${admin.id}`, 10, 60).allowed) {
    return Response.json({ error: "rate_limited" }, { status: 429, headers });
  }
  const payload = await request.json().catch(() => null);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return Response.json({ error: "invalid_request" }, { status: 400, headers });
  }
  const input = payload as Record<string, unknown>;
  if (Object.keys(input).some((key) => key !== "nodeNameHint") ||
      (input.nodeNameHint !== undefined && (typeof input.nodeNameHint !== "string" || input.nodeNameHint.length < 2 || input.nodeNameHint.length > 80))) {
    return Response.json({ error: "invalid_request" }, { status: 400, headers });
  }
  const tenant = findTenantByID(admin.tenantId);
  if (!tenant || tenant.exchangeKillSwitch) return Response.json({ error: "enrollment_disabled" }, { status: 403, headers });
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
  createEnrollmentToken({ tenantId: admin.tenantId, rawToken: token, expiresAt, createdByUserId: admin.id,
    allowedIp: null, nodeNameHint: typeof input.nodeNameHint === "string" ? input.nodeNameHint : null });
  appendAuditLog({ actorType: "user", actorId: admin.id, tenantId: admin.tenantId,
    action: "enrollment_token.create", details: `Created one-use enrollment token for ${input.nodeNameHint ?? "any node"}` });
  return Response.json({ token, expiresAt, clusterId: admin.clusterId }, { status: 201, headers });
}
