import { getAdmin, sameOrigin } from "@/lib/network-admin";
import { appendAuditLog, findTenantByID, updateTenantExchangeControls } from "@/lib/portal-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const headers = { "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" };

export async function POST(request: Request) {
  const admin = getAdmin(request);
  if (!admin) return Response.json({ error: "unauthorized" }, { status: 401, headers });
  if (!sameOrigin(request)) return Response.json({ error: "origin_required" }, { status: 403, headers });
  const payload = await request.json().catch(() => null);
  if (!payload || typeof payload !== "object" || Array.isArray(payload) ||
      Object.keys(payload).length !== 1 || typeof (payload as { enabled?: unknown }).enabled !== "boolean") {
    return Response.json({ error: "invalid_request" }, { status: 400, headers });
  }
  const tenant = findTenantByID(admin.tenantId);
  if (!tenant || tenant.exchangeKillSwitch) return Response.json({ error: "sharing_disabled" }, { status: 403, headers });
  const updated = updateTenantExchangeControls(admin.tenantId, {
    sharingEnabled: (payload as { enabled: boolean }).enabled,
    reviewOnlyMode: true,
    autoApproveEnabled: false,
    localPolicyMode: "audit_only",
  });
  appendAuditLog({ actorType: "user", actorId: admin.id, tenantId: admin.tenantId,
    action: "exchange_sharing.update", details: `Self-hosted sharing ${updated?.sharingEnabled ? "enabled" : "disabled"}` });
  return Response.json({ sharingEnabled: updated?.sharingEnabled ?? false, reviewOnlyMode: true }, { headers });
}
