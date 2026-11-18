import { getAdmin } from "@/lib/network-admin";
import { findLicenseByTenantID, findTenantByID, getDB } from "@/lib/portal-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const headers = { "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" };
  const admin = getAdmin(request);
  if (!admin) return Response.json({ error: "unauthorized" }, { status: 401, headers });
  const tenant = findTenantByID(admin.tenantId);
  const license = findLicenseByTenantID(admin.tenantId);
  const nodes = getDB().prepare("SELECT count(*) AS count FROM nodes WHERE tenant_id=? AND cluster_id=? AND revoked_at IS NULL").get(admin.tenantId, admin.clusterId) as { count: number };
  const accessActive = tenant?.licenseStatus === "active" && !tenant.exchangeKillSwitch &&
    (tenant.plan === "community" || (tenant.plan === "pro" && license?.tier === "pro" && license.status === "active" && Date.parse(license.expiresAt) > Date.now()));
  return Response.json({ clusterId: admin.clusterId, enrolledNodes: nodes.count, accessActive, sharingEnabled: tenant?.sharingEnabled === true, agentPolicyAcknowledged: false }, { headers });
}
