import { getAdmin, listNetworkPolicyAudit } from "@/lib/network-admin";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const headers = { "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" };

export async function GET(request: Request) {
  const admin = getAdmin(request);
  if (!admin) return Response.json({ error: "unauthorized" }, { status: 401, headers });
  return Response.json({ events: listNetworkPolicyAudit(admin.tenantId) }, { headers });
}
