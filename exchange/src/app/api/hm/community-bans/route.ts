import { json, requireNodeAuth } from "@/app/api/_lib";
import { appendAuditLog, listCommunityFeedForTenant, logSync } from "@/lib/portal-store";
import { parseFeedCursor } from "@/lib/exchange-validation";

export async function GET(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) {
    return auth.response;
  }
  const url = new URL(request.url);
  const trustThreshold = Number(url.searchParams.get("trustThreshold") ?? 0);
  const limit = Number(url.searchParams.get("limit") ?? 100);
  const after = parseFeedCursor(url.searchParams.get("since"));
  const { records, cursor } = listCommunityFeedForTenant(auth.node.tenantId, { after, trustThreshold, limit });
  logSync({
    nodeId: auth.node.id,
    syncType: "pull",
    success: true,
    recordsCount: records.length,
  });
  appendAuditLog({
    actorType: "node",
    actorId: auth.node.id,
    tenantId: auth.node.tenantId,
    action: "ban.pull",
    reasonCode: null,
    details: `Node pulled ${records.length} approved community bans`,
  });
  return json({ records, cursor });
}
