import { requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { appendAuditLog, exchangeRetentionSeconds, listAttackExchangeFeedForTenant, listSignalRetractionsForTenant, logSync, recordSignalFeedDeliveries } from "@/lib/portal-store";
import { parseFeedCursor } from "@/lib/exchange-validation";
import { approvedSignalSourceTenants } from "@/lib/discovery-store";
import { getReceivePolicy, trustedSourceTenantIds } from "@/lib/network-admin";

export async function GET(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) {
    return auth.response;
  }

  const url = new URL(request.url);
  const trustThreshold = Number(url.searchParams.get("trustThreshold") ?? 0);
  const adminPolicy = process.env.NETWORK_ADMIN_POLICY_ENFORCED === "true" ? getReceivePolicy(auth.node.tenantId) : null;
  const limit = Number(url.searchParams.get("limit") ?? 100);
  const includePending = url.searchParams.get("includePending") === "true";
  const after = parseFeedCursor(url.searchParams.get("after"));
  const retractionAfterRaw = url.searchParams.get("retractionAfter") ?? "0";
  if (!Number.isInteger(trustThreshold) || trustThreshold < 0 || trustThreshold > 100 ||
      !Number.isInteger(limit) || limit < 1 || limit > 250) {
    return signedNodeJson({ error: "invalid_feed_parameters" }, auth.secret, { status: 400 });
  }
  if (!/^\d{1,15}$/.test(retractionAfterRaw) || !Number.isSafeInteger(Number(retractionAfterRaw))) {
    return signedNodeJson({ error: "invalid_retraction_cursor" }, auth.secret, { status: 400 });
  }
  const feeds = listAttackExchangeFeedForTenant(auth.node.tenantId, {
    trustThreshold,
    minSignalConfidence: adminPolicy?.minConfidence ?? 0,
    limit,
    includePending,
    after,
    approvedSourceTenants: process.env.NETTOOLS_DISCOVERY_ENABLED === "true"
      ? (process.env.NETWORK_ADMIN_POLICY_ENFORCED === "true"
        ? trustedSourceTenantIds(auth.node.tenantId, approvedSignalSourceTenants(auth.node.tenantId))
        : approvedSignalSourceTenants(auth.node.tenantId)) : [],
  });
  recordSignalFeedDeliveries(auth.node.tenantId, feeds.mergedFeed.map((record) => record.id));
  const retractionFeed = listSignalRetractionsForTenant(auth.node.tenantId, Number(retractionAfterRaw), limit);

  logSync({
    nodeId: auth.node.id,
    syncType: "pull",
    success: true,
    recordsCount: feeds.mergedFeed.length,
  });

  appendAuditLog({
    actorType: "node",
    actorId: auth.node.id,
    tenantId: auth.node.tenantId,
    action: "attack_feed.pull",
    reasonCode: null,
    details: `Node pulled ${feeds.localNodeAttacks.length} local node-site attacks and ${feeds.connectedMeshAttacks.length} connected-app attacks`,
  });

  return signedNodeJson({
    tenantId: auth.node.tenantId,
    nodeId: auth.node.id,
    syncWindowSeconds: exchangeRetentionSeconds(),
    cursor: feeds.cursor,
    localNodeAttacks: feeds.localNodeAttacks,
    connectedMeshAttacks: feeds.connectedMeshAttacks,
    mergedFeed: feeds.mergedFeed,
    retractions: retractionFeed.retractions,
    retractionCursor: retractionFeed.cursor,
  }, auth.secret);
}
