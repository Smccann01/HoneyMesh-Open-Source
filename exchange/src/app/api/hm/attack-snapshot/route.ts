import { requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { snapshotAttackExchangeFeedForTenant } from "@/lib/portal-store";
import { approvedSignalSourceTenants } from "@/lib/discovery-store";
import { getReceivePolicy, trustedSourceTenantIds } from "@/lib/network-admin";

export async function GET(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) return auth.response;

  const url = new URL(request.url);
  const threshold = Number(url.searchParams.get("trustThreshold") ?? 0);
  if (!Number.isInteger(threshold) || threshold < 0 || threshold > 100) {
    return signedNodeJson({ error: "invalid_trust_threshold" }, auth.secret, { status: 400 });
  }
  const policy = process.env.NETWORK_ADMIN_POLICY_ENFORCED === "true" ? getReceivePolicy(auth.node.tenantId) : null;
  const discovery = process.env.NETTOOLS_DISCOVERY_ENABLED === "true"
    ? approvedSignalSourceTenants(auth.node.tenantId) : [];
  const sources = process.env.NETWORK_ADMIN_POLICY_ENFORCED === "true"
    ? trustedSourceTenantIds(auth.node.tenantId, discovery) : discovery;
  const snapshot = snapshotAttackExchangeFeedForTenant(auth.node.tenantId, {
    trustThreshold: threshold,
    minSignalConfidence: policy?.minConfidence ?? 0,
    approvedSourceTenants: sources,
  });
  if (!snapshot.complete) {
    return signedNodeJson({ error: "snapshot_too_large", limit: 2500 }, auth.secret, { status: 409 });
  }
  return signedNodeJson(snapshot, auth.secret);
}
