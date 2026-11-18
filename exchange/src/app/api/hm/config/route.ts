import { requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { exchangeRetentionSeconds, findTenantByID } from "@/lib/portal-store";

export async function GET(request: Request) {
  const auth = await requireNodeAuth(request, { requireCommunityAccess: false });
  if (!auth.ok) {
    return auth.response;
  }
  const tenant = findTenantByID(auth.node.tenantId);
  return signedNodeJson({
    tenantId: auth.node.tenantId,
    sharingEnabled: tenant?.sharingEnabled ?? false,
    exchangeKillSwitch: tenant?.exchangeKillSwitch ?? false,
    reviewOnlyMode: tenant?.reviewOnlyMode ?? false,
    autoApproveEnabled: tenant?.autoApproveEnabled ?? false,
    plan: tenant?.plan ?? "community",
    licenseStatus: tenant?.licenseStatus ?? "invalid",
    localPolicyMode: tenant?.localPolicyMode ?? "audit_only",
    syncWindowSeconds: exchangeRetentionSeconds(),
  }, auth.secret);
}
