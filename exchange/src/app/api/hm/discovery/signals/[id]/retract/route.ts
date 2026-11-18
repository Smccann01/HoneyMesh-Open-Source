import { requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { verifyDiscoveryIdentity } from "@/lib/discovery-auth";
import { isDirectoryAdmin, logDirectoryEvent } from "@/lib/discovery-store";
import { findBanByID, retractPublishedSignal } from "@/lib/portal-store";

export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) return auth.response;
  if (process.env.NETTOOLS_DISCOVERY_ENABLED !== "true") return signedNodeJson({ error: "discovery_disabled" }, auth.secret, { status: 404 });
  if (!isDirectoryAdmin(auth.node) || !verifyDiscoveryIdentity(request, auth.node)) {
    return signedNodeJson({ error: "admin_required" }, auth.secret, { status: 403 });
  }
  const { id } = await context.params;
  const signal = findBanByID(id);
  if (!signal || signal.tenantId !== auth.node.tenantId || signal.sourceType !== "honeymesh_node") {
    return signedNodeJson({ error: "signal_unavailable" }, auth.secret, { status: 404 });
  }
  const updated = retractPublishedSignal(auth.node.tenantId, id);
  if (!updated) return signedNodeJson({ error: "signal_not_approved" }, auth.secret, { status: 409 });
  logDirectoryEvent(auth.node, "signal.retract", id);
  return signedNodeJson({ signal: updated }, auth.secret);
}
