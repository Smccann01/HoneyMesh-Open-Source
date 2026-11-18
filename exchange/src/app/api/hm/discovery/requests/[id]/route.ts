import { requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { parseDiscoveryJson, verifyDiscoveryIdentity } from "@/lib/discovery-auth";
import { decideDirectoryRequest, isDirectoryAdmin, logDirectoryEvent } from "@/lib/discovery-store";
import { directoryDecisionSchema } from "@/lib/exchange-validation";
import { appendAuditLog } from "@/lib/portal-store";

export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) return auth.response;
  if (process.env.NETTOOLS_DISCOVERY_ENABLED !== "true") return signedNodeJson({ error: "discovery_disabled" }, auth.secret, { status: 404 });
  if (!isDirectoryAdmin(auth.node) || !verifyDiscoveryIdentity(request, auth.node)) {
    return signedNodeJson({ error: "admin_required" }, auth.secret, { status: 403 });
  }
  const { id } = await context.params;
  const parsed = directoryDecisionSchema.safeParse(parseDiscoveryJson(auth.body));
  if (!parsed.success) return signedNodeJson({ error: "invalid_decision" }, auth.secret, { status: 400 });
  const result = decideDirectoryRequest(auth.node, id, parsed.data.decision);
  if (!result) return signedNodeJson({ error: "request_unavailable" }, auth.secret, { status: 404 });
  appendAuditLog({ actorType: "node", actorId: auth.node.id, tenantId: auth.node.tenantId,
    action: "discovery.request.decision", reasonCode: null, details: `${id}: ${parsed.data.decision}` });
  logDirectoryEvent(auth.node, "request.decision", `${id}:${parsed.data.decision}`);
  return signedNodeJson({ request: result }, auth.secret);
}
