import { requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { parseDiscoveryJson, verifyDiscoveryIdentity } from "@/lib/discovery-auth";
import { createDirectoryRequest, isDirectoryAdmin, listDirectoryRequests, logDirectoryEvent } from "@/lib/discovery-store";
import { directoryRequestSchema } from "@/lib/exchange-validation";
import { appendAuditLog } from "@/lib/portal-store";

export async function GET(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) return auth.response;
  if (process.env.NETTOOLS_DISCOVERY_ENABLED !== "true") return signedNodeJson({ error: "discovery_disabled" }, auth.secret, { status: 404 });
  return signedNodeJson({ requests: listDirectoryRequests(auth.node) }, auth.secret);
}

export async function POST(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) return auth.response;
  if (process.env.NETTOOLS_DISCOVERY_ENABLED !== "true") return signedNodeJson({ error: "discovery_disabled" }, auth.secret, { status: 404 });
  if (!isDirectoryAdmin(auth.node) || !verifyDiscoveryIdentity(request, auth.node)) {
    return signedNodeJson({ error: "admin_required" }, auth.secret, { status: 403 });
  }
  const parsed = directoryRequestSchema.safeParse(parseDiscoveryJson(auth.body));
  if (!parsed.success) return signedNodeJson({ error: "invalid_request" }, auth.secret, { status: 400 });
  const result = createDirectoryRequest(auth.node, parsed.data.toClusterId, parsed.data.scope);
  if ("error" in result) return signedNodeJson(result, auth.secret, { status: 400 });
  appendAuditLog({ actorType: "node", actorId: auth.node.id, tenantId: auth.node.tenantId,
    action: "discovery.request.create", reasonCode: null, details: `To ${parsed.data.toClusterId}: ${parsed.data.scope}` });
  logDirectoryEvent(auth.node, "request.create", `${parsed.data.toClusterId}:${parsed.data.scope}`);
  return signedNodeJson(result, auth.secret, { status: 201 });
}
