import { json, requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { appendAuditLog, heartbeatNode } from "@/lib/portal-store";
import { heartbeatSchema } from "@/lib/exchange-validation";
import { touchDirectoryCluster } from "@/lib/discovery-store";

export async function POST(request: Request) {
  // A node reporting itself offline must still be able to authenticate a
  // later heartbeat and return online. Other machine routes remain closed.
  const auth = await requireNodeAuth(request, { requireCommunityAccess: false, allowOffline: true });
  if (!auth.ok) {
    return auth.response;
  }
  const parsedPayload = heartbeatSchema.safeParse(JSON.parse(auth.body || "{}"));
  if (!parsedPayload.success) {
    appendAuditLog({
      actorType: "node",
      actorId: auth.node.id,
      tenantId: auth.node.tenantId,
      action: "node.heartbeat.reject",
      reasonCode: "schema.invalid_payload",
      details: "Rejected heartbeat due to schema validation failure",
    });
    return json({ error: "invalid_payload", issues: parsedPayload.error.flatten() }, { status: 400 });
  }
  const node = heartbeatNode(auth.node.id, parsedPayload.data.status);
  if (!node) {
    return json({ error: "not_found" }, { status: 404 });
  }
  if (parsedPayload.data.status !== "offline") touchDirectoryCluster(node);
  appendAuditLog({
    actorType: "node",
    actorId: auth.node.id,
    tenantId: auth.node.tenantId,
    action: "node.heartbeat",
    reasonCode: null,
    details: `Heartbeat received with status ${node.status}`,
  });
  return signedNodeJson({ record: node }, auth.secret);
}
