import { requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { parseDiscoveryJson, verifyDiscoveryIdentity } from "@/lib/discovery-auth";
import { isDirectoryAdmin, logDirectoryEvent, rotateDirectoryAdmin } from "@/lib/discovery-store";
import { z } from "zod";

const schema = z.object({ newAdminNodeId: z.string().uuid() }).strict();

export async function POST(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) return auth.response;
  if (process.env.NETTOOLS_DISCOVERY_ENABLED !== "true") return signedNodeJson({ error: "discovery_disabled" }, auth.secret, { status: 404 });
  if (!isDirectoryAdmin(auth.node) || !verifyDiscoveryIdentity(request, auth.node)) {
    return signedNodeJson({ error: "admin_required" }, auth.secret, { status: 403 });
  }
  const parsed = schema.safeParse(parseDiscoveryJson(auth.body));
  if (!parsed.success || !rotateDirectoryAdmin(auth.node, parsed.data.newAdminNodeId)) {
    return signedNodeJson({ error: "invalid_new_admin" }, auth.secret, { status: 400 });
  }
  logDirectoryEvent(auth.node, "admin.rotate", parsed.data.newAdminNodeId);
  return signedNodeJson({ status: "rotated", newAdminNodeId: parsed.data.newAdminNodeId }, auth.secret);
}
