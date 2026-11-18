import { requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { verifyDiscoveryIdentity } from "@/lib/discovery-auth";
import { isDirectoryAdmin, listDirectoryAudit } from "@/lib/discovery-store";

export async function GET(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) return auth.response;
  if (process.env.NETTOOLS_DISCOVERY_ENABLED !== "true") return signedNodeJson({ error: "discovery_disabled" }, auth.secret, { status: 404 });
  if (!isDirectoryAdmin(auth.node) || !verifyDiscoveryIdentity(request, auth.node)) {
    return signedNodeJson({ error: "admin_required" }, auth.secret, { status: 403 });
  }
  const url = new URL(request.url);
  const action = url.searchParams.get("action") ?? "";
  const before = url.searchParams.get("before") ?? "";
  if (action.length > 80 || (before && !Number.isFinite(Date.parse(before)))) {
    return signedNodeJson({ error: "invalid_query" }, auth.secret, { status: 400 });
  }
  return signedNodeJson({ events: listDirectoryAudit(auth.node, action, before, 100) }, auth.secret);
}
