import { requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { listLocalNodeFeedForTenant } from "@/lib/portal-store";

export async function GET(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) return auth.response;
  if (process.env.NETTOOLS_DISCOVERY_ENABLED !== "true") return signedNodeJson({ error: "discovery_disabled" }, auth.secret, { status: 404 });
  const signals = listLocalNodeFeedForTenant(auth.node.tenantId, { limit: 100, status: "any" })
    .filter((signal) => signal.sourceType === "honeymesh_node");
  return signedNodeJson({ signals }, auth.secret);
}
