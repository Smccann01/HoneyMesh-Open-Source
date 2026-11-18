import { requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { listDirectoryClusters } from "@/lib/discovery-store";

export async function GET(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) return auth.response;
  if (process.env.NETTOOLS_DISCOVERY_ENABLED !== "true") return signedNodeJson({ error: "discovery_disabled" }, auth.secret, { status: 404 });
  const url = new URL(request.url);
  const after = url.searchParams.get("after") ?? "";
  const rawLimit = Number(url.searchParams.get("limit") ?? 50);
  if (after.length > 120 || !/^[A-Za-z0-9_.:-]*$/.test(after) || !Number.isInteger(rawLimit) || rawLimit < 1 || rawLimit > 100) {
    return signedNodeJson({ error: "invalid_query" }, auth.secret, { status: 400 });
  }
  return signedNodeJson({ version: 1, ...listDirectoryClusters(auth.node.tenantId, after, rawLimit) }, auth.secret);
}
