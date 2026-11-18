import { activitySourceId } from "@/lib/activity-source-id";
import { activityReasons } from "@/lib/activity-store";
import { isPublicIndicator } from "@/lib/discovery-policy";
import { fetchAgentEdgeBlocks, guardActivitySnapshot } from "@/lib/edge-guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

let cachedPayload: { until: number; data: unknown } | null = null;
let pendingPayload: Promise<unknown> | null = null;
const reasonLabels: Record<string, string> = activityReasons;

async function buildActivity() {
  if (process.env.EXCHANGE_ACTIVITY_ENABLED !== "true") {
    return { enabled: false, updatedAt: new Date().toISOString() };
  }

  const now = Date.now();
  const guard = guardActivitySnapshot();
  const agent = await fetchAgentEdgeBlocks();
  const records: Array<{ sourceId: string; sourceIp: string | null; reason: string; layer: "Application" | "HoneyMesh agent"; protocol: "HTTPS" | "Unknown"; expiresAt: string }> = [];
  const sourceIds = new Set<string>();

  for (const block of guard.blocks) {
    const expiry = Date.parse(block.expiresAt);
    if (!isPublicIndicator(block.ip) || expiry <= now || expiry > now + 600_000) continue;
    const id = activitySourceId(block.ip);
    sourceIds.add(id);
    records.push({ sourceId: id, sourceIp: block.confirmed ? block.ip : null, reason: reasonLabels[block.reasonCode], layer: "Application", protocol: block.protocol, expiresAt: block.expiresAt });
  }

  for (const block of agent?.blocks ?? []) {
    if (!block || typeof block.ip !== "string" || typeof block.reason_code !== "string" || typeof block.expires_at !== "string") continue;
    const expiry = Date.parse(block.expires_at);
    if (!isPublicIndicator(block.ip) || !reasonLabels[block.reason_code] || expiry <= now || expiry > now + 600_000) continue;
    const id = activitySourceId(block.ip);
    sourceIds.add(id);
    records.push({ sourceId: id, sourceIp: block.ip, reason: reasonLabels[block.reason_code], layer: "HoneyMesh agent", protocol: "Unknown", expiresAt: block.expires_at });
  }

  records.sort((a, b) => Date.parse(a.expiresAt) - Date.parse(b.expiresAt));
  return {
    enabled: true,
    updatedAt: new Date().toISOString(),
    guardMode: process.env.EXCHANGE_GUARD_MODE === "enforce" ? "enforce" : process.env.EXCHANGE_GUARD_MODE === "observe" ? "observe" : "off",
    agentStatus: !process.env.EXCHANGE_EDGE_SOCKET ? "not_configured" : agent ? "connected" : "unavailable",
    agentMode: agent?.mode ?? null,
    recentFailureCount: guard.recentFailureCount,
    activeSources: sourceIds.size,
    activeControls: records.length,
    records: records.slice(0, 100),
  };
}

export async function GET() {
  const headers = { "cache-control": "no-store, max-age=0", "x-robots-tag": "noindex, nofollow" };
  if (cachedPayload && cachedPayload.until > Date.now()) {
    return Response.json(cachedPayload.data, { headers });
  }
  if (!pendingPayload) {
    pendingPayload = buildActivity()
      .then((data) => { cachedPayload = { until: Date.now() + 5000, data }; return data; })
      .finally(() => { pendingPayload = null; });
  }
  return Response.json(await pendingPayload, { headers });
}
