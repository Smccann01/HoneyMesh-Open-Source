import { activityReasons, listPublicActivity, type ActivityProtocol, type ActivityReason } from "@/lib/activity-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const headers = { "cache-control": "no-store, max-age=0", "x-robots-tag": "noindex, nofollow" };
  if (process.env.EXCHANGE_ACTIVITY_ENABLED !== "true") {
    return Response.json({ enabled: false, records: [] }, { headers });
  }
  const params = new URL(request.url).searchParams;
  const days = Number(params.get("days") ?? "30");
  const reason = params.get("reason");
  const protocol = params.get("protocol");
  const outcome = params.get("outcome");
  const cursor = params.get("cursor");
  let decodedCursor = "";
  try { decodedCursor = cursor ? Buffer.from(cursor, "base64url").toString("utf8") : ""; } catch { /* Rejected below. */ }
  if (![1, 7, 30].includes(days) || (reason && !Object.hasOwn(activityReasons, reason)) ||
      (protocol && protocol !== "HTTPS" && protocol !== "Unknown") ||
      (outcome && outcome !== "observed" && outcome !== "controlled") ||
      (cursor && (!/^[A-Za-z0-9_-]{1,24}$/.test(cursor) || !/^[1-9][0-9]{0,15}$/.test(decodedCursor)))) {
    return Response.json({ error: "invalid_filter" }, { status: 400, headers });
  }
  try {
    const history = listPublicActivity({
      days, cursor, reason: (reason || null) as ActivityReason | null,
      protocol: (protocol || null) as ActivityProtocol | null,
      outcome: (outcome || null) as "observed" | "controlled" | null,
    });
    return Response.json({ enabled: true, updatedAt: new Date().toISOString(), ...history }, { headers });
  } catch {
    return Response.json({ error: "history_unavailable" }, { status: 503, headers });
  }
}
