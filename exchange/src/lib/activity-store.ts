import { randomUUID } from "node:crypto";
import { isIP } from "node:net";

import { isPublicIndicator } from "@/lib/discovery-policy";
import { getDB } from "@/lib/portal-store";

export const activityReasons = {
  invalid_signature_burst: "Invalid machine signatures",
  replay_burst: "Replay attempts",
  anonymous_rate_burst: "Excessive unauthenticated requests",
} as const;

export type ActivityReason = keyof typeof activityReasons;
export type ActivityProtocol = "HTTPS" | "Unknown";
export type ActivityAction = "observed" | "limit_armed";

type StoredActivity = {
  id: number;
  externalId: string;
  sourceId: string;
  sourceIp: string | null;
  reasonCode: ActivityReason;
  protocol: ActivityProtocol;
  serviceClass: string;
  detector: string;
  action: ActivityAction;
  observedAt: string;
  expiresAt: string | null;
  enforcedAt: string | null;
  hitCount: number;
};

const PUBLIC_DAYS = 30;
const PRIVATE_DAYS = 90;
const MAX_ROWS = 50_000;
let lastPruneAt = 0;

function pruneActivity() {
  if (Date.now() - lastPruneAt < 60 * 60_000) return;
  const db = getDB();
  db.prepare("DELETE FROM exchange_activity_records WHERE observed_at < ?")
    .run(new Date(Date.now() - PRIVATE_DAYS * 86_400_000).toISOString());
  db.prepare("UPDATE exchange_activity_records SET source_ip=NULL WHERE source_ip IS NOT NULL AND observed_at < ?")
    .run(new Date(Date.now() - PUBLIC_DAYS * 86_400_000).toISOString());
  lastPruneAt = Date.now();
}

export function recordGuardActivity(input: {
  sourceId: string;
  reasonCode: ActivityReason;
  protocol: ActivityProtocol;
  observedAt: string;
  expiresAt: string | null;
  hitCount: number;
  action: ActivityAction;
}) {
  const externalId = randomUUID();
  const db = getDB();
  db.transaction(() => {
    db.prepare(`INSERT INTO exchange_activity_records
      (external_id, source_id, reason_code, protocol, service_class, detector, action, observed_at, expires_at, enforced_at, hit_count)
      VALUES (?, ?, ?, ?, 'Exchange machine API', 'Exchange Guard', ?, ?, ?, NULL, ?)`).run(
      externalId, input.sourceId, input.reasonCode, input.protocol, input.action,
      input.observedAt, input.expiresAt, input.hitCount,
    );
    db.prepare("DELETE FROM exchange_activity_records WHERE observed_at < ?")
      .run(new Date(Date.now() - PRIVATE_DAYS * 86_400_000).toISOString());
    const count = (db.prepare("SELECT COUNT(*) AS count FROM exchange_activity_records").get() as { count: number }).count;
    if (count > MAX_ROWS) {
      db.prepare("DELETE FROM exchange_activity_records WHERE id NOT IN (SELECT id FROM exchange_activity_records ORDER BY id DESC LIMIT ?)").run(MAX_ROWS);
      db.prepare("INSERT INTO exchange_activity_meta (id, truncated_at) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET truncated_at=excluded.truncated_at")
        .run(new Date().toISOString());
    }
  })();
  return externalId;
}

export function confirmGuardRejection(externalId: string, sourceIp: string) {
  if (!isIP(sourceIp) || !isPublicIndicator(sourceIp)) return;
  getDB().prepare("UPDATE exchange_activity_records SET enforced_at=COALESCE(enforced_at, ?), source_ip=COALESCE(source_ip, ?) WHERE external_id=? AND action='limit_armed'")
    .run(new Date().toISOString(), sourceIp, externalId);
}

function parseCursor(value: string | null) {
  if (!value) return null;
  try {
    const decoded = Buffer.from(value, "base64url").toString("utf8");
    if (!/^[1-9][0-9]{0,15}$/.test(decoded)) return null;
    const id = Number(decoded);
    return Number.isSafeInteger(id) ? id : null;
  } catch { return null; }
}

export function listPublicActivity(input: {
  days: number;
  cursor: string | null;
  reason: ActivityReason | null;
  protocol: ActivityProtocol | null;
  outcome: "observed" | "controlled" | null;
}) {
  pruneActivity();
  const db = getDB();
  const days = [1, 7, 30].includes(input.days) ? input.days : PUBLIC_DAYS;
  const cutoff = new Date(Date.now() - days * 86_400_000).toISOString();
  const conditions = ["observed_at >= ?"];
  const params: Array<string | number> = [cutoff];
  if (input.reason) { conditions.push("reason_code = ?"); params.push(input.reason); }
  if (input.protocol) { conditions.push("protocol = ?"); params.push(input.protocol); }
  if (input.outcome) { conditions.push("action = ?"); params.push(input.outcome === "observed" ? "observed" : "limit_armed"); }
  const filteredWhere = conditions.join(" AND ");
  const cursorId = parseCursor(input.cursor);
  if (cursorId) { conditions.push("id < ?"); params.push(cursorId); }
  const rows = db.prepare(`SELECT id, external_id AS externalId, source_id AS sourceId, source_ip AS sourceIp,
    reason_code AS reasonCode, protocol, service_class AS serviceClass, detector,
    action, observed_at AS observedAt, expires_at AS expiresAt,
    enforced_at AS enforcedAt, hit_count AS hitCount
    FROM exchange_activity_records WHERE ${conditions.join(" AND ")} ORDER BY id DESC LIMIT 51`)
    .all(...params) as StoredActivity[];
  const page = rows.slice(0, 50);
  const nextCursor = rows.length > 50 && page.length ? Buffer.from(String(page[page.length - 1].id)).toString("base64url") : null;
  const now = Date.now();
  const records = page.filter((row) => row.reasonCode in activityReasons && /^HM-[A-F0-9]{10}$/.test(row.sourceId)).map((row) => ({
    id: row.externalId,
    sourceId: row.sourceId,
    sourceIp: row.enforcedAt && row.sourceIp && isIP(row.sourceIp) && isPublicIndicator(row.sourceIp) ? row.sourceIp : null,
    behavior: activityReasons[row.reasonCode],
    reasonCode: row.reasonCode,
    protocol: row.protocol === "HTTPS" ? "HTTPS" : "Unknown",
    serviceClass: "Exchange machine API",
    detector: "Exchange Guard",
    layer: "Application" as const,
    outcome: row.action === "observed" ? "Observed" : row.expiresAt && Date.parse(row.expiresAt) <= now ? "Expired" : row.enforcedAt ? "Blocked" : "Limit armed",
    observedAt: row.observedAt,
    expiresAt: row.expiresAt,
    enforcedAt: row.enforcedAt,
    hitCount: row.hitCount,
  }));
  const coverage = db.prepare("SELECT MIN(observed_at) AS oldestAt FROM exchange_activity_records WHERE observed_at >= ?")
    .get(new Date(Date.now() - PUBLIC_DAYS * 86_400_000).toISOString()) as { oldestAt: string | null };
  const meta = db.prepare("SELECT truncated_at AS truncatedAt FROM exchange_activity_meta WHERE id=1").get() as { truncatedAt: string | null } | undefined;
  const historyTruncated = !!meta?.truncatedAt && Date.parse(meta.truncatedAt) >= Date.now() - days * 86_400_000;
  const dailyParams = cursorId ? params.slice(0, -1) : params;
  const daily = db.prepare(`SELECT substr(observed_at, 1, 10) AS day,
    SUM(CASE WHEN action='observed' THEN 1 ELSE 0 END) AS observed,
    SUM(CASE WHEN action='limit_armed' THEN 1 ELSE 0 END) AS controlled
    FROM exchange_activity_records WHERE ${filteredWhere} GROUP BY day ORDER BY day ASC`)
    .all(...dailyParams) as Array<{ day: string; observed: number; controlled: number }>;
  return { records, nextCursor, days, oldestAvailableAt: coverage.oldestAt, historyTruncated, daily };
}
