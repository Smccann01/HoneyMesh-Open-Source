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

const SOURCE_IP_DAYS = 30;
const PRIVATE_DAYS = 90;
const MAX_ROWS = 50_000;
let lastPruneAt = 0;

function pruneActivity() {
  if (Date.now() - lastPruneAt < 60 * 60_000) return;
  const db = getDB();
  db.prepare("DELETE FROM exchange_activity_records WHERE observed_at < ?")
    .run(new Date(Date.now() - PRIVATE_DAYS * 86_400_000).toISOString());
  db.prepare("UPDATE exchange_activity_records SET source_ip=NULL WHERE source_ip IS NOT NULL AND observed_at < ?")
    .run(new Date(Date.now() - SOURCE_IP_DAYS * 86_400_000).toISOString());
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
  // Public activity reads no longer trigger maintenance; expire old source IPs on writes.
  pruneActivity();
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
