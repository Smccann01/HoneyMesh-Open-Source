import { randomUUID, createHash } from "node:crypto";

import { json, requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { appendAuditLog, createManualBan, findRecentDuplicateBan } from "@/lib/portal-store";
import { trustPathForBan } from "@/lib/auth";
import { publishBanSchema } from "@/lib/exchange-validation";

export async function POST(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) {
    return auth.response;
  }
  const parsedPayload = publishBanSchema.safeParse(JSON.parse(auth.body || "{}"));
  if (!parsedPayload.success) {
    appendAuditLog({
      actorType: "node",
      actorId: auth.node.id,
      tenantId: auth.node.tenantId,
      action: "ban.publish.reject",
      reasonCode: "schema.invalid_payload",
      details: `Rejected published signal due to schema validation failure`,
    });
    return json({ error: "invalid_payload", issues: parsedPayload.error.flatten() }, { status: 400 });
  }
  const payload = parsedPayload.data;
  const evidenceHash = createHash("sha256").update(JSON.stringify(payload.evidence ?? payload)).digest("hex").slice(0, 20);
  const duplicate = findRecentDuplicateBan(auth.node.tenantId, evidenceHash, Math.min(payload.ttl, 3600));
  if (duplicate) {
    appendAuditLog({
      actorType: "node",
      actorId: auth.node.id,
      tenantId: auth.node.tenantId,
      action: "ban.publish.reject",
      reasonCode: "exchange.duplicate_signal",
      details: `Rejected duplicate signal for ${payload.attackerIp}; matched ${duplicate.id}`,
    });
    return signedNodeJson({ status: "duplicate", record: duplicate }, auth.secret, { status: 202 });
  }
  const decision = trustPathForBan(auth.node, {
    confidence: payload.confidence,
    ja4: payload.ja4,
    attackType: payload.attackType,
  });
  if (decision === "reject") {
    appendAuditLog({
      actorType: "node",
      actorId: auth.node.id,
      tenantId: auth.node.tenantId,
      action: "ban.publish.reject",
      reasonCode: "exchange.rejected",
      details: `Rejected published signal for ${payload.attackerIp}`,
    });
    return signedNodeJson({ status: "rejected" }, auth.secret, { status: 403 });
  }
  const record = createManualBan({
    id: payload.id ?? randomUUID(),
    sourceType: "honeymesh_node",
    tenantId: auth.node.tenantId,
    nodeId: auth.node.id,
    attackerIp: payload.attackerIp,
    cidr: payload.cidr ?? null,
    ja4: payload.ja4 ?? "",
    ja3Legacy: payload.ja3Legacy ?? "",
    attackType: payload.attackType,
    protocol: payload.protocol ?? "tcp",
    port: Number(payload.port ?? 0),
    service: payload.service ?? "unknown",
    confidence: payload.confidence,
    reason: payload.reason,
    ttl: payload.ttl,
    status: decision === "auto_approve" ? "approved" : decision === "quarantine" ? "quarantined" : "pending",
    evidenceHash,
    trustScoreAtSubmission: auth.node.trustLevel,
    publisher: auth.node.nodeName,
    sourceChannel: "local",
    actionTaken:
      payload.actionTaken === "observe" ||
      payload.actionTaken === "stage" ||
      payload.actionTaken === "temporary_ban" ||
      payload.actionTaken === "high_confidence_ban"
        ? payload.actionTaken
        : decision === "auto_approve"
          ? "high_confidence_ban"
          : "stage",
    mode:
      payload.mode === "audit_only" ||
      payload.mode === "suggested" ||
      payload.mode === "auto_temp" ||
      payload.mode === "auto_high_confidence"
        ? payload.mode
        : decision === "auto_approve"
          ? "auto_high_confidence"
          : "suggested",
  });
  appendAuditLog({
    actorType: "node",
    actorId: auth.node.id,
    tenantId: auth.node.tenantId,
    action: "ban.publish.accept",
    reasonCode:
      decision === "auto_approve"
        ? "exchange.approved"
        : decision === "quarantine"
          ? "exchange.quarantined"
          : "exchange.pending_review",
    details: `Accepted signal ${record.id} via ${decision}`,
  });
  return signedNodeJson({ status: record.status, moderation_path: decision, record }, auth.secret, { status: 201 });
}
