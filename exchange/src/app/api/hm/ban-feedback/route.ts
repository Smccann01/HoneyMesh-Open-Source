import { json, requireNodeAuth } from "@/app/api/_lib";
import { appendAuditLog, logFeedback } from "@/lib/portal-store";
import { z } from "zod";

const feedbackSchema = z.object({
  banId: z.string().min(3).max(128),
  useful: z.boolean(),
  notes: z.string().max(500).optional(),
});

export async function POST(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) {
    return auth.response;
  }
  const parsedPayload = feedbackSchema.safeParse(JSON.parse(auth.body || "{}"));
  if (!parsedPayload.success) {
    return json({ error: "invalid_payload", issues: parsedPayload.error.flatten() }, { status: 400 });
  }
  const payload = parsedPayload.data;
  const record = logFeedback({
    nodeId: auth.node.id,
    banId: payload.banId,
    useful: payload.useful,
    notes: payload.notes ?? "",
  });
  appendAuditLog({
    actorType: "node",
    actorId: auth.node.id,
    tenantId: auth.node.tenantId,
    action: "ban.feedback",
    reasonCode: null,
    details: `Node reported feedback for ban ${payload.banId}: useful=${payload.useful}`,
  });
  return json({ record }, { status: 201 });
}
