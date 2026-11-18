import { z } from "zod";

import { getAdmin, getReceivePolicy, sameOrigin, updateReceivePolicy } from "@/lib/network-admin";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const headers = { "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" };
const schema = z.object({ receiveEnabled: z.boolean(), exchangeOriginEnabled: z.boolean(), mode: z.enum(["observe", "review", "temporary"]), minConfidence: z.number().int().min(80).max(100), maxTTL: z.number().int().min(60).max(300) }).strict();

export async function GET(request: Request) {
  const admin = getAdmin(request);
  if (!admin) return Response.json({ error: "unauthorized" }, { status: 401, headers });
  return Response.json({ policy: getReceivePolicy(admin.tenantId) }, { headers });
}

export async function PUT(request: Request) {
  const admin = getAdmin(request);
  if (!admin) return Response.json({ error: "unauthorized" }, { status: 401, headers });
  if (!sameOrigin(request)) return Response.json({ error: "origin_required" }, { status: 403, headers });
  let body: unknown;
  try { body = await request.json(); } catch { return Response.json({ error: "invalid_request" }, { status: 400, headers }); }
  const parsed = schema.safeParse(body);
  if (!parsed.success) return Response.json({ error: "invalid_policy" }, { status: 400, headers });
  return Response.json({ policy: updateReceivePolicy(admin, parsed.data) }, { headers });
}
