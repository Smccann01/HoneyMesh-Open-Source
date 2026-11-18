import { z } from "zod";

import { getAdmin, listTrustedSources, sameOrigin, setTrustedSource } from "@/lib/network-admin";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const headers = { "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" };
const schema = z.object({ clusterId: z.string().min(2).max(128), trusted: z.boolean() }).strict();

export async function GET(request: Request) {
  const admin = getAdmin(request);
  if (!admin) return Response.json({ error: "unauthorized" }, { status: 401, headers });
  return Response.json({ sources: listTrustedSources(admin.tenantId) }, { headers });
}

export async function PUT(request: Request) {
  const admin = getAdmin(request);
  if (!admin) return Response.json({ error: "unauthorized" }, { status: 401, headers });
  if (!sameOrigin(request)) return Response.json({ error: "origin_required" }, { status: 403, headers });
  let body: unknown;
  try { body = await request.json(); } catch { return Response.json({ error: "invalid_request" }, { status: 400, headers }); }
  const parsed = schema.safeParse(body);
  if (!parsed.success || !setTrustedSource(admin, parsed.data.clusterId, parsed.data.trusted)) return Response.json({ error: "invalid_source" }, { status: 400, headers });
  return Response.json({ sources: listTrustedSources(admin.tenantId) }, { headers });
}
