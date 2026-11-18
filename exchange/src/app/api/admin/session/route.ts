import { clearSessionCookie, getAdmin, loginAdmin, logoutAdmin, sameOrigin, sessionCookie } from "@/lib/network-admin";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const headers = { "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" };

export async function GET(request: Request) {
  const admin = getAdmin(request);
  return Response.json({ admin }, { status: admin ? 200 : 401, headers });
}

export async function POST(request: Request) {
  if (!sameOrigin(request)) return Response.json({ error: "origin_required" }, { status: 403, headers });
  let payload: unknown;
  try { payload = await request.json(); } catch { return Response.json({ error: "invalid_request" }, { status: 400, headers }); }
  if (!payload || typeof payload !== "object") return Response.json({ error: "invalid_request" }, { status: 400, headers });
  const input = payload as Record<string, unknown>;
  if (typeof input.email !== "string" || typeof input.password !== "string" || typeof input.code !== "string") {
    return Response.json({ error: "invalid_request" }, { status: 400, headers });
  }
  const result = loginAdmin(input.email, input.password, input.code);
  if (!result) return Response.json({ error: "invalid_credentials" }, { status: 401, headers });
  return Response.json({ admin: result.admin }, { headers: { ...headers, "set-cookie": sessionCookie(result.token) } });
}

export async function DELETE(request: Request) {
  if (!sameOrigin(request)) return Response.json({ error: "origin_required" }, { status: 403, headers });
  logoutAdmin(request);
  return Response.json({ ok: true }, { headers: { ...headers, "set-cookie": clearSessionCookie() } });
}
