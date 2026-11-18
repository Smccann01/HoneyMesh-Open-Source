import { requireNodeAuth, signedNodeJson } from "@/app/api/_lib";
import { parseDiscoveryJson, verifyDiscoveryIdentity } from "@/lib/discovery-auth";
import { claimDirectoryAdmin, getOwnProfile, isDirectoryAdmin, logDirectoryEvent, updateOwnProfile } from "@/lib/discovery-store";
import { directoryProfileSchema } from "@/lib/exchange-validation";
import { appendAuditLog } from "@/lib/portal-store";

export async function GET(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) return auth.response;
  if (process.env.NETTOOLS_DISCOVERY_ENABLED !== "true") return signedNodeJson({ error: "discovery_disabled" }, auth.secret, { status: 404 });
  return signedNodeJson({ profile: getOwnProfile(auth.node.tenantId) }, auth.secret);
}

// Claiming is explicit and requires the node identity private key in addition to machine auth.
export async function POST(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) return auth.response;
  if (process.env.NETTOOLS_DISCOVERY_ENABLED !== "true") return signedNodeJson({ error: "discovery_disabled" }, auth.secret, { status: 404 });
  if (!verifyDiscoveryIdentity(request, auth.node)) return signedNodeJson({ error: "identity_required" }, auth.secret, { status: 403 });
  const profile = claimDirectoryAdmin(auth.node);
  if (!profile) return signedNodeJson({ error: "admin_already_claimed" }, auth.secret, { status: 409 });
  appendAuditLog({ actorType: "node", actorId: auth.node.id, tenantId: auth.node.tenantId,
    action: "discovery.admin.claim", reasonCode: null, details: `Admin identity claimed for ${auth.node.clusterId}` });
  logDirectoryEvent(auth.node, "admin.claim", auth.node.clusterId);
  return signedNodeJson({ profile }, auth.secret);
}

export async function PUT(request: Request) {
  const auth = await requireNodeAuth(request);
  if (!auth.ok) return auth.response;
  if (process.env.NETTOOLS_DISCOVERY_ENABLED !== "true") return signedNodeJson({ error: "discovery_disabled" }, auth.secret, { status: 404 });
  if (!isDirectoryAdmin(auth.node) || !verifyDiscoveryIdentity(request, auth.node)) {
    return signedNodeJson({ error: "admin_required" }, auth.secret, { status: 403 });
  }
  const parsed = directoryProfileSchema.safeParse(parseDiscoveryJson(auth.body));
  if (!parsed.success) return signedNodeJson({ error: "invalid_profile" }, auth.secret, { status: 400 });
  const profile = updateOwnProfile(auth.node, parsed.data);
  appendAuditLog({ actorType: "node", actorId: auth.node.id, tenantId: auth.node.tenantId,
    action: "discovery.profile.update", reasonCode: null, details: `Visibility: ${parsed.data.discoverable}` });
  logDirectoryEvent(auth.node, "profile.update", `visible=${parsed.data.discoverable}`);
  return signedNodeJson({ profile }, auth.secret);
}
