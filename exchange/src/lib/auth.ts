import { createHash, createHmac, createPublicKey, timingSafeEqual, verify } from "node:crypto";

import type { CommunityBan, LicenseRecord, LicenseTier, NodeRecord, TrustPath } from "@/lib/portal-types";
import { findNodeByID, hasNodeNonce, saveNodeNonce, findTenantByID, findLicenseByTenantID, findNodeSecret, upsertLicense } from "@/lib/portal-store";

const NODE_WINDOW_MS = 1000 * 60 * 5;
const licensePublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAg2RJCQObk6HJsoEC5fdvxFWWtOlNNv23gmi42WZS5tM=
-----END PUBLIC KEY-----`;
const keygenPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAuHkja1vrS7YZbxaaClM5sVO4xnrNlv9A4r3KrwJkT38=
-----END PUBLIC KEY-----`;
const trustedLicensePublicKeys = [licensePublicKeyPEM, keygenPublicKeyPEM];

export function hashNodeBody(body: string) {
  return createHash("sha256").update(body).digest("hex");
}

export function signNodeMessage(secret: string, parts: string[]) {
  return createHmac("sha256", secret).update(parts.join("\n")).digest("hex");
}

export function hashNodeSecret(secret: string) {
  return createHash("sha256").update(secret).digest("hex");
}

export function signNodeRequest(secret: string, method: string, path: string, timestamp: string, nonce: string, body: string) {
  return signNodeMessage(secret, [method, path, timestamp, nonce, body]);
}

export function signNodeResponse(secret: string, status: number, timestamp: string, bodyHash: string) {
  return signNodeMessage(secret, ["response", String(status), timestamp, bodyHash]);
}

export function verifyNodeRequest(node: NodeRecord, method: string, path: string, timestamp: string, nonce: string, body: string, signature: string, bodyHash?: string, allowOffline = false) {
  const parsed = Date.parse(timestamp);
  if (!Number.isFinite(parsed) || Math.abs(Date.now() - parsed) > NODE_WINDOW_MS) {
    return { ok: false as const, reason: "stale_request" };
  }
  if (!nonce) {
    return { ok: false as const, reason: "missing_nonce" };
  }
  if (hasNodeNonce(node.id, nonce)) {
    return { ok: false as const, reason: "replay_detected" };
  }
  const material = findNodeSecret(node.id);
  if (!material) {
    return { ok: false as const, reason: "unknown_node_secret" };
  }
  if (bodyHash && bodyHash !== hashNodeBody(body)) {
    return { ok: false as const, reason: "invalid_body_hash" };
  }
  const expected = signNodeRequest(material, method, path, timestamp, nonce, body);
  const incoming = Buffer.from(signature, "hex");
  const target = Buffer.from(expected, "hex");
  if (incoming.length !== target.length || !timingSafeEqual(incoming, target)) {
    return { ok: false as const, reason: "invalid_signature" };
  }
  if (node.revokedAt || (node.status === "offline" && !allowOffline)) {
    return { ok: false as const, reason: "node_inactive" };
  }
  saveNodeNonce(node.id, nonce);
  return { ok: true as const };
}

export function trustPathForBan(node: NodeRecord, ban: Pick<CommunityBan, "confidence" | "ja4" | "attackType">): TrustPath {
  const tenant = findTenantByID(node.tenantId);
  if (!tenant || tenant.exchangeKillSwitch) {
    return "reject";
  }
  if (tenant.reviewOnlyMode) {
    return ban.confidence >= 60 ? "pending_review" : "quarantine";
  }
  if (!tenant.autoApproveEnabled) {
    return ban.confidence >= 60 ? "pending_review" : "reject";
  }
  if (node.trustLevel >= 90 && ban.confidence >= 92 && ban.ja4) {
    return "auto_approve";
  }
  if (node.trustLevel < 35 || ban.confidence < 40) {
    return "quarantine";
  }
  if (node.trustLevel >= 45 && ban.confidence >= 60) {
    return "pending_review";
  }
  return "reject";
}

export function tenantCanUseCommunityFeed(tenantId: string) {
  const tenant = findTenantByID(tenantId);
  if (tenant?.plan === "community" && tenant.licenseStatus === "active" && tenant.sharingEnabled &&
      !tenant.exchangeKillSwitch && tenant.reviewOnlyMode && !tenant.autoApproveEnabled) return true;
  const license = findLicenseByTenantID(tenantId);
  return (
    !!tenant &&
    !!license &&
    tenant.plan === "pro" &&
    tenant.sharingEnabled &&
    !tenant.exchangeKillSwitch &&
    tenant.licenseStatus === "active" &&
    license.status === "active" &&
    license.tier === "pro" &&
    Number.isFinite(Date.parse(license.expiresAt)) &&
    Date.parse(license.expiresAt) > Date.now() &&
    meshScopeActive(license)
  );
}

function meshScopeActive(license: LicenseRecord) {
  const scopeExpiry = Date.parse(license.meshScopeExpiresAt ?? "");
  const licenseExpiry = Date.parse(license.expiresAt);
  return Number.isFinite(scopeExpiry) && scopeExpiry > Date.now() &&
    Number.isFinite(licenseExpiry) && scopeExpiry <= licenseExpiry;
}

export function getTenantExchangeAccessState(tenantId: string) {
  const tenant = findTenantByID(tenantId);
  const license = findLicenseByTenantID(tenantId);
  if (!tenant || !license) {
    return { allowed: false as const, reason: "missing_license" };
  }
  const expiresAt = Date.parse(license.expiresAt);
  if (Number.isFinite(expiresAt) && expiresAt <= Date.now() && license.status !== "expired") {
    upsertLicense({ ...license, status: "expired", lastValidatedAt: new Date().toISOString() });
  }
  const refreshedTenant = findTenantByID(tenantId) ?? tenant;
  const refreshedLicense = findLicenseByTenantID(tenantId) ?? license;
  if (refreshedLicense.tier !== "pro" || refreshedTenant.plan !== "pro") {
    return { allowed: false as const, reason: "invalid_license_tier" };
  }
  if (refreshedLicense.status !== "active" || refreshedTenant.licenseStatus !== "active") {
    return {
      allowed: false as const,
      reason: refreshedLicense.status === "expired" || refreshedTenant.licenseStatus === "expired" ? "license_expired" : "license_inactive",
      expiresAt: refreshedLicense.expiresAt,
    };
  }
  if (!meshScopeActive(refreshedLicense)) {
    return { allowed: false as const, reason: "mesh_scope_missing_or_expired" };
  }
  return { allowed: true as const, tenant: refreshedTenant, license: refreshedLicense };
}

export function findNodeWithSecret(nodeId: string) {
  const node = findNodeByID(nodeId);
  if (!node) {
    return null;
  }
  return {
    node,
    secret: findNodeSecret(node.id),
  };
}

type LicenseUploadPayload = {
  cluster_id: string;
  expires_at: string;
  max_nodes: number;
  tier: string;
  signature: string;
  issued_at?: string;
  exchange_entitlement?: {
    scope: string;
    cluster_id: string;
    expires_at: string;
    signature: string;
  };
};

type VerifiedLicenseClaimInput = {
  raw: string;
  tenantId: string;
  clusterId: string;
  licensePayload: string;
  licenseSignature: string;
  licenseClaim?: {
    payload: string;
    signature: string;
    clusterId?: string;
    expiresAt?: string;
    maxNodes?: number;
    tier?: string;
  };
};

function parseLicenseUploadPayload(raw: string) {
  const payload = JSON.parse(raw) as LicenseUploadPayload;
  if (!payload.signature || !payload.expires_at || !payload.tier) {
    throw new Error("invalid_license_payload");
  }
  const expiresAt = new Date(payload.expires_at);
  if (!Number.isFinite(expiresAt.getTime())) {
    throw new Error("invalid_expiry");
  }
  return {
    payload,
    expiresAt,
    normalizedTier: normalizeLicenseTier(payload.tier),
  };
}

export function validateLicenseUpload(raw: string, tenantId: string): LicenseRecord {
  const { payload, expiresAt, normalizedTier } = parseLicenseUploadPayload(raw);
  const licenseBody = `${payload.cluster_id ?? ""}|${expiresAt.toISOString().replace(".000Z", "Z")}|${payload.max_nodes ?? 0}|${normalizedTier.toUpperCase()}`;
  const validSignature = trustedLicensePublicKeys.some((key) => verify(
    null,
    Buffer.from(licenseBody),
    createPublicKey(key),
    Buffer.from(payload.signature, "base64"),
  ));
  if (!validSignature) {
    throw new Error("invalid_signature");
  }
  const tenant = findTenantByID(tenantId);
  if (!tenant) {
    throw new Error("invalid_tenant");
  }
  return {
    id: `license-${tenantId}`,
    tenantId,
    tier: normalizedTier,
    status: expiresAt.getTime() > Date.now() ? "active" : "expired",
    issuedAt: payload.issued_at ?? new Date().toISOString(),
    expiresAt: expiresAt.toISOString(),
    licenseFingerprint: createHash("sha256").update(raw).digest("hex"),
    rawMetadataJson: raw,
    lastValidatedAt: new Date().toISOString(),
  };
}

export function validateVerifiedLicenseClaim({ raw, tenantId, clusterId, licensePayload, licenseSignature, licenseClaim }: VerifiedLicenseClaimInput, verificationKeys: string | string[] = trustedLicensePublicKeys): LicenseRecord & { maxNodes: number } {
  const { payload, expiresAt, normalizedTier } = parseLicenseUploadPayload(raw);
  if (!payload.cluster_id || payload.cluster_id !== clusterId || !Number.isSafeInteger(payload.max_nodes) || payload.max_nodes < 1) {
    throw new Error("license_identity_mismatch");
  }
  if (expiresAt.getTime() <= Date.now()) throw new Error("license_expired");
  const exactPayload = `${payload.cluster_id}|${payload.expires_at}|${payload.max_nodes}|${normalizedTier.toUpperCase()}`;
  if (licensePayload !== exactPayload || licenseSignature !== payload.signature) {
    throw new Error("invalid_license_claim");
  }
  if (licenseClaim) {
    if (licenseClaim.payload !== licensePayload || licenseClaim.signature !== licenseSignature) {
      throw new Error("invalid_license_claim");
    }
    if (licenseClaim.clusterId && licenseClaim.clusterId !== payload.cluster_id) {
      throw new Error("invalid_license_claim");
    }
    if (licenseClaim.expiresAt && licenseClaim.expiresAt !== payload.expires_at) {
      throw new Error("invalid_license_claim");
    }
    if (typeof licenseClaim.maxNodes === "number" && licenseClaim.maxNodes !== (payload.max_nodes ?? 0)) {
      throw new Error("invalid_license_claim");
    }
    if (licenseClaim.tier && normalizeLicenseTier(licenseClaim.tier) !== normalizedTier) {
      throw new Error("invalid_license_claim");
    }
  }

  const verifiedKey = (Array.isArray(verificationKeys) ? verificationKeys : [verificationKeys]).find((key) => verify(
    null, Buffer.from(exactPayload), createPublicKey(key), Buffer.from(licenseSignature, "base64"),
  ));
  if (!verifiedKey) {
    throw new Error("invalid_signature");
  }
  if (payload.signature !== licenseSignature) {
    throw new Error("invalid_license_claim");
  }
  const entitlement = payload.exchange_entitlement;
  if (!entitlement || entitlement.scope !== "exchange_mesh_trial" || entitlement.cluster_id !== clusterId ||
      !entitlement.signature || !Number.isFinite(Date.parse(entitlement.expires_at)) ||
      Date.parse(entitlement.expires_at) <= Date.now() || Date.parse(entitlement.expires_at) > expiresAt.getTime()) {
    throw new Error("exchange_entitlement_required");
  }
  const entitlementPayload = `honeymesh-exchange-entitlement-v1|${entitlement.scope}|${entitlement.cluster_id}|${entitlement.expires_at}`;
  if (!verify(null, Buffer.from(entitlementPayload), createPublicKey(verifiedKey), Buffer.from(entitlement.signature, "base64"))) {
    throw new Error("invalid_exchange_entitlement");
  }
  return {
    id: `license-${tenantId}`,
    tenantId,
    tier: normalizedTier,
    status: expiresAt.getTime() > Date.now() ? "active" : "expired",
    issuedAt: payload.issued_at ?? new Date().toISOString(),
    expiresAt: expiresAt.toISOString(),
    licenseFingerprint: createHash("sha256").update(raw).digest("hex"),
    rawMetadataJson: raw,
    meshScopeExpiresAt: entitlement.expires_at,
    lastValidatedAt: new Date().toISOString(),
    maxNodes: payload.max_nodes,
  };
}

export function normalizeLicenseTier(tier: string): LicenseTier {
  return String(tier).toLowerCase() === "pro" ? "pro" : "community";
}
