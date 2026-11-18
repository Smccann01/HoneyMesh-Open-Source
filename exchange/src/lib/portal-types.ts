export type Role = "super_admin" | "tenant_admin" | "reviewer" | "analyst";
export type Plan = "community" | "pro";
export type LicenseStatus = "active" | "expired" | "invalid";
export type NodeStatus = "online" | "degraded" | "offline";
export type BanStatus = "pending" | "approved" | "rejected" | "expired" | "quarantined";
export type SyncType = "push" | "pull";
export type SourceType = "portal" | "honeymesh_node";
export type TrustPath = "auto_approve" | "pending_review" | "quarantine" | "reject";
export type LocalPolicyMode = "audit_only" | "suggested" | "auto_temp" | "auto_high_confidence";
export type ReviewAction = "approve" | "reject";
export type LicenseTier = "community" | "pro";
export type AuditReasonCode =
  | "auth.invalid_credentials"
  | "auth.mfa_required"
  | "auth.invalid_signature"
  | "auth.stale_request"
  | "auth.replay_detected"
  | "auth.node_inactive"
  | "auth.community_feed_not_allowed"
  | "schema.invalid_payload"
  | "license.invalid"
  | "license.expired"
  | "exchange.kill_switch"
  | "exchange.review_only"
  | "exchange.rate_limited"
  | "exchange.duplicate_signal"
  | "exchange.quarantined"
  | "exchange.approved"
  | "exchange.pending_review"
  | "exchange.rejected";

export type User = {
  id: string;
  email: string;
  name: string;
  role: Role;
  tenantId: string;
  passwordHash: string;
  mfaEnabled: boolean;
};

export type Tenant = {
  id: string;
  name: string;
  plan: Plan;
  sharingEnabled: boolean;
  exchangeKillSwitch: boolean;
  reviewOnlyMode: boolean;
  autoApproveEnabled: boolean;
  trustLevel: number;
  licenseStatus: LicenseStatus;
  localPolicyMode: LocalPolicyMode;
  licenseId: string | null;
};

export type NodeRecord = {
  id: string;
  tenantId: string;
  clusterId: string;
  nodeName: string;
  apiKeyHash: string;
  publicKey: string;
  status: NodeStatus;
  lastSeen: string;
  trustLevel: number;
  softwareVersion: string;
  machineFingerprint: string | null;
  revokedAt: string | null;
};

export type CommunityBan = {
  id: string;
  clusterId?: string;
  sourceType: SourceType;
  tenantId: string;
  nodeId: string | null;
  attackerIp: string;
  cidr: string | null;
  ja4: string;
  ja3Legacy: string;
  attackType: string;
  protocol: string;
  port: number;
  service: string;
  confidence: number;
  reason: string;
  firstSeen: string;
  lastSeen: string;
  ttl: number;
  status: BanStatus;
  evidenceHash: string;
  trustScoreAtSubmission: number;
  publisher: string;
  sourceChannel: "local" | "community";
  actionTaken: "observe" | "stage" | "temporary_ban" | "high_confidence_ban";
  mode: LocalPolicyMode;
};

export type BanVote = {
  id: string;
  banId: string;
  reviewerUserId: string;
  action: ReviewAction;
  notes: string;
  createdAt: string;
};

export type SyncLog = {
  id: string;
  nodeId: string;
  syncType: SyncType;
  success: boolean;
  recordsCount: number;
  createdAt: string;
};

export type AuditLog = {
  id: string;
  actorType: "user" | "node" | "system";
  actorId: string;
  tenantId: string;
  action: string;
  reasonCode: AuditReasonCode | null;
  details: string;
  createdAt: string;
};

export type BanFeedback = {
  id: string;
  nodeId: string;
  banId: string;
  useful: boolean;
  notes: string;
  createdAt: string;
};

export type SessionRecord = {
  id: string;
  userId: string;
  createdAt: string;
};

export type LicenseRecord = {
  id: string;
  tenantId: string;
  tier: LicenseTier;
  status: LicenseStatus;
  issuedAt: string;
  expiresAt: string;
  licenseFingerprint: string;
  rawMetadataJson: string;
  meshScopeExpiresAt?: string | null;
  lastValidatedAt: string;
};

export type EnrollmentToken = {
  id: string;
  tenantId: string;
  tokenHash: string;
  expiresAt: string;
  usedAt: string | null;
  createdByUserId: string;
  allowedIp: string | null;
  nodeNameHint: string | null;
};

export type NodeNonce = {
  id: string;
  nodeId: string;
  nonce: string;
  createdAt: string;
};

export type MfaChallenge = {
  id: string;
  userId: string;
  code: string;
  createdAt: string;
  expiresAt: string;
};

export type DashboardSummary = {
  communityBansReceived: number;
  bansPublishedByOrg: number;
  localNodeSignals24h: number;
  connectedMeshSignals24h: number;
  topJA4s: Array<{ value: string; count: number }>;
  topAttackerIps: Array<{ value: string; count: number }>;
  trustHealth: number;
  syncHealth: number;
  pendingReviews: number;
  totalBlocks24h: number;
  uniqueAttackers24h: number;
  topAttackType: string;
  topJA4: string;
  localBlocks24h: number;
  networkBlocks24h: number;
  quarantinedSignals: number;
  rejectedSignals24h: number;
};
