import { z } from "zod";

const ipAddressPattern =
  /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$|^(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}$/;

export const nodeRegistrationSchema = z.object({
  id: z.string().min(8).optional(),
  nodeName: z.string().min(2).max(80),
  clusterId: z.string().min(2).max(120),
  enrollToken: z.string().min(12).max(256),
  publicKey: z.string().min(8).max(4096),
  softwareVersion: z.string().min(1).max(64).optional(),
  machineFingerprint: z.string().max(256).nullable().optional(),
  trustLevel: z.number().int().min(0).max(100).optional(),
  secret: z.string().min(16).max(256).optional(),
});

export const heartbeatSchema = z.object({
  status: z.enum(["online", "degraded", "offline"]).default("online"),
});

export const directoryProfileSchema = z.object({
  displayName: z.string().trim().min(2).max(80),
  discoverable: z.boolean(),
  allowInvites: z.boolean(),
  allowSignals: z.boolean(),
  capabilities: z.array(z.enum(["mesh-v2", "exchange-signals-v1"])).max(8),
}).strict();

export const directoryRequestSchema = z.object({
  toClusterId: z.string().min(2).max(120),
  scope: z.enum(["signals", "mesh"]),
}).strict();

export const directoryDecisionSchema = z.object({
  decision: z.enum(["approved", "rejected", "revoked"]),
}).strict();

export const machineBootstrapSchema = z.object({
  id: z.string().min(8).max(128).optional(),
  nodeName: z.string().min(2).max(80),
  clusterId: z.string().min(2).max(120),
  publicKey: z.string().min(8).max(4096),
  softwareVersion: z.string().min(1).max(64).optional(),
  machineFingerprint: z.string().max(256).nullable().optional(),
  trustLevel: z.number().int().min(0).max(100).optional(),
  licenseJson: z.union([z.string().min(10), z.record(z.string(), z.unknown())]),
  licensePayload: z.string().min(10).max(1024).optional(),
  licenseSignature: z.string().min(10).max(1024).optional(),
  licenseClaim: z
    .object({
      payload: z.string().min(10).max(1024),
      signature: z.string().min(10).max(1024),
      clusterId: z.string().min(2).max(120).optional(),
      expiresAt: z.string().min(1).max(128).optional(),
      maxNodes: z.number().int().min(0).max(100000).optional(),
      tier: z.string().min(1).max(64).optional(),
    })
    .optional(),
}).strict();

export const publishBanSchema = z.object({
  id: z.string().min(8).max(128).optional(),
  attackerIp: z.string().regex(ipAddressPattern, "Invalid IP address"),
  cidr: z.string().max(64).nullable().optional(),
  ja4: z.string().max(128).default(""),
  ja3Legacy: z.string().max(256).default(""),
  attackType: z.string().min(2).max(64),
  protocol: z.enum(["tcp", "udp"]).default("tcp"),
  port: z.number().int().min(0).max(65535),
  service: z.string().min(1).max(64).default("unknown"),
  confidence: z.number().min(0).max(100),
  reason: z.string().min(3).max(500).default("Node submission"),
  ttl: z.number().int().min(60).max(600).default(300),
  sourceChannel: z.enum(["local", "community"]).default("local"),
  actionTaken: z.enum(["observe", "stage", "temporary_ban", "high_confidence_ban"]).optional(),
  mode: z.enum(["audit_only", "suggested", "auto_temp", "auto_high_confidence"]).optional(),
  evidence: z
    .object({
      evidenceLevel: z.enum(["sanitized"]).default("sanitized"),
      payloadShared: z.literal(false).default(false),
      evidenceHash: z.string().max(128).optional(),
    })
    .partial()
    .optional(),
}).strict();

export const licenseUploadSchema = z.object({
  licenseJson: z.union([z.string().min(10), z.record(z.string(), z.unknown())]),
});

export const signupSchema = z
  .object({
    organizationName: z.string().min(2).max(120),
    email: z.string().email(),
    password: z.string().min(10).max(200),
    confirmPassword: z.string().min(10).max(200),
    name: z.string().min(2).max(120).optional(),
    mfaEnabled: z.boolean().optional(),
    licenseJson: z.union([z.string().min(10), z.record(z.string(), z.unknown())]),
  })
  .superRefine((value, ctx) => {
    if (value.password !== value.confirmPassword) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["confirmPassword"],
        message: "Passwords do not match",
      });
    }
  });

export const sharingSettingsSchema = z.object({
  sharingEnabled: z.boolean(),
});

export const exchangeControlsSchema = z.object({
  exchangeKillSwitch: z.boolean().optional(),
  reviewOnlyMode: z.boolean().optional(),
  autoApproveEnabled: z.boolean().optional(),
  localPolicyMode: z.enum(["audit_only", "suggested", "auto_temp", "auto_high_confidence"]).optional(),
});

export function parseFeedCursor(raw: string | null) {
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8")) as { lastSeen?: string; id?: string };
    if (!parsed.lastSeen || !parsed.id) {
      return null;
    }
    return JSON.stringify({ lastSeen: parsed.lastSeen, id: parsed.id });
  } catch {
    return null;
  }
}
