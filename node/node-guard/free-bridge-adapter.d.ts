export type FreeGuardBridgeResult = Readonly<{
  status: "disabled" | "observe_only" | "source_protected" | "ttl_too_short" | "duplicate" |
    "capacity_exhausted" | "observed" | "blocked" | "agent_unavailable";
  policyId?: string;
  sourceIp?: string;
  eventId?: string;
}>;

export declare function createFreeGuardHostAdapter(options: {
  enabled?: boolean;
  bridge?: { sendEvent(event: { sourceIp: string; reasonCode: string; evidenceHash: string;
    confidence: number; ttlSeconds: number; eventId: string }): Promise<{ status: "observed" | "blocked" }> };
  applicationId?: string;
  policyId?: string;
  canActOnSource?: (sourceIp: string) => boolean;
  confidence?: number;
  ttlSeconds?: number;
  maxForwardedEvents?: number;
  onResult?: (result: FreeGuardBridgeResult) => void | Promise<void>;
  now?: () => number;
}): Readonly<{ forward(decision: unknown): Promise<FreeGuardBridgeResult> }>;
