import type { ReasonCode } from "./index.d.ts";

export declare function createAgentBridge(options: {
  socketPath: string;
  secret: string | Buffer;
  appId?: string;
  timeoutMs?: number;
}): Readonly<{
  sendEvent(event: {
    sourceIp: string;
    reasonCode: ReasonCode;
    evidenceHash: string;
    confidence: number;
    ttlSeconds: number;
    eventId?: string;
  }): Promise<{ eventId: string; status: "observed" | "blocked" }>;
  activeBlocks(): Promise<{
    total: number;
    mode: "TEST" | "ENFORCE" | "LOCKDOWN" | "unknown";
    blocks: Array<{ sourceIp: string; reasonCode: ReasonCode; expiresAt: string }>;
  }>;
}>;
