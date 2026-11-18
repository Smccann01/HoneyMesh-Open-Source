import { createHash, createHmac, randomBytes } from "node:crypto";
import http from "node:http";
import { isIP } from "node:net";

import { isPublicIndicator } from "@/lib/discovery-policy";
import { activitySourceId } from "@/lib/activity-source-id";
import { confirmGuardRejection, recordGuardActivity } from "@/lib/activity-store";

type GuardReason = "invalid_signature_burst" | "replay_burst" | "anonymous_rate_burst";
type GuardState = { hits: number[]; blockedUntil: number; publishedUntil: number; activityId: string | null; rejectionConfirmed: boolean; protocol: "HTTPS" | "Unknown" };

const state = new Map<string, GuardState>();
const WINDOW_MS = 60_000;
const BLOCK_MS = 120_000;
const MAX_KEYS = 20_000;
const GUARD_REASONS: GuardReason[] = ["invalid_signature_burst", "replay_burst", "anonymous_rate_burst"];

export function trustedClientIP(request: Request) {
  if (process.env.EXCHANGE_TRUST_PROXY !== "true") return null;
  const address = request.headers.get("x-real-ip")?.trim() ?? "";
  return isIP(address) && isPublicIndicator(address) ? address : null;
}

function getState(ip: string) {
  const now = Date.now();
  let entry = state.get(ip);
  if (!entry) {
    if (state.size >= MAX_KEYS) {
      for (const [key, value] of state) {
        if (value.blockedUntil < now && value.hits.every((hit) => hit < now - WINDOW_MS)) state.delete(key);
        if (state.size < MAX_KEYS) break;
      }
    }
    if (state.size >= MAX_KEYS) return null;
    entry = { hits: [], blockedUntil: 0, publishedUntil: 0, activityId: null, rejectionConfirmed: false, protocol: "Unknown" };
    state.set(ip, entry);
  }
  entry.hits = entry.hits.filter((hit) => hit >= now - WINDOW_MS);
  return entry;
}

export function edgeGuardBlocked(request: Request) {
  if (process.env.EXCHANGE_GUARD_MODE !== "enforce") return false;
  const ip = trustedClientIP(request);
  if (!ip) return false;
  for (const reason of GUARD_REASONS) {
    const entry = state.get(`${reason}:${ip}`);
    if (!entry || entry.blockedUntil <= Date.now()) continue;
    if (entry.activityId && !entry.rejectionConfirmed) {
      try { confirmGuardRejection(entry.activityId, ip); entry.rejectionConfirmed = true; } catch { /* Keep the live control effective. */ }
    }
    return true;
  }
  return false;
}

export function guardActivitySnapshot() {
  const now = Date.now();
  const blocks: Array<{ ip: string; reasonCode: GuardReason; expiresAt: string; protocol: "HTTPS" | "Unknown"; confirmed: boolean }> = [];
  let recentFailureCount = 0;
  for (const [key, entry] of state) {
    recentFailureCount += entry.hits.filter((hit) => hit >= now - WINDOW_MS).length;
    if (entry.blockedUntil <= now) continue;
    const reasonCode = GUARD_REASONS.find((reason) => key.startsWith(`${reason}:`));
    if (!reasonCode) continue;
    blocks.push({ ip: key.slice(reasonCode.length + 1), reasonCode, expiresAt: new Date(entry.blockedUntil).toISOString(), protocol: entry.protocol, confirmed: entry.rejectionConfirmed });
  }
  return { recentFailureCount, blocks };
}

export function recordEdgeGuardFailure(request: Request, reason: GuardReason) {
  if (process.env.EXCHANGE_GUARD_MODE !== "observe" && process.env.EXCHANGE_GUARD_MODE !== "enforce") return;
  const ip = trustedClientIP(request);
  if (!ip) return;
  const entry = getState(`${reason}:${ip}`);
  if (!entry) return;
  const now = Date.now();
  entry.hits.push(now);
  const threshold = reason === "anonymous_rate_burst" ? 40 : 12;
  if (entry.hits.length < threshold || entry.publishedUntil > now) return;
  entry.publishedUntil = now + WINDOW_MS;
  const sourceId = activitySourceId(ip, new Date(now));
  entry.protocol = request.headers.get("x-forwarded-proto") === "https" ? "HTTPS" : "Unknown";
  const isEnforcing = process.env.EXCHANGE_GUARD_MODE === "enforce";
  if (isEnforcing) entry.blockedUntil = now + BLOCK_MS;
  try {
    entry.activityId = recordGuardActivity({
      sourceId, reasonCode: reason,
      protocol: entry.protocol,
      observedAt: new Date(now).toISOString(),
      expiresAt: isEnforcing ? new Date(entry.blockedUntil).toISOString() : null,
      hitCount: entry.hits.length,
      action: isEnforcing ? "limit_armed" : "observed",
    });
    entry.rejectionConfirmed = false;
  } catch {
    entry.activityId = null;
  }
  const evidenceHash = createHash("sha256").update(`${reason}:${ip}:${Math.floor(now / WINDOW_MS)}`).digest("hex");
  void sendEdgeEvent({
    event_id: randomBytes(16).toString("hex"),
    source: "exchange_guard",
    ip,
    reason_code: reason,
    evidence_hash: evidenceHash,
    confidence: reason === "anonymous_rate_burst" ? 80 : 90,
    ttl_seconds: 120,
  });
}

export async function sendEdgeEvent(event: {
  event_id: string; source: "exchange_guard"; ip: string; reason_code: GuardReason;
  evidence_hash: string; confidence: number; ttl_seconds: number;
}) {
  const socketPath = process.env.EXCHANGE_EDGE_SOCKET;
  const secret = process.env.EXCHANGE_EDGE_SECRET;
  if (!socketPath || !secret || secret.length < 32) return false;
  const body = JSON.stringify(event);
  const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const nonce = randomBytes(16).toString("hex");
  const signature = createHmac("sha256", secret).update(`${timestamp}\n${nonce}\n${body}`).digest("hex");
  return new Promise<boolean>((resolve) => {
    const req = http.request({
      socketPath, path: "/v1/event", method: "POST", timeout: 2000,
      headers: {
        "content-type": "application/json", "content-length": Buffer.byteLength(body),
        "x-edge-timestamp": timestamp, "x-edge-nonce": nonce, "x-edge-signature": signature,
      },
    }, (response) => {
      response.resume();
      response.on("end", () => resolve(response.statusCode === 200));
    });
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(false));
    req.end(body);
  });
}

export async function fetchAgentEdgeBlocks(): Promise<null | { total: number; mode: "TEST" | "ENFORCE" | "LOCKDOWN" | "unknown"; blocks: Array<{ ip: string; reason_code: string; expires_at: string }> }> {
  const socketPath = process.env.EXCHANGE_EDGE_SOCKET;
  const secret = process.env.EXCHANGE_EDGE_SECRET;
  if (!socketPath || !secret || secret.length < 32) return null;
  const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const nonce = randomBytes(16).toString("hex");
  const signature = createHmac("sha256", secret).update(`${timestamp}\n${nonce}\n`).digest("hex");
  return new Promise((resolve) => {
    const req = http.request({
      socketPath, path: "/v1/active-blocks", method: "GET", timeout: 2000,
      headers: { "x-edge-timestamp": timestamp, "x-edge-nonce": nonce, "x-edge-signature": signature },
    }, (response) => {
      if (response.statusCode !== 200) { response.resume(); resolve(null); return; }
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > 32_768) { req.destroy(); return; }
        chunks.push(chunk);
      });
      response.on("end", () => {
        try {
          const data: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (!data || typeof data !== "object" || !("blocks" in data) || !("total" in data) || !Array.isArray(data.blocks) || typeof data.total !== "number") {
            resolve(null); return;
          }
          const mode = "mode" in data && (data.mode === "TEST" || data.mode === "ENFORCE" || data.mode === "LOCKDOWN") ? data.mode : "unknown";
          resolve({ total: data.total, mode, blocks: data.blocks as Array<{ ip: string; reason_code: string; expires_at: string }> });
        } catch { resolve(null); }
      });
    });
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(null));
    req.end();
  });
}
