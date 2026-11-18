import { createHmac, randomBytes } from "node:crypto";
import http from "node:http";
import path from "node:path";
import { isEligibleSource, REASON_CODES } from "./index.mjs";

const HEX_HASH = /^[a-f0-9]{32,64}$/;
const IDENTIFIER = /^[A-Za-z0-9_-]{8,128}$/;

function validatedEvent(input, appId) {
  if (!input || typeof input !== "object") throw new TypeError("event is required");
  const { sourceIp, reasonCode, evidenceHash, confidence, ttlSeconds } = input;
  const eventId = input.eventId ?? randomBytes(16).toString("hex");
  if (!isEligibleSource(sourceIp)) throw new TypeError("sourceIp must be a verified eligible public IP");
  if (!REASON_CODES.includes(reasonCode)) throw new TypeError("unknown reasonCode");
  if (typeof evidenceHash !== "string" || !HEX_HASH.test(evidenceHash)) throw new TypeError("evidenceHash must be a lowercase hex digest");
  if (!Number.isSafeInteger(confidence) || confidence < 80 || confidence > 100) throw new RangeError("confidence must be 80-100");
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 300) throw new RangeError("ttlSeconds must be 60-300");
  if (typeof eventId !== "string" || !IDENTIFIER.test(eventId)) throw new TypeError("invalid eventId");
  return { event_id: eventId, ...(appId ? { app_id: appId } : {}), source: "node_guard", ip: sourceIp, reason_code: reasonCode, evidence_hash: evidenceHash, confidence, ttl_seconds: ttlSeconds };
}

/** Authenticated, bounded client for the HoneyMesh local edge-ingest socket. */
export function createAgentBridge({ socketPath, secret, appId, timeoutMs = 2_000 } = {}) {
  if (typeof socketPath !== "string" || !path.isAbsolute(socketPath)) throw new TypeError("socketPath must be absolute");
  const key = Buffer.isBuffer(secret) ? secret : typeof secret === "string" ? Buffer.from(secret) : null;
  if (!key || key.length < 32) throw new TypeError("a separate 32-byte or longer secret is required");
  if (appId !== undefined && (typeof appId !== "string" || !IDENTIFIER.test(appId))) throw new TypeError("appId must be an 8-128 character identifier");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) throw new RangeError("timeoutMs must be 100-10000");

  function request(method, route, body = "") {
    const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const nonce = randomBytes(16).toString("hex");
    const signature = createHmac("sha256", key).update(`${timestamp}\n${nonce}\n${body}`).digest("hex");
    return new Promise((resolve, reject) => {
      const req = http.request({
        socketPath, path: route, method, timeout: timeoutMs,
        headers: {
          "x-edge-timestamp": timestamp, "x-edge-nonce": nonce, "x-edge-signature": signature,
          ...(method === "POST" ? { "content-type": "application/json", "content-length": Buffer.byteLength(body) } : {}),
        },
      }, (response) => {
        const chunks = [];
        let size = 0;
        response.on("data", (chunk) => {
          size += chunk.length;
          if (size > 32_768) { req.destroy(new Error("agent response exceeds 32 KiB")); return; }
          chunks.push(chunk);
        });
        response.on("end", () => {
          if (response.statusCode !== 200) { reject(new Error(`agent returned HTTP ${response.statusCode}`)); return; }
          try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
          catch { reject(new Error("invalid agent response")); }
        });
        response.on("error", reject);
      });
      req.on("timeout", () => req.destroy(new Error("agent request timed out")));
      req.on("error", reject);
      req.end(body);
    });
  }

  async function sendEvent(input) {
    const event = validatedEvent(input, appId);
    const data = await request("POST", "/v1/event", JSON.stringify(event));
    if (data?.status !== "observed" && data?.status !== "blocked") throw new Error("invalid agent event status");
    return { eventId: event.event_id, status: data.status };
  }

  async function activeBlocks() {
    const data = await request("GET", "/v1/active-blocks");
    if (!data || !Number.isSafeInteger(data.total) || data.total < 0 || !Array.isArray(data.blocks) || data.blocks.length > 100 || data.blocks.length > data.total) {
      throw new Error("invalid agent snapshot");
    }
    const blocks = data.blocks.map((block) => {
      if (!block || !isEligibleSource(block.ip) || !REASON_CODES.includes(block.reason_code) || typeof block.expires_at !== "string" || !Number.isFinite(Date.parse(block.expires_at))) {
        throw new Error("invalid agent block");
      }
      return { sourceIp: block.ip, reasonCode: block.reason_code, expiresAt: block.expires_at };
    });
    const mode = data.mode ?? "unknown";
    if (!["TEST", "ENFORCE", "LOCKDOWN", "unknown"].includes(mode)) throw new Error("invalid agent mode");
    return { total: data.total, blocks, mode };
  }

  return Object.freeze({ sendEvent, activeBlocks });
}
