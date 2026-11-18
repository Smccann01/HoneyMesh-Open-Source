import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { isIP } from "node:net";
import { createHoneyMeshGuard, isEligibleSource } from "@honeymesh/node-guard";

function normalizedAddress(raw) {
  if (typeof raw !== "string") return null;
  const address = raw.startsWith("::ffff:") ? raw.slice(7) : raw;
  return isIP(address) && isEligibleSource(address) ? address : null;
}

/** Use only with a proxy that overwrites X-Real-IP on every request. */
export function verifiedSourceResolver({ trustedProxyPeers = [] } = {}) {
  const peers = new Set(trustedProxyPeers);
  return (request) => {
    const peer = request.socket.remoteAddress;
    if (peers.has(peer)) {
      const header = request.headers["x-real-ip"];
      return typeof header === "string" && !header.includes(",") ? normalizedAddress(header) : null;
    }
    // A direct peer can never supply its own source through a forwarded header.
    return normalizedAddress(peer);
  };
}

function signatureValid(key, body, supplied) {
  if (typeof supplied !== "string" || !/^[a-f0-9]{64}$/.test(supplied)) return false;
  const expected = createHmac("sha256", key).update(body).digest();
  return timingSafeEqual(expected, Buffer.from(supplied, "hex"));
}

export function createReferenceService({ signingKey, verifiedSource = verifiedSourceResolver(), canaryIps = [], bridge = null, mode = "observe", threshold = 12, entitlement, unitId } = {}) {
  if (!Buffer.isBuffer(signingKey) || signingKey.length < 32) throw new TypeError("signingKey must be at least 32 bytes");
  const canary = new Set(canaryIps);
  for (const ip of canary) if (!isEligibleSource(ip)) throw new TypeError("canaryIps contains an ineligible address");
  const decisions = [];
  const guard = createHoneyMeshGuard({
    mode, entitlement, unitId, thresholds: { invalid_signature_burst: threshold },
    canActOnSource: (ip) => mode === "observe" || canary.has(ip),
    onDecision: async (decision) => {
      decisions.push(decision);
      if (decisions.length > 100) decisions.shift();
      if (bridge) {
        const evidenceHash = createHmac("sha256", signingKey)
          .update(`${decision.sourceIp}|${decision.reasonCode}|${decision.observedAt}`).digest("hex");
        try {
          await bridge.sendEvent({ sourceIp: decision.sourceIp, reasonCode: decision.reasonCode, evidenceHash, confidence: 90, ttlSeconds: 60 });
        } catch { /* Application remains available if the local agent is unavailable. */ }
      }
    },
  });
  const server = createServer(async (request, response) => {
    response.setHeader("Cache-Control", "no-store");
    if (request.method === "GET" && request.url === "/healthz") {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ status: "ok", mode }));
      return;
    }
    if (request.method !== "POST" || request.url !== "/v1/signed") {
      response.writeHead(404).end();
      return;
    }
    const sourceIp = verifiedSource(request);
    if (!sourceIp || !isEligibleSource(sourceIp)) {
      response.writeHead(400).end("unverified source");
      return;
    }
    if (guard.isBlocked(sourceIp)) {
      response.writeHead(429).end("temporarily limited");
      return;
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of request) {
      size += chunk.length;
      if (size > 4096) { response.writeHead(413).end(); return; }
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks);
    if (!signatureValid(signingKey, body, request.headers["x-app-signature"])) {
      guard.record({ sourceIp, reasonCode: "invalid_signature_burst", protocol: "HTTP" });
      response.writeHead(401).end("invalid signature");
      return;
    }
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ accepted: true }));
  });
  return { server, guard, decisions };
}
