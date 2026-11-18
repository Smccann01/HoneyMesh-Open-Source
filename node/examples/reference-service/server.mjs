import { readFileSync } from "node:fs";
import { createAgentBridge } from "@honeymesh/node-guard/bridge";
import { createReferenceService, verifiedSourceResolver } from "./app.mjs";

const signingKey = readFileSync(process.env.REFERENCE_SIGNING_KEY_FILE);
const bridge = process.env.HM_EDGE_SOCKET && process.env.HM_EDGE_SECRET_FILE
  ? createAgentBridge({ socketPath: process.env.HM_EDGE_SOCKET, secret: readFileSync(process.env.HM_EDGE_SECRET_FILE).toString().trim(), appId: process.env.HM_EDGE_APP_ID })
  : null;
const canaryIps = (process.env.REFERENCE_CANARY_IPS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
const trustedProxyPeers = (process.env.REFERENCE_TRUSTED_PROXY_PEERS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
const { server } = createReferenceService({
  signingKey, bridge, canaryIps,
  mode: process.env.REFERENCE_MODE === "enforce" ? "enforce" : "observe",
  verifiedSource: verifiedSourceResolver({ trustedProxyPeers }),
});
const port = Number(process.env.PORT ?? 3101);
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("invalid PORT");
const bindIp = process.env.REFERENCE_BIND_IP ?? "127.0.0.1";
server.listen(port, bindIp, () => console.log(`reference service listening on ${bindIp}:${port}`));
