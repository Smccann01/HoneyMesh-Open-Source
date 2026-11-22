import { randomBytes } from "node:crypto";
import { mkdirSync, openSync, writeFileSync, closeSync } from "node:fs";
import path from "node:path";

const args = Object.fromEntries(process.argv.slice(2).map((arg) => {
  const at = arg.indexOf("=");
  if (!arg.startsWith("--") || at < 0) throw new Error("Use --name=value arguments");
  return [arg.slice(2, at), arg.slice(at + 1)];
}));

const origin = args.origin;
const output = args.output;
const dbPath = args.db;
if (!origin || !output || !dbPath) {
  throw new Error("Required: --origin=https://exchange.example.com --output=/secure/exchange.env --db=/secure/exchange.db");
}
const parsed = new URL(origin);
if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/" || !parsed.hostname.includes(".") || parsed.hostname === "honeymesh.io") {
  throw new Error("Origin must be your organization's HTTPS origin with no path, query, or credentials");
}
if (!path.isAbsolute(output) || !path.isAbsolute(dbPath) || output === dbPath) {
  throw new Error("Output and database paths must be distinct absolute paths");
}
if (/[\r\n\0]/.test(output) || /[\r\n\0]/.test(dbPath)) {
  throw new Error("Paths cannot contain control characters");
}
const secret = () => randomBytes(32).toString("hex");
const lines = [
  `DATABASE_URL=file:${dbPath}`,
  `EXCHANGE_PUBLIC_ORIGIN=${parsed.origin}`,
  "EXCHANGE_TRUST_PROXY=true",
  "EXCHANGE_GUARD_MODE=observe",
  "NETTOOLS_DISCOVERY_ENABLED=false",
  "NETWORK_ADMIN_POLICY_ENFORCED=true",
  "NETTOOLS_SEED_DEMO=false",
  `EXCHANGE_ACTIVITY_SALT=${secret()}`,
  "# Set EXCHANGE_EDGE_SOCKET and EXCHANGE_EDGE_SECRET only after agent bridge validation.",
  "# Expose this service only through a trusted HTTPS reverse proxy; bind Node to loopback.",
];
mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
const file = openSync(output, "wx", 0o600);
try { writeFileSync(file, `${lines.join("\n")}\n`, "utf8"); }
finally { closeSync(file); }
console.log(`Private Exchange pilot environment created at ${output}. Keep it private; no credentials were printed.`);
