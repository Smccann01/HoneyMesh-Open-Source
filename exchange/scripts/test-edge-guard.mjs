import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const directory = mkdtempSync(path.join(tmpdir(), "exchange-guard-test-"));
const port = 32000 + Math.floor(Math.random() * 20000);
const base = `http://127.0.0.1:${port}`;
const server = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "-p", String(port)], {
  cwd: process.cwd(),
  env: { ...process.env, DATABASE_URL: `file:${path.join(directory, "exchange.db")}`,
    EXCHANGE_GUARD_MODE: "enforce", EXCHANGE_TRUST_PROXY: "true", NETTOOLS_TEST_INSECURE_LOOPBACK: "true" },
  stdio: ["ignore", "pipe", "pipe"],
});
let output = "";
server.stdout.on("data", (chunk) => { output += chunk.toString(); });
server.stderr.on("data", (chunk) => { output += chunk.toString(); });

async function request(headers = {}) {
  return fetch(`${base}/api/hm/config`, { headers, redirect: "manual" });
}

try {
  let ready = false;
  for (let i = 0; i < 80; i++) {
    if (server.exitCode !== null) throw new Error(`server exited: ${output}`);
    try { await fetch(base); ready = true; break; } catch { await new Promise((resolve) => setTimeout(resolve, 100)); }
  }
  assert.ok(ready, `server not ready: ${output}`);
  for (let i = 0; i < 42; i++) {
    const result = await request({ "x-real-ip": "8.8.8.8", "x-forwarded-proto": "https" });
    if (i < 40) assert.equal(result.status, 401);
  }
  assert.equal((await request({ "x-real-ip": "8.8.8.8", "x-forwarded-proto": "https" })).status, 429);
  assert.equal((await request({ "x-real-ip": "1.1.1.1", "x-forwarded-proto": "https" })).status, 401);
  for (let i = 0; i < 45; i++) {
    const result = await request({ "x-forwarded-for": "9.9.9.9", "x-forwarded-proto": "https" });
    assert.equal(result.status, 401, "untrusted first forwarded IP must not cause a block");
  }
  console.log("Exchange Guard integration passed: bounded block, unrelated IP, and spoofed X-Forwarded-For.");
} finally {
  server.kill("SIGTERM");
  rmSync(directory, { recursive: true, force: true });
}
