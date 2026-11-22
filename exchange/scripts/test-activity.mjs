import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const directory = mkdtempSync(path.join(tmpdir(), "exchange-private-activity-"));
const port = 32000 + Math.floor(Math.random() * 20000);
const base = `http://127.0.0.1:${port}`;
const server = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "-p", String(port)], {
  cwd: process.cwd(),
  env: { ...process.env, DATABASE_URL: `file:${path.join(directory, "exchange.db")}`, EXCHANGE_ACTIVITY_ENABLED: "true" },
  stdio: ["ignore", "pipe", "pipe"],
});
let output = "";
server.stdout.on("data", (chunk) => { output += chunk.toString(); });
server.stderr.on("data", (chunk) => { output += chunk.toString(); });

try {
  let ready = false;
  for (let attempt = 0; attempt < 80; attempt++) {
    if (server.exitCode !== null) throw new Error(`server exited: ${output}`);
    try { await fetch(base); ready = true; break; } catch { await new Promise((resolve) => setTimeout(resolve, 100)); }
  }
  assert.ok(ready, `server not ready: ${output}`);

  const home = await fetch(base);
  assert.equal(home.status, 200);
  const homeHtml = await home.text();
  assert.match(homeHtml, /Open your private console/);
  assert.match(homeHtml, /does not show live activity/);
  assert.doesNotMatch(homeHtml, /href="\/activity"/);

  const activity = await fetch(`${base}/activity`, { redirect: "manual" });
  assert.equal(activity.status, 307);
  assert.equal(new URL(activity.headers.get("location"), base).pathname, "/console");

  for (const resource of ["exchange-activity", "exchange-history?days=30"]) {
    const response = await fetch(`${base}/api/public/${resource}`);
    assert.equal(response.status, 404, `public ${resource} must not exist even with EXCHANGE_ACTIVITY_ENABLED=true`);
    assert.doesNotMatch(await response.text(), /sourceIp|attacker_ip|activeControls/);
  }

  const privateStatus = await fetch(`${base}/api/admin/status`);
  assert.equal(privateStatus.status, 401, "network status requires an admin session");
  const downloads = await fetch(`${base}/downloads`);
  assert.equal(downloads.status, 200);
  assert.doesNotMatch(await downloads.text(), /href="\/activity"/);
  console.log("Public Exchange activity is closed; the private console requires authentication.");
} finally {
  server.kill("SIGTERM");
  rmSync(directory, { recursive: true, force: true });
}
