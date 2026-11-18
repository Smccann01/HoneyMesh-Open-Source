import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const directory = process.argv[2];
if (!directory || !path.isAbsolute(directory)) {
  throw new Error("Usage: node scripts/backup-daily.mjs /absolute/private/backup-directory");
}
const stamp = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
const destination = path.join(directory, `exchange-${stamp}-${process.pid}.db`);
const result = spawnSync(process.execPath, [fileURLToPath(new URL("./backup-exchange.mjs", import.meta.url)), destination], {
  stdio: "inherit",
  env: process.env,
});
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status || 1);
