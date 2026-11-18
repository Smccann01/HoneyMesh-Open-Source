import { chmodSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";

const databaseUrl = process.env.DATABASE_URL?.trim();
const destination = process.argv[2];
if (!databaseUrl?.startsWith("file:") || !destination) {
  throw new Error("Usage: DATABASE_URL=file:/absolute/exchange.db npm run backup -- /secure/path/backup.db");
}
const source = path.resolve(process.cwd(), databaseUrl.slice(5));
const target = path.resolve(destination);
if (!existsSync(source) || source === target || target.includes(`${path.sep}public${path.sep}`)) {
  throw new Error("Source must exist; destination must differ and remain outside public files");
}
process.umask(0o077);
mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
const db = new Database(source, { readonly: true, fileMustExist: true });
try {
  await db.backup(target);
  chmodSync(target, 0o600);
  const restored = new Database(target, { readonly: true, fileMustExist: true });
  try {
    const result = restored.pragma("integrity_check", { simple: true });
    if (result !== "ok") throw new Error("Backup integrity check failed");
  } finally { restored.close(); }
  process.stdout.write(`Backup verified at ${target}\n`);
} finally { db.close(); }
