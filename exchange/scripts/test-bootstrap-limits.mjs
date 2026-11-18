import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import test from "node:test";
import ts from "typescript";

const require = createRequire(import.meta.url);
const directory = mkdtempSync(path.join(tmpdir(), "hm-exchange-bootstrap-"));
process.env.DATABASE_URL = `file:${path.join(directory, "exchange.db")}`;
process.env.NETTOOLS_SEED_DEMO = "false";
const source = readFileSync(path.resolve("src/lib/portal-store.ts"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
}).outputText;
const moduleRecord = { exports: {} };
const localRequire = (name) => {
  if (name === "@/lib/discovery-policy") return { isPublicIndicator: () => true };
  if (name === "@/lib/exchange-validation") return { parseFeedCursor: () => null };
  return require(name);
};
new Function("require", "module", "exports", compiled)(localRequire, moduleRecord, moduleRecord.exports);
const { getDB, registerNode } = moduleRecord.exports;

function node(id, fingerprint) {
  return {
    id, tenantId: "tenant-test", clusterId: "cluster-test", nodeName: id,
    trustLevel: 75, publicKey: "test-public-key", softwareVersion: "test",
    machineFingerprint: fingerprint, revokedAt: null,
  };
}

test("bootstrap limit and identity are enforced inside registration transaction", () => {
  registerNode(node("node-one", "fingerprint-one"), "secret-one", 1);
  assert.throws(() => registerNode(node("node-two", "fingerprint-two"), "secret-two", 1),
    /node_limit_or_identity_conflict/);
  assert.throws(() => registerNode(node("node-one", "fingerprint-other"), "secret-three", 2),
    /node_limit_or_identity_conflict/);
  assert.throws(() => registerNode(node("node-three", "fingerprint-one"), "secret-four", 2),
    /node_limit_or_identity_conflict/);
  const db = getDB();
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM nodes").get().n, 1);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM node_credentials").get().n, 1);
  assert.equal(db.prepare("SELECT shared_secret FROM node_credentials WHERE node_id='node-one'").get().shared_secret,
    "secret-one", "a conflict must never rotate an existing node secret");
});

process.on("exit", () => {
  globalThis.__honeymeshPortalDB?.close();
  rmSync(directory, { recursive: true, force: true });
});
