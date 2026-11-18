import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import ts from "typescript";

const require = createRequire(import.meta.url);
const source = readFileSync(path.resolve("src/lib/auth.ts"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const record = { exports: {} };
const localRequire = (name) => name === "@/lib/portal-store" ? {} : require(name);
new Function("require", "module", "exports", compiled)(localRequire, record, record.exports);
const { hashNodeBody, signNodeRequest, signNodeResponse } = record.exports;

test("machine API v1 signatures match the receiving Go agent vector", () => {
  const secret = "hm-protocol-v1-test-secret-not-production";
  const stamp = "2026-11-05T08:00:00.000Z";
  const body = '{"attackerIp":"203.0.113.7","ttl":120}';
  const hash = "4965071b54371dbea99d28cf19853f2d6eafefbf4492c8b4ec1b91ed866467b7";
  assert.equal(hashNodeBody(body), hash);
  assert.equal(signNodeRequest(secret, "POST", "/api/hm/publish-ban?sample=1", stamp, "fixture-nonce-001", body),
    "c6a80cc213d54ac15618634c9ca4a2c798cbb71ad1f526297a0c331c79f5eaed");
  assert.equal(signNodeResponse(secret, 200, stamp, hash),
    "eeee4b1733fa1cf824fbf046675c4b269ef500428e9288483801ad587d8f7952");
});
