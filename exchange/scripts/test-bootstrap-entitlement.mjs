import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
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
const compiledModule = { exports: {} };
const localRequire = (id) => id === "@/lib/portal-store" ? {} : require(id);
new Function("require", "module", "exports", compiled)(localRequire, compiledModule, compiledModule.exports);
const { validateVerifiedLicenseClaim } = compiledModule.exports;
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const verificationKey = publicKey.export({ format: "pem", type: "spki" });
const rotated = generateKeyPairSync("ed25519");
const rotatedVerificationKey = rotated.publicKey.export({ format: "pem", type: "spki" });

function candidate(overrides = {}, { licenseSigner = privateKey, trialSigner = licenseSigner } = {}) {
  const clusterId = "cid_trial_01";
  const expiresAt = new Date(Date.now() + 86400_000).toISOString().replace(".000Z", "Z");
  const licensePayload = `${clusterId}|${expiresAt}|1|PRO`;
  const licenseSignature = sign(null, Buffer.from(licensePayload), licenseSigner).toString("base64");
  const entitlementPayload = `honeymesh-exchange-entitlement-v1|exchange_mesh_trial|${clusterId}|${expiresAt}`;
  const license = {
    cluster_id: clusterId, expires_at: expiresAt, max_nodes: 1, tier: "PRO", signature: licenseSignature,
    exchange_entitlement: {
      scope: "exchange_mesh_trial", cluster_id: clusterId, expires_at: expiresAt,
      signature: sign(null, Buffer.from(entitlementPayload), trialSigner).toString("base64"),
    },
  };
  return { raw: JSON.stringify({ ...license, ...overrides }), tenantId: "tenant-trial-01", clusterId, licensePayload, licenseSignature };
}

function validate(input) {
  return validateVerifiedLicenseClaim(input, verificationKey);
}

test("a separately signed trial scope permits only its own active cluster", () => {
  const accepted = validate(candidate());
  assert.equal(accepted.tier, "pro");
  assert.equal(accepted.maxNodes, 1);
  assert.equal(accepted.status, "active");
});

test("a paid Core-style Pro license without trial scope is rejected", () => {
  assert.throws(() => validate(candidate({ exchange_entitlement: undefined })), /exchange_entitlement_required/);
});

test("tampered license identity and expiry cannot borrow a valid signature", () => {
  assert.throws(() => validate(candidate({ cluster_id: "cid_other" })), /license_identity_mismatch/);
  assert.throws(() => validate(candidate({ tier: "COMMUNITY" })), /invalid_license_claim/);
  assert.throws(() => validate(candidate({ expires_at: "2099-01-01T00:00:00Z" })), /invalid_license_claim/);
});

test("trial scope must be signed and bounded by the license", () => {
  const input = candidate();
  const license = JSON.parse(input.raw);
  license.exchange_entitlement.signature = license.signature;
  assert.throws(() => validate({ ...input, raw: JSON.stringify(license) }), /invalid_exchange_entitlement/);
  license.exchange_entitlement.expires_at = "2099-01-01T00:00:00Z";
  assert.throws(() => validate({ ...input, raw: JSON.stringify(license) }), /exchange_entitlement_required/);
});

test("rotated publisher is accepted, but mixed publisher signatures are rejected", () => {
  const trusted = [verificationKey, rotatedVerificationKey];
  assert.equal(validateVerifiedLicenseClaim(candidate({}, { licenseSigner: rotated.privateKey }), trusted).status, "active");
  assert.throws(() => validateVerifiedLicenseClaim(candidate({}, {
    licenseSigner: rotated.privateKey, trialSigner: privateKey,
  }), trusted), /invalid_exchange_entitlement/);
});
