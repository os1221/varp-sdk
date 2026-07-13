#!/usr/bin/env node

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const manifest = require("../package.json");

const FIXED_TIMESTAMP = "2026-07-12T00:00:00.000Z";
const FIXED_PRIVATE_KEY = "01".repeat(32);
const HASH_VECTOR_INPUT = "receipts not vibes";
const HASH_VECTOR_EXPECTED =
  "f38f885d7d1bfb8f404c1e1974c07f959a47449e5abe09b18575fbd35e8a1e7d";
const JCS_VECTOR_INPUT = { z: [3, { b: false, a: "é" }], a: 1 };
const JCS_VECTOR_EXPECTED = '{"a":1,"z":[3,{"a":"é","b":false}]}';
const PROOF_PACKET = {
  schema: "verdict.proof-packet/v1",
  issued_at: "2026-07-12T00:00:00Z",
  producer: "varp-runtime-smoke",
  subject: "built-package",
  action: "verify",
  unit: {
    id: "varp.runtime.smoke",
    unit: "built public API",
    currency: "USD",
    amount_usd: "0.00",
    max_amount_usd: "0.00",
  },
  claim: {
    statement: "Team A win probability is 54 percent.",
    statement_sha256: "d17c887edf27afa9ecb3c5f3bbd5400b466b3e94810bd061b5a5d0b14fc87d11",
  },
  evidence: [{ type: "known-vector", content_sha256: "a".repeat(64) }],
  receipts: [{ protocol: "VERDICT/v1", content_hash: "b".repeat(64) }],
};

async function withFixedClock(callback) {
  const OriginalDate = global.Date;
  class FixedDate extends OriginalDate {
    constructor(...args) {
      super(...(args.length === 0 ? [FIXED_TIMESTAMP] : args));
    }

    static now() {
      return OriginalDate.parse(FIXED_TIMESTAMP);
    }
  }

  global.Date = FixedDate;
  try {
    return await callback();
  } finally {
    global.Date = OriginalDate;
  }
}

async function smokeApi(api, label) {
  assert.equal(api.jcsStringify(JCS_VECTOR_INPUT), JCS_VECTOR_EXPECTED, `${label} JCS vector`);
  assert.equal(
    await api.hashContent(HASH_VECTOR_INPUT),
    HASH_VECTOR_EXPECTED,
    `${label} BLAKE3 vector`,
  );

  const validation = await api.validateProofPacket(PROOF_PACKET);
  assert.deepEqual(validation, { valid: true, errors: [] }, `${label} proof-packet validation`);
  const proof = await api.verifyProofPacket(PROOF_PACKET);
  assert.equal(proof.kind, "proof_packet", `${label} proof-packet kind`);
  assert.equal(proof.valid, true, `${label} proof-packet verification`);
  assert.equal(proof.signature_valid, null, `${label} raw packet must not claim signature verification`);
}

function runCli(...args) {
  return spawnSync(process.execPath, [path.resolve(__dirname, "../dist/cli.js"), ...args], {
    encoding: "utf8",
  });
}

async function main() {
  const cjs = require("../dist/index.js");
  const esm = await import(pathToFileURL(path.resolve(__dirname, "../dist/index.mjs")));
  const requiredExports = [
    "createVerdictV1",
    "hashContent",
    "jcsStringify",
    "validateProofPacket",
    "verifyLedger",
    "verifyProofPacket",
    "verifyReceipt",
  ];

  for (const name of requiredExports) {
    assert.equal(typeof cjs[name], "function", `CJS export ${name} must be a function`);
    assert.equal(typeof esm[name], "function", `ESM export ${name} must be a function`);
  }

  await smokeApi(cjs, "CJS");
  await smokeApi(esm, "ESM");

  const receiptOptions = {
    agent: "RuntimeSmoke",
    description: "built package round trip",
    delta_sv: 0.1,
    privateKeyHex: FIXED_PRIVATE_KEY,
  };
  const cjsReceipt = await withFixedClock(() => cjs.createVerdictV1(receiptOptions));
  const esmReceipt = await withFixedClock(() => esm.createVerdictV1(receiptOptions));
  assert.deepEqual(esmReceipt, cjsReceipt, "CJS and ESM signing must be byte-for-byte deterministic");
  assert.equal(cjsReceipt.verdict.timestamp, FIXED_TIMESTAMP);
  assert.match(cjsReceipt.verdict.event_hash, /^[0-9a-f]{64}$/);
  assert.match(cjsReceipt.verdict.signature, /^[0-9a-f]{128}$/);
  assert.equal((await esm.verifyReceipt(cjsReceipt)).verified, true, "ESM must verify a CJS receipt");

  const linkedReceipt = await withFixedClock(() =>
    esm.createVerdictV1({
      ...receiptOptions,
      description: "built package linked receipt",
      prevHash: cjsReceipt.verdict.event_hash,
    }),
  );
  assert.equal((await cjs.verifyReceipt(linkedReceipt)).verified, true, "CJS must verify an ESM receipt");
  const ledgerText = `${JSON.stringify(cjsReceipt)}\n${JSON.stringify(linkedReceipt)}\n`;
  for (const [label, api] of [["CJS", cjs], ["ESM", esm]]) {
    const ledger = await api.verifyLedger(ledgerText);
    assert.equal(ledger.chain_valid, true, `${label} linked ledger must be valid`);
    assert.deepEqual(
      ledger.results.map((result) => result.verified),
      [true, true],
      `${label} must verify every ledger receipt`,
    );
  }

  const versionCli = runCli("--version");
  assert.equal(versionCli.status, 0, versionCli.stderr || "VARP CLI version command failed");
  assert.equal(versionCli.stdout.trim(), manifest.version);

  const hashCli = runCli("hash", HASH_VECTOR_INPUT);
  assert.equal(hashCli.status, 0, hashCli.stderr || "VARP CLI hash command failed");
  assert.equal(hashCli.stdout.trim(), HASH_VECTOR_EXPECTED);

  console.log(`runtime smoke passed for Node ${process.versions.node}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
