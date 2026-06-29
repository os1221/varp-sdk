// @ts-check
// Regression: createVerdictV1 → verifyReceipt must round-trip, INCLUDING evidence_root.
// (A dropped evidence_root in the envelope made every content-bound receipt fail to verify
//  while the keystone sat at v1.0.0 with a publish-ready tarball. This locks it.)
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createVerdictV1, verifyReceipt } from "../dist/index.mjs";

const pk = () => randomBytes(32).toString("hex");

describe("createVerdictV1 ⇄ verifyReceipt round-trip", () => {
  it("a fresh receipt WITHOUT evidence_root verifies", async () => {
    const line = await createVerdictV1({ agent: "A", description: "no evidence", privateKeyHex: pk() });
    assert.equal((await verifyReceipt(line)).verified, true);
  });

  it("a fresh receipt WITH evidence_root verifies (the regression)", async () => {
    const line = await createVerdictV1({ agent: "A", description: "bound to evidence", evidence_root: "deadbeefcafe", privateKeyHex: pk() });
    assert.equal("evidence_root" in line.verdict, true, "evidence_root must survive into the envelope");
    assert.equal((await verifyReceipt(line)).verified, true);
  });

  it("tampering with the description is rejected (hash_mismatch)", async () => {
    const line = await createVerdictV1({ agent: "A", description: "the original verdict", evidence_root: "abc123", privateKeyHex: pk() });
    line.verdict.description = "a forged verdict";
    const r = await verifyReceipt(line);
    assert.equal(r.verified, false);
    assert.equal(r.reason, "hash_mismatch");
  });

  it("tampering with the evidence_root is rejected", async () => {
    const line = await createVerdictV1({ agent: "A", description: "verdict", evidence_root: "real-root", privateKeyHex: pk() });
    line.verdict.evidence_root = "swapped-root";
    assert.equal((await verifyReceipt(line)).verified, false);
  });

  it("the same content from different surfaces both verify under one standard", async () => {
    const k = pk();
    const court = await createVerdictV1({ agent: "TheCourt", description: "grant", evidence_root: "h1", privateKeyHex: k });
    const fate = await createVerdictV1({ agent: "FATE", description: "ARG 17.5%", evidence_root: "h2", privateKeyHex: k });
    assert.equal((await verifyReceipt(court)).verified, true);
    assert.equal((await verifyReceipt(fate)).verified, true);
  });
});
