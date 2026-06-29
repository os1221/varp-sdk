// examples/moat-demo.mjs — one verifiable standard, every surface.
// Any AI output — a Court verdict, a FATE forecast — signs and verifies under the SAME
// VERDICT/v1 receipt and the SAME verifyReceipt(). That single fact is the moat.
//   node examples/moat-demo.mjs
import { createVerdictV1, verifyReceipt, hashContent } from "../dist/index.mjs";
import { randomBytes } from "node:crypto";

const privateKeyHex = randomBytes(32).toString("hex"); // ephemeral; use ~/.omega key in prod

async function surface(agent, description, content) {
  const evidence_root = await hashContent(JSON.stringify(content));
  const line = await createVerdictV1({ agent, description, evidence_root, privateKeyHex });
  return { line, v: await verifyReceipt(line) };
}

console.log("\n🔗  VARP — one verifiable standard, every surface\n");

const court = await surface("TheCourt",
  "The council grants the petitioner's plea for clemency.",
  { verdict: "grant", gauges: { S: 5, D: -3 }, choice: "hear the grievance" });
console.log("  THE COURT   verdict  →", court.v.verified ? "✓ VERIFIED" : "✗ " + court.v.reason,
            " ·", court.line.verdict.event_hash.slice(0, 20) + "…");

const fate = await surface("FATE",
  "Projected champion: Argentina, 17.5%.",
  { champion: "ARG", p: 0.175, n: 9000, seed: 20260618 });
console.log("  FATE        forecast →", fate.v.verified ? "✓ VERIFIED" : "✗ " + fate.v.reason,
            " ·", fate.line.verdict.event_hash.slice(0, 20) + "…");

const forged = structuredClone(court.line);
forged.verdict.description = "The council secretly denied the plea.";
const tv = await verifyReceipt(forged);
console.log("\n  TAMPER      Court verdict rewritten →",
            tv.verified ? "✗ NOT CAUGHT (bug!)" : "✓ REJECTED (" + tv.reason + ")");

const ok = court.v.verified && fate.v.verified && !tv.verified;
console.log("\n  " + (ok
  ? "✓ Two surfaces, one signature standard, one verifyReceipt — the moat is coherent.\n"
  : "✗ Unexpected — investigate.\n"));
process.exit(ok ? 0 : 1);
