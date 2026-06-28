#!/usr/bin/env node
import {
  createVerdictV1,
  hashContent,
  verifyLedger,
  verifyReceipt
} from "./chunk-HVIW3FWV.mjs";

// src/cli.ts
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
function getVersion() {
  try {
    const dir = typeof __dirname !== "undefined" ? __dirname : dirname(fileURLToPath(import.meta.url));
    return JSON.parse(readFileSync(join(dir, "..", "package.json"), "utf8")).version;
  } catch {
    return "1.0.0";
  }
}
var [, , cmd, ...args] = process.argv;
async function main() {
  if (cmd === "--help" || cmd === "-h" || args[0] === "--help" || args[0] === "-h") {
    showHelp();
    return;
  }
  switch (cmd) {
    case "verify": {
      const path = args[0];
      if (!path) {
        die("Usage: varp verify <receipt.json>");
      }
      const raw = readFileSync(path, "utf8");
      const line = JSON.parse(raw);
      const result = await verifyReceipt(line);
      if (result.verified) {
        console.log(`\u2713 verified
  hash: ${result.event_hash}
  signer: ${result.signer_pubkey}`);
        process.exit(0);
      } else {
        console.error(`\u2717 INVALID \u2014 ${result.reason}`);
        process.exit(1);
      }
    }
    case "verify-ledger": {
      const path = args[0];
      if (!path) {
        die("Usage: varp verify-ledger <ledger.jsonl>");
      }
      const text = readFileSync(path, "utf8");
      const { results, chain_valid } = await verifyLedger(text);
      const passed = results.filter((r) => r.verified).length;
      const failed = results.filter((r) => !r.verified).length;
      results.filter((r) => !r.verified).forEach((r) => {
        console.error(`  line ${r.line}: \u2717 ${r.reason} ${r.event_hash ?? ""}`);
      });
      console.log(`
${chain_valid ? "\u2713" : "\u2717"} ${passed}/${results.length} verified \u2014 chain_valid: ${chain_valid}`);
      process.exit(chain_valid ? 0 : 1);
    }
    case "chain-report": {
      const path = args[0];
      if (!path) {
        die("Usage: varp chain-report <ledger.jsonl>");
      }
      const text = readFileSync(path, "utf8");
      const lines = text.split("\n").filter((l) => l.trim());
      let prevHash = null;
      let breaks = 0;
      const report = [];
      for (let i = 0; i < lines.length; i++) {
        let entry;
        try {
          entry = JSON.parse(lines[i]);
        } catch {
          report.push(`  line ${i + 1}: parse_error`);
          breaks++;
          continue;
        }
        const v = entry.verdict;
        if (!v) {
          report.push(`  line ${i + 1}: no_verdict`);
          continue;
        }
        const hash = v.event_hash;
        const prev = v.prev_hash;
        if (i === 0) {
          prevHash = hash ?? null;
          report.push(`  line ${i + 1}: chain_root ${hash?.slice(0, 12) ?? "?"}\u2026`);
          continue;
        }
        if (prev && prevHash && prev !== prevHash) {
          report.push(`  line ${i + 1}: BREAK \u2014 prev_hash mismatch (expected ${prevHash.slice(0, 12)}\u2026, got ${prev.slice(0, 12)}\u2026)`);
          breaks++;
        }
        prevHash = hash ?? prevHash;
      }
      const ok = breaks === 0;
      report.slice(0, 20).forEach((r) => console.log(r));
      if (report.length > 20) console.log(`  \u2026 and ${report.length - 20} more`);
      console.log(`
${ok ? "\u2713" : "\u2717"} ${lines.length} entries, ${breaks} chain break(s)`);
      process.exit(ok ? 0 : 1);
    }
    case "sign": {
      const getFlag = (f) => {
        const i = args.indexOf(f);
        return i >= 0 ? args[i + 1] : void 0;
      };
      const agent = getFlag("--agent");
      const desc = getFlag("--desc");
      const key = getFlag("--key") ?? process.env.VARP_PRIVATE_KEY;
      const sv = parseFloat(getFlag("--sv") ?? "0.1");
      const prevHash = getFlag("--prev-hash");
      if (!agent) {
        die("Usage: varp sign --agent <name> --desc <text> --key <hex64> [--sv 0.1] [--prev-hash <hex>]");
      }
      if (!desc) {
        die("Usage: varp sign --agent <name> --desc <text> --key <hex64> [--sv 0.1] [--prev-hash <hex>]");
      }
      if (!key) {
        die("Provide --key <hex64> or set VARP_PRIVATE_KEY env var");
      }
      const receipt = await createVerdictV1({ agent, description: desc, privateKeyHex: key, delta_sv: sv, prevHash });
      console.log(JSON.stringify(receipt, null, 2));
      break;
    }
    case "summarize": {
      const path = args[0];
      if (!path) {
        die("Usage: varp summarize <ledger.jsonl>");
      }
      const text = readFileSync(path, "utf8");
      const lines = text.split("\n").filter((l) => l.trim());
      const agentCounts = {};
      let firstTs = "";
      let lastTs = "";
      let parseErrors = 0;
      let noVerdict = 0;
      for (const line of lines) {
        let entry;
        try {
          entry = JSON.parse(line);
        } catch {
          parseErrors++;
          continue;
        }
        const v = entry.verdict;
        if (!v) {
          noVerdict++;
          continue;
        }
        let agent;
        let ts;
        if (v.agent) {
          agent = String(v.agent);
          ts = String(v.timestamp ?? "");
        } else if (v.event && typeof v.event === "object") {
          const desc = String(v.event.description ?? "");
          const match = desc.match(/^\[([^\]]+)\]/);
          agent = match ? match[1] : "unknown";
          ts = String(v.event.timestamp ?? "");
        } else {
          agent = "unknown";
          ts = "";
        }
        agentCounts[agent] = (agentCounts[agent] ?? 0) + 1;
        if (ts && (!firstTs || ts < firstTs)) firstTs = ts;
        if (ts && ts > lastTs) lastTs = ts;
      }
      const totalValid = Object.values(agentCounts).reduce((a, b) => a + b, 0);
      const topAgents = Object.entries(agentCounts).sort(([, a], [, b]) => b - a).slice(0, 10);
      console.log(`
=== Ledger Summary: ${path} ===`);
      console.log(`  Total lines:    ${lines.length}`);
      console.log(`  Valid receipts: ${totalValid}`);
      console.log(`  Unique agents:  ${Object.keys(agentCounts).length}`);
      if (parseErrors) console.log(`  Parse errors:   ${parseErrors}`);
      if (noVerdict) console.log(`  No-verdict:     ${noVerdict}`);
      console.log(`  Earliest:       ${firstTs || "\u2014"}`);
      console.log(`  Latest:         ${lastTs || "\u2014"}`);
      console.log(`
  Top agents by receipt count:`);
      for (const [agent, count] of topAgents) {
        const pct = Math.round(count / totalValid * 100);
        const bar = "\u2588".repeat(Math.round(pct / 5));
        console.log(`    ${agent.padEnd(28)} ${String(count).padStart(6)} ${bar} (${pct}%)`);
      }
      if (Object.keys(agentCounts).length > 10) {
        console.log(`    \u2026 and ${Object.keys(agentCounts).length - 10} more agent(s)`);
      }
      process.exit(0);
    }
    case "keygen": {
      const ed = await import("@noble/ed25519");
      if (!ed.etc.sha512Sync) {
        try {
          const { createHash } = await import("crypto");
          ed.etc.sha512Sync = (...msgs) => {
            const h = createHash("sha512");
            for (const m of msgs) h.update(m);
            return h.digest();
          };
        } catch {
        }
      }
      const { randomBytes } = await import("crypto");
      const privBytes = randomBytes(32);
      const pubBytes = ed.getPublicKey(privBytes);
      const privHex = privBytes.toString("hex");
      const pubHex = Buffer.from(pubBytes).toString("hex");
      console.log(`private_key: ${privHex}`);
      console.log(`public_key:  ${pubHex}`);
      console.log(`
Usage: varp sign --agent MyAgent --desc "task done" --key ${privHex}`);
      console.log(`Verify authorship: publish public_key at your domain and compare with signer_pubkey in receipts.`);
      break;
    }
    case "hash": {
      const text = args.join(" ");
      if (!text) {
        die("Usage: varp hash <text>");
      }
      const hex = await hashContent(text);
      console.log(hex);
      break;
    }
    case "version":
    case "-v":
    case "--version":
      console.log(getVersion());
      break;
    case "help":
    default:
      showHelp();
  }
}
function showHelp() {
  console.log(`
varp \u2014 Verifiable AI Receipt Protocol CLI

Commands:
  varp verify <receipt.json>        Verify a single VERDICT/v1 receipt
  varp verify-ledger <ledger.jsonl> Verify all receipts in a JSONL ledger
  varp chain-report <ledger.jsonl>  Check prev_hash chain linkage (chain integrity audit)
  varp summarize <ledger.jsonl>     Show receipt count, agents, date range, top agents
  varp sign --agent <name> --desc <text> --key <hex64>
                                    Create and sign a new VERDICT/v1 receipt
  varp keygen                       Generate a fresh Ed25519 keypair
  varp hash <text>                  BLAKE3(text) \u2192 hex
  varp version                      Print version and exit
  varp help                         Show this message

Sign flags:
  --key <hex64>    Ed25519 private key seed (or set VARP_PRIVATE_KEY env)
  --sv <float>     Delta SV value (default: 0.1)
  --prev-hash <h>  Previous receipt hash for chain linking

Flags: --help / -h  Show this message

Verify authorship by comparing signer_pubkey against os1221.com/fate-pubkey.txt
Learn more: https://os1221.com/verdict
`.trim());
}
function die(msg) {
  console.error(msg);
  process.exit(1);
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
