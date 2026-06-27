#!/usr/bin/env node
/**
 * varp CLI — verify and inspect VERDICT/v1 receipts
 *
 * Commands:
 *   varp verify <receipt.json>        Verify a single receipt file
 *   varp verify-ledger <ledger.jsonl> Verify all receipts in a JSONL ledger
 *   varp hash <text>                  BLAKE3-hash a string, output hex
 *   varp version                      Print version and exit
 *   varp help                         Show usage
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyReceipt, verifyLedger, hashContent, createVerdictV1 } from "./index.js";

function getVersion(): string {
  try {
    // Works whether run from dist/ (CJS __dirname) or via import.meta.url (ESM)
    const dir = typeof __dirname !== "undefined"
      ? __dirname
      : dirname(fileURLToPath(import.meta.url));
    return JSON.parse(readFileSync(join(dir, "..", "package.json"), "utf8")).version;
  } catch {
    return "1.0.0";
  }
}

const [, , cmd, ...args] = process.argv;

async function main() {
  // Global --help / -h flags redirect to help output
  if (cmd === "--help" || cmd === "-h" || args[0] === "--help" || args[0] === "-h") {
    showHelp();
    return;
  }

  switch (cmd) {
    case "verify": {
      const path = args[0];
      if (!path) { die("Usage: varp verify <receipt.json>"); }
      const raw = readFileSync(path, "utf8");
      const line = JSON.parse(raw);
      const result = await verifyReceipt(line);
      if (result.verified) {
        console.log(`✓ verified\n  hash: ${result.event_hash}\n  signer: ${result.signer_pubkey}`);
        process.exit(0);
      } else {
        console.error(`✗ INVALID — ${result.reason}`);
        process.exit(1);
      }
    }

    case "verify-ledger": {
      const path = args[0];
      if (!path) { die("Usage: varp verify-ledger <ledger.jsonl>"); }
      const text = readFileSync(path, "utf8");
      const { results, chain_valid } = await verifyLedger(text);
      const passed = results.filter((r) => r.verified).length;
      const failed = results.filter((r) => !r.verified).length;
      results.filter((r) => !r.verified).forEach((r) => {
        console.error(`  line ${r.line}: ✗ ${r.reason} ${r.event_hash ?? ""}`);
      });
      console.log(`\n${chain_valid ? "✓" : "✗"} ${passed}/${results.length} verified — chain_valid: ${chain_valid}`);
      process.exit(chain_valid ? 0 : 1);
    }

    case "chain-report": {
      const path = args[0];
      if (!path) { die("Usage: varp chain-report <ledger.jsonl>"); }
      const text = readFileSync(path, "utf8");
      const lines = text.split("\n").filter((l) => l.trim());
      let prevHash: string | null = null;
      let breaks = 0;
      const report: string[] = [];
      for (let i = 0; i < lines.length; i++) {
        let entry;
        try { entry = JSON.parse(lines[i]); } catch { report.push(`  line ${i + 1}: parse_error`); breaks++; continue; }
        const v = entry.verdict;
        if (!v) { report.push(`  line ${i + 1}: no_verdict`); continue; }
        const hash = v.event_hash as string | undefined;
        const prev = v.prev_hash as string | undefined;
        if (i === 0) {
          prevHash = hash ?? null;
          report.push(`  line ${i + 1}: chain_root ${hash?.slice(0, 12) ?? "?"}…`);
          continue;
        }
        if (prev && prevHash && prev !== prevHash) {
          report.push(`  line ${i + 1}: BREAK — prev_hash mismatch (expected ${prevHash.slice(0, 12)}…, got ${prev.slice(0, 12)}…)`);
          breaks++;
        }
        prevHash = hash ?? prevHash;
      }
      const ok = breaks === 0;
      report.slice(0, 20).forEach(r => console.log(r));
      if (report.length > 20) console.log(`  … and ${report.length - 20} more`);
      console.log(`\n${ok ? "✓" : "✗"} ${lines.length} entries, ${breaks} chain break(s)`);
      process.exit(ok ? 0 : 1);
    }

    case "sign": {
      const getFlag = (f: string) => {
        const i = args.indexOf(f);
        return i >= 0 ? args[i + 1] : undefined;
      };
      const agent = getFlag("--agent");
      const desc = getFlag("--desc");
      const key = getFlag("--key") ?? process.env.VARP_PRIVATE_KEY;
      const sv = parseFloat(getFlag("--sv") ?? "0.1");
      const prevHash = getFlag("--prev-hash");
      if (!agent) { die("Usage: varp sign --agent <name> --desc <text> --key <hex64> [--sv 0.1] [--prev-hash <hex>]"); }
      if (!desc) { die("Usage: varp sign --agent <name> --desc <text> --key <hex64> [--sv 0.1] [--prev-hash <hex>]"); }
      if (!key) { die("Provide --key <hex64> or set VARP_PRIVATE_KEY env var"); }
      const receipt = await createVerdictV1({ agent, description: desc, privateKeyHex: key, delta_sv: sv, prevHash });
      console.log(JSON.stringify(receipt, null, 2));
      break;
    }

    case "keygen": {
      const ed = await import("@noble/ed25519");
      if (!ed.etc.sha512Sync) {
        try {
          const { createHash } = await import("node:crypto");
          ed.etc.sha512Sync = (...msgs: Uint8Array[]) => {
            const h = createHash("sha512");
            for (const m of msgs) h.update(m);
            return h.digest();
          };
        } catch { /* browser */ }
      }
      const { randomBytes } = await import("node:crypto");
      const privBytes = randomBytes(32);
      const pubBytes = ed.getPublicKey(privBytes);
      const privHex = privBytes.toString("hex");
      const pubHex = Buffer.from(pubBytes).toString("hex");
      console.log(`private_key: ${privHex}`);
      console.log(`public_key:  ${pubHex}`);
      console.log(`\nUsage: varp sign --agent MyAgent --desc "task done" --key ${privHex}`);
      console.log(`Verify authorship: publish public_key at your domain and compare with signer_pubkey in receipts.`);
      break;
    }

    case "hash": {
      const text = args.join(" ");
      if (!text) { die("Usage: varp hash <text>"); }
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

function showHelp(): void {
  console.log(`
varp — Verifiable AI Receipt Protocol CLI

Commands:
  varp verify <receipt.json>        Verify a single VERDICT/v1 receipt
  varp verify-ledger <ledger.jsonl> Verify all receipts in a JSONL ledger
  varp chain-report <ledger.jsonl>  Check prev_hash chain linkage (chain integrity audit)
  varp sign --agent <name> --desc <text> --key <hex64>
                                    Create and sign a new VERDICT/v1 receipt
  varp keygen                       Generate a fresh Ed25519 keypair
  varp hash <text>                  BLAKE3(text) → hex
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

function die(msg: string): never {
  console.error(msg);
  process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
