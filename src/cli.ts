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
import { verifyReceipt, verifyLedger, hashContent } from "./index.js";

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
      console.log(`
varp — Verifiable AI Receipt Protocol CLI

Commands:
  varp verify <receipt.json>        Verify a single VERDICT/v1 receipt
  varp verify-ledger <ledger.jsonl> Verify all receipts in a JSONL ledger
  varp hash <text>                  BLAKE3(text) → hex
  varp version                      Print version and exit
  varp help                         Show this message

Verify authorship by comparing signer_pubkey against os1221.com/fate-pubkey.txt
Learn more: https://os1221.com/verdict
`.trim());
  }
}

function die(msg: string): never {
  console.error(msg);
  process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
