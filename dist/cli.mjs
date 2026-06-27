#!/usr/bin/env node
import {
  hashContent,
  verifyLedger,
  verifyReceipt
} from "./chunk-6IIA23GK.mjs";

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
      console.log(`
varp \u2014 Verifiable AI Receipt Protocol CLI

Commands:
  varp verify <receipt.json>        Verify a single VERDICT/v1 receipt
  varp verify-ledger <ledger.jsonl> Verify all receipts in a JSONL ledger
  varp hash <text>                  BLAKE3(text) \u2192 hex
  varp version                      Print version and exit
  varp help                         Show this message

Verify authorship by comparing signer_pubkey against os1221.com/fate-pubkey.txt
Learn more: https://os1221.com/verdict
`.trim());
  }
}
function die(msg) {
  console.error(msg);
  process.exit(1);
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
