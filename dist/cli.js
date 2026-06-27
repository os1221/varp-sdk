#!/usr/bin/env node
"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/cli.ts
var import_node_fs = require("fs");
var import_node_path = require("path");
var import_node_url = require("url");

// src/index.ts
function jcsStringify(val) {
  if (val === null) return "null";
  if (typeof val === "boolean") return val ? "true" : "false";
  if (typeof val === "number") {
    if (!isFinite(val)) throw new Error("JCS: non-finite number");
    return String(val);
  }
  if (typeof val === "string") return JSON.stringify(val);
  if (Array.isArray(val)) return "[" + val.map(jcsStringify).join(",") + "]";
  if (typeof val === "object") {
    const obj = val;
    const sorted = Object.keys(obj).sort();
    return "{" + sorted.map((k) => JSON.stringify(k) + ":" + jcsStringify(obj[k])).join(",") + "}";
  }
  throw new Error(`JCS: unsupported type ${typeof val}`);
}
async function blake3Hex(data) {
  try {
    const { blake3 } = await import("@noble/hashes/blake3");
    const hash = blake3(data);
    return Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    const hash = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
}
function extractContentPayload(line) {
  const v = line.verdict;
  if (!v) return null;
  return {
    agent: v.agent,
    description: v.description,
    timestamp: v.timestamp,
    delta_sv: v.delta_sv,
    ...v.evidence_root ? { evidence_root: v.evidence_root } : {}
  };
}
async function verifyReceipt(line) {
  const v = line.verdict;
  if (!v) return { verified: false, reason: "no_verdict_field" };
  const sig = v.signature;
  const pub = v.signer_pubkey;
  const hash = v.event_hash;
  if (!sig || !pub || !hash) return { verified: false, reason: "missing_fields" };
  const payload = extractContentPayload(line);
  if (!payload) return { verified: false, reason: "no_content_payload" };
  const canonical = jcsStringify(payload);
  const recomputed = await blake3Hex(new TextEncoder().encode(canonical));
  if (recomputed !== hash.toLowerCase()) {
    return { verified: false, reason: "hash_mismatch", event_hash: hash };
  }
  try {
    const { verifyAsync } = await import("@noble/ed25519");
    const sigBytes = hexToBytes(sig);
    const pubBytes = hexToBytes(pub);
    const msgBytes = new TextEncoder().encode(hash.toLowerCase());
    const ok = await verifyAsync(sigBytes, msgBytes, pubBytes);
    return ok ? { verified: true, event_hash: hash, signer_pubkey: pub } : { verified: false, reason: "sig_invalid" };
  } catch (e) {
    return { verified: false, reason: `sig_error: ${e}` };
  }
}
async function verifyLedger(jsonlText) {
  const lines = jsonlText.split("\n").filter((l) => l.trim());
  const results = await Promise.all(
    lines.map(async (raw, i) => {
      try {
        const line = JSON.parse(raw);
        const r = await verifyReceipt(line);
        return { line: i + 1, event_hash: line.verdict?.event_hash, ...r };
      } catch {
        return { line: i + 1, verified: false, reason: "parse_error" };
      }
    })
  );
  const chain_valid = results.every((r) => r.verified);
  return { results, chain_valid };
}
function hexToBytes(hex) {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
async function hashContent(text) {
  return blake3Hex(new TextEncoder().encode(text));
}

// src/cli.ts
var import_meta = {};
function getVersion() {
  try {
    const dir = typeof __dirname !== "undefined" ? __dirname : (0, import_node_path.dirname)((0, import_node_url.fileURLToPath)(import_meta.url));
    return JSON.parse((0, import_node_fs.readFileSync)((0, import_node_path.join)(dir, "..", "package.json"), "utf8")).version;
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
      const raw = (0, import_node_fs.readFileSync)(path, "utf8");
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
      const text = (0, import_node_fs.readFileSync)(path, "utf8");
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
      showHelp();
  }
}
function showHelp() {
  console.log(`
varp \u2014 Verifiable AI Receipt Protocol CLI

Commands:
  varp verify <receipt.json>        Verify a single VERDICT/v1 receipt
  varp verify-ledger <ledger.jsonl> Verify all receipts in a JSONL ledger
  varp hash <text>                  BLAKE3(text) \u2192 hex
  varp version                      Print version and exit
  varp help                         Show this message

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
