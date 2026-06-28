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
  if (v["event"] && typeof v["event"] === "object") {
    const ev = v["event"];
    const payload2 = {
      description: ev["description"],
      delta_sv: ev["delta_sv"],
      timestamp: ev["timestamp"]
    };
    if (ev["evidence_root"] != null) payload2["evidence_root"] = ev["evidence_root"];
    return payload2;
  }
  const payload = {
    agent: v["agent"],
    description: v["description"],
    timestamp: v["timestamp"],
    delta_sv: v["delta_sv"]
  };
  if (v["evidence_root"] != null) payload["evidence_root"] = v["evidence_root"];
  return payload;
}
async function verifyReceipt(line) {
  const v = line.verdict;
  if (!v) return { verified: false, reason: "no_verdict_field" };
  const sig = v["signature"] ?? v["signature_hex"];
  const pub = v["signer_pubkey"] ?? v["signer_pubkey_hex"];
  const ev = v["event"];
  const hash = v["event_hash"] ?? (ev && ev["hash"]);
  if (!sig || !pub || !hash) return { verified: false, reason: "missing_fields" };
  const payload = extractContentPayload(line);
  if (!payload) return { verified: false, reason: "no_content_payload" };
  const isOmegaFormat = ev != null;
  const canonical = isOmegaFormat ? jcsStringify(payload) : jcsStringify(payload);
  const recomputed = await blake3Hex(new TextEncoder().encode(canonical));
  if (recomputed !== hash.toLowerCase()) {
    const legacyFloat = (n) => Number.isFinite(n) && Number.isInteger(n) ? n.toFixed(1) : JSON.stringify(n);
    const dsv = payload["delta_sv"];
    let legacyStr = `{"description":${JSON.stringify(payload["description"])},"delta_sv":${legacyFloat(dsv)},"timestamp":${JSON.stringify(payload["timestamp"])}`;
    if (payload["evidence_root"] != null) legacyStr += `,"evidence_root":${JSON.stringify(payload["evidence_root"])}`;
    legacyStr += "}";
    const legacyRecomputed = await blake3Hex(new TextEncoder().encode(legacyStr));
    if (legacyRecomputed !== hash.toLowerCase()) {
      return { verified: false, reason: "hash_mismatch", event_hash: hash };
    }
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
async function createVerdictV1(opts) {
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
  const { sign, getPublicKey } = ed;
  const privBytes = hexToBytes(opts.privateKeyHex);
  const pubBytes = getPublicKey(privBytes);
  const pubHex = bytesToHex(pubBytes);
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  const payload = {
    agent: opts.agent,
    description: opts.description,
    timestamp,
    delta_sv: opts.delta_sv ?? 0.1,
    ...opts.evidence_root ? { evidence_root: opts.evidence_root } : {}
  };
  const canonical = jcsStringify(payload);
  const event_hash = await blake3Hex(new TextEncoder().encode(canonical));
  const sigBytes = await sign(new TextEncoder().encode(event_hash), privBytes);
  const signature = bytesToHex(sigBytes);
  return {
    verdict: {
      event_hash,
      signature,
      signer_pubkey: pubHex,
      ...opts.prevHash ? { prev_hash: opts.prevHash } : {},
      timestamp,
      delta_sv: opts.delta_sv ?? 0.1,
      description: opts.description,
      agent: opts.agent,
      chain_valid: true,
      content_valid: true
    }
  };
}
function hexToBytes(hex) {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
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
    case "chain-report": {
      const path = args[0];
      if (!path) {
        die("Usage: varp chain-report <ledger.jsonl>");
      }
      const text = (0, import_node_fs.readFileSync)(path, "utf8");
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
      const text = (0, import_node_fs.readFileSync)(path, "utf8");
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
