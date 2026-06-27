"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
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
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  blake3Hex: () => blake3Hex,
  bytesToHex: () => bytesToHex,
  createVerdictV1: () => createVerdictV1,
  hashContent: () => hashContent,
  hexToBytes: () => hexToBytes,
  jcsStringify: () => jcsStringify,
  verifyLedger: () => verifyLedger,
  verifyReceipt: () => verifyReceipt
});
module.exports = __toCommonJS(index_exports);
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
async function createVerdictV1(opts) {
  const { sign, getPublicKey } = await import("@noble/ed25519");
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  blake3Hex,
  bytesToHex,
  createVerdictV1,
  hashContent,
  hexToBytes,
  jcsStringify,
  verifyLedger,
  verifyReceipt
});
