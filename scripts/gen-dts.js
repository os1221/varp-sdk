// Generates dist/index.d.ts from the public API surface of src/index.ts.
// Used instead of tsup --dts to avoid @noble/hashes ↔ DOM lib type conflict.
const { writeFileSync, mkdirSync } = require("fs");
mkdirSync("dist", { recursive: true });
writeFileSync("dist/index.d.ts", `
export type VerifyResult = {
  verified: boolean;
  reason?: string;
  event_hash?: string;
  signer_pubkey?: string;
};

export interface VerdictV1Envelope {
  event_hash: string;
  signature: string;
  signer_pubkey: string;
  prev_hash?: string;
  timestamp: string;
  delta_sv: number;
  description: string;
  agent: string;
  chain_valid?: boolean;
  content_valid?: boolean;
  evidence_root?: string;
}

export interface LedgerLine {
  verdict?: VerdictV1Envelope;
  event_hash?: string;
  signature?: string;
  signer_pubkey?: string;
  [key: string]: unknown;
}

export interface SignOptions {
  agent: string;
  description: string;
  delta_sv?: number;
  evidence_root?: string;
  privateKeyHex: string;
  prevHash?: string;
}

export declare function verifyReceipt(line: LedgerLine): Promise<VerifyResult>;
export declare function verifyLedger(jsonlText: string): Promise<{
  results: Array<{ line: number; event_hash?: string; verified: boolean; reason?: string }>;
  chain_valid: boolean;
}>;
export declare function createVerdictV1(opts: SignOptions): Promise<LedgerLine>;
export declare function hexToBytes(hex: string): Uint8Array;
export declare function bytesToHex(bytes: Uint8Array): string;
export declare function hashContent(text: string): Promise<string>;
export declare function getPublicKey(privateKeyHex: string): Promise<string>;
export declare function parseLedger(text: string): LedgerLine[];
export declare function jcsStringify(val: unknown): string;
export declare function blake3Hex(data: Uint8Array): Promise<string>;
`.trimStart());
console.log("dist/index.d.ts generated");
