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

export type WarrantPacketStatus =
  | "verified"
  | "invalid"
  | "unavailable_private_ledger";

export interface WarrantPacketVerifyResult {
  verified: boolean;
  status: WarrantPacketStatus;
  reasons: string[];
  report_hash?: string;
  coverage_hash?: string;
  repo_count?: number;
  credential_gates?: number;
  receipt_event_hash?: string;
  private_ledger_status: "redacted" | "not_checked";
}

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

export interface OmegaReceiptEvent {
  timestamp?: string;
  description?: string;
  delta_sv?: number;
  hash?: string;
  [key: string]: unknown;
}

export interface OmegaReceiptVerdict {
  event?: OmegaReceiptEvent;
  signature_hex?: string;
  signer_pubkey_hex?: string;
  [key: string]: unknown;
}

export interface LedgerLine {
  verdict?: VerdictV1Envelope | OmegaReceiptVerdict;
  event_hash?: string;
  signature?: string;
  signer_pubkey?: string;
  prev_hash?: string;
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
export declare function verifyWarrantProofPacket(
  packetInput: unknown,
  reportInput: unknown
): Promise<WarrantPacketVerifyResult>;

export declare const PROOF_PACKET_SCHEMA: "verdict.proof-packet/v1";

export interface ProofPacketValidation {
  valid: boolean;
  errors: string[];
}

export interface ProofPacketVerifyResult {
  kind: "proof_packet" | "verdict_v1_envelope";
  valid: boolean;
  signature_valid: boolean | null;
  validation: ProofPacketValidation;
  errors: string[];
  subject?: string;
  action?: string;
  unit_id?: string;
  content_hash?: string;
  signer_pubkey?: string;
}

export declare function validateProofPacket(packetInput: unknown): Promise<ProofPacketValidation>;
export declare function verifyProofPacket(input: unknown): Promise<ProofPacketVerifyResult>;
export declare function createVerdictV1(opts: SignOptions): Promise<LedgerLine>;
export declare function hexToBytes(hex: string): Uint8Array;
export declare function bytesToHex(bytes: Uint8Array): string;
export declare function hashContent(text: string): Promise<string>;
export declare function ed25519Verify(
  signatureHex: string,
  message: Uint8Array | string,
  publicKeyHex: string,
): Promise<boolean>;
export declare function getPublicKey(privateKeyHex: string): Promise<string>;
export declare function parseLedger(text: string): LedgerLine[];
export declare function jcsStringify(val: unknown): string;
export declare function blake3Hex(data: Uint8Array): Promise<string>;
export declare function sha256Hex(data: Uint8Array): Promise<string>;
`.trimStart());
console.log("dist/index.d.ts generated");
