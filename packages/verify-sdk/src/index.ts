/**
 * SONATE Verify SDK
 *
 * Client-side SDK for verifying trust receipts in Node.js and browsers.
 * Zero backend calls required - cryptographic verification is local.
 *
 * @example
 * ```typescript
 * import { verify, fetchPublicKey } from '@sonate/verify-sdk';
 *
 * const publicKey = await fetchPublicKey();
 * const result = await verify(receipt, publicKey);
 *
 * if (result.valid) {
 *   console.log('All checks passed');
 * }
 * ```
 */

import { canonicalize as canonicalizeRfc8785 } from 'json-canonicalize';

// Use Web Crypto API for browser compatibility
const isBrowser = typeof window !== 'undefined';

export interface TrustReceipt {
  /** V2 receipt ID (SHA-256 hash of canonical content) */
  id: string;
  /** Receipt schema version */
  version: '2.0.0' | '2.2.0';
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Session identifier */
  session_id: string;
  /** DID of the AI agent */
  agent_did: string;
  /** DID of the human user */
  human_did: string;
  /** Policy version */
  policy_version?: string;
  /** Governance mode */
  mode: 'constitutional' | 'directive';
  /** AI interaction data */
  interaction: {
    prompt?: string;
    response?: string;
    prompt_hash?: string;
    response_hash?: string;
    model: string;
    provider?: string;
    temperature?: number;
    max_tokens?: number;
    reasoning?: {
      thought_process?: string;
      confidence?: number;
      retrieved_context?: string[];
    };
  };
  /** Trust metrics */
  telemetry?: {
    resonance_score?: number;
    resonance_rm?: number;
    trust_resonance_gap?: number;
    overall_trust_score?: number;
    resonance_quality?: string;
    bedau_index?: number;
    coherence_score?: number;
    truth_debt?: number;
    volatility?: number;
    ciq_metrics?: {
      clarity?: number;
      integrity?: number;
      quality?: number;
    };
  };
  /** Policy state */
  policy_state?: Record<string, any>;
  /** Hash chain for immutability */
  chain: {
    previous_hash: string;
    chain_hash: string;
    chain_length?: number;
  };
  /** Cryptographic signature */
  signature: {
    algorithm: 'Ed25519';
    value: string;
    key_version: string;
    timestamp_signed?: string;
    public_key?: string;
  };
  /** Optional metadata */
  metadata?: Record<string, any>;

  // Deprecated V1 fields (for backwards compat detection)
  /** @deprecated Use `id` instead */
  self_hash?: string;
}

export interface VerificationResult {
  valid: boolean;
  checks: {
    structure: { passed: boolean; message: string };
    signature: { passed: boolean; message: string };
    hash: { passed: boolean; message: string };
    chain: { passed: boolean; message: string };
    timestamp: { passed: boolean; message: string };
  };
  trustScore: number | null;
  errors: string[];
  receipt: TrustReceipt;
}

export interface PublicKeyInfo {
  publicKey: string;
  algorithm: string;
  format: string;
  keyId?: string;
}

// Default SONATE public key endpoint
const DEFAULT_PUBKEY_URL = 'https://yseeku-backend.fly.dev/api/public-demo/public-key';

/**
 * Fetch the SONATE platform public key
 */
export async function fetchPublicKey(url?: string): Promise<string> {
  const response = await fetch(url || DEFAULT_PUBKEY_URL);
  if (!response.ok) {
    throw new Error(`Failed to fetch public key: ${response.status}`);
  }
  const data = await response.json();
  return data.data?.publicKey || data.publicKey;
}

/**
 * Convert hex string to Uint8Array.
 * Validates the input so malformed signatures/keys fail loudly rather than
 * silently decoding to zero bytes (which would mask tampering as a clean mismatch).
 */
function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('Invalid hex encoding');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * SHA-256 hash (browser-compatible)
 */
async function sha256(message: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);

  if (isBrowser && crypto.subtle) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return bytesToHex(new Uint8Array(hashBuffer));
  } else {
    // Node.js fallback
    const nodeCrypto = await import('crypto');
    return nodeCrypto.createHash('sha256').update(message).digest('hex');
  }
}

/**
 * Verify Ed25519 signature (browser-compatible)
 */
async function verifyEd25519(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    // Use @noble/ed25519 (works in both environments)
    const ed = (await import('@noble/ed25519')) as any;

    // Best-effort SHA-512 wiring for older @noble/ed25519 (<3.1), which needs a hash
    // impl. Newer versions ship a built-in hash and FREEZE `etc`, so assigning to it
    // throws in strict-mode (ESM) consumers. That throw must never reach the verify
    // call below (it would fail every receipt), so it is guarded — `verifyAsync` works
    // without any configuration on those versions.
    try {
      if (ed.etc && !ed.etc.sha512Sync && !ed.etc.sha512Async) {
        if (isBrowser && crypto.subtle) {
          ed.etc.sha512Async = async (msg: Uint8Array) =>
            new Uint8Array(await crypto.subtle.digest('SHA-512', new Uint8Array(msg)));
        } else {
          const nodeCrypto = await import('crypto');
          ed.etc.sha512Sync = (...m: Uint8Array[]) =>
            new Uint8Array(nodeCrypto.createHash('sha512').update(m[0]).digest());
        }
      }
    } catch {
      // `etc` is frozen on newer @noble/ed25519 — fine, it has a built-in hash.
    }

    return await ed.verifyAsync(signature, message, publicKey);
  } catch {
    // A malformed signature/key or a tampered receipt fails verification.
    // This is an expected outcome (it powers the tamper test), so we return
    // false rather than logging to the consumer's console.
    return false;
  }
}

/**
 * Canonicalize a receipt for signing/verification per RFC 8785.
 *
 * Producer (receipt-generator, public-demo route) and verifier (this SDK)
 * both delegate to the same `json-canonicalize` library so signature input
 * bytes are identical across processes and runtimes. `undefined` values are
 * stripped first to match the prior hand-rolled behaviour, since they aren't
 * representable in canonical JSON.
 */
export function canonicalize(obj: any): string {
  return canonicalizeRfc8785(stripUndefined(obj));
}

function stripUndefined(value: any): any {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(stripUndefined);
  const out: Record<string, any> = {};
  for (const key of Object.keys(value)) {
    if (value[key] !== undefined) out[key] = stripUndefined(value[key]);
  }
  return out;
}

function cloneReceipt<T>(value: T): T {
  return JSON.parse(JSON.stringify(value));
}

function buildReceiptForIdVerification(receipt: TrustReceipt): Record<string, any> {
  const receiptBase = cloneReceipt(receipt) as Record<string, any>;
  delete receiptBase.signature;
  delete receiptBase.id;
  if (receiptBase.chain) {
    receiptBase.chain = {
      ...receiptBase.chain,
      chain_hash: '',
    };
  }
  return receiptBase;
}

export interface VerifyOptions {
  /** Maximum age of receipt in milliseconds (default: 1 year) */
  maxAgeMs?: number;
  /** Maximum clock skew tolerance in milliseconds (default: 5 minutes) */
  maxFutureMs?: number;
}

const DEFAULT_MAX_AGE_MS = 365 * 24 * 60 * 60 * 1000;
const DEFAULT_MAX_FUTURE_MS = 5 * 60 * 1000;

/**
 * Verify a SONATE trust receipt
 *
 * @param receipt - The trust receipt to verify
 * @param publicKey - The SONATE public key (hex string)
 * @param options - Optional verification parameters
 * @returns Verification result with detailed checks
 */
export async function verify(
  receipt: TrustReceipt,
  publicKey: string,
  options?: VerifyOptions
): Promise<VerificationResult> {
  const result: VerificationResult = {
    valid: false,
    checks: {
      structure: { passed: false, message: '' },
      signature: { passed: false, message: '' },
      hash: { passed: false, message: '' },
      chain: { passed: false, message: '' },
      timestamp: { passed: false, message: '' },
    },
    trustScore: null,
    errors: [],
    receipt,
  };

  try {
    // 1. Structure validation (V2-only: require `id`)
    const receiptId = receipt.id || receipt.self_hash;
    if (!receiptId || !receipt.signature?.value) {
      const missing = [];
      if (!receiptId) missing.push('id');
      if (!receipt.signature?.value) missing.push('signature');
      result.checks.structure.message = `Missing required fields: ${missing.join(', ')}`;
      result.errors.push(result.checks.structure.message);

      if (receipt.self_hash && !receipt.id) {
        result.checks.structure.message =
          'This receipt uses V1 format (self_hash). V2 format with "id" field is required.';
        result.errors.push(result.checks.structure.message);
      }
    } else {
      result.checks.structure.passed = true;
      result.checks.structure.message = 'Valid V2 receipt structure';
    }

    // 2. Receipt ID verification - hash canonical receipt base without signature or id
    if (receiptId) {
      const canonicalForId = canonicalize(buildReceiptForIdVerification(receipt));
      const computedReceiptId = await sha256(canonicalForId);
      const hashValid = computedReceiptId === receiptId;

      result.checks.hash.passed = hashValid;
      result.checks.hash.message = hashValid
        ? 'Receipt hash matches canonical payload'
        : 'Receipt hash does not match canonical payload';

      if (!hashValid) {
        result.errors.push('Receipt hash verification failed');
      }
    } else {
      result.checks.hash.message = 'No receipt id provided';
      result.errors.push(result.checks.hash.message);
    }

    // 3. Signature verification - sign over canonical receipt content (without signature)
    const signatureValue = receipt.signature?.value;

    if (signatureValue && publicKey) {
      try {
        const { signature: _sig, ...receiptWithoutSig } = receipt;
        const canonical = canonicalize(receiptWithoutSig);
        const messageBytes = new TextEncoder().encode(canonical);
        const signatureBytes = hexToBytes(signatureValue);
        const publicKeyBytes = hexToBytes(publicKey);

        const isValid = await verifyEd25519(messageBytes, signatureBytes, publicKeyBytes);

        result.checks.signature.passed = isValid;
        result.checks.signature.message = isValid
          ? 'Ed25519 signature verified'
          : 'Signature verification failed - content may have been tampered';

        if (!isValid) {
          result.errors.push('Signature verification failed');
        }
      } catch {
        // Malformed signature or public-key hex encoding — fail this check but
        // let the remaining checks (chain, timestamp) still run and report.
        result.checks.signature.passed = false;
        result.checks.signature.message = 'Malformed signature or public-key encoding';
        result.errors.push('Signature verification failed: invalid hex encoding');
      }
    } else {
      result.checks.signature.message = 'No signature or public key provided';
      result.errors.push(result.checks.signature.message);
    }

    // 4. Chain hash verification
    if (receipt.chain?.chain_hash && receipt.chain?.previous_hash) {
      // Reconstruct: canonicalize(receipt without sig, with empty chain_hash) + previous_hash
      const { signature: _sig, ...receiptWithoutSig } = receipt;
      const receiptForChain = {
        ...receiptWithoutSig,
        chain: { ...receipt.chain, chain_hash: '' },
      };
      const contentForChain = canonicalize(receiptForChain);
      const chainContent = contentForChain + receipt.chain.previous_hash;
      const expectedChainHash = await sha256(chainContent);

      const chainValid = expectedChainHash === receipt.chain.chain_hash;
      result.checks.chain.passed = chainValid;
      result.checks.chain.message = chainValid
        ? 'Chain hash verified'
        : 'Chain hash mismatch - receipt may have been tampered';

      if (!chainValid) {
        result.errors.push('Chain hash verification failed');
      }
    } else if (receipt.chain?.previous_hash === 'GENESIS') {
      // First receipt in chain - chain hash should still be present and valid
      if (receipt.chain?.chain_hash) {
        const { signature: _sig, ...receiptWithoutSig } = receipt;
        const receiptForChain = {
          ...receiptWithoutSig,
          chain: { ...receipt.chain, chain_hash: '' },
        };
        const contentForChain = canonicalize(receiptForChain);
        const chainContent = contentForChain + 'GENESIS';
        const expectedChainHash = await sha256(chainContent);

        const chainValid = expectedChainHash === receipt.chain.chain_hash;
        result.checks.chain.passed = chainValid;
        result.checks.chain.message = chainValid
          ? 'Genesis chain hash verified'
          : 'Genesis chain hash mismatch';
        if (!chainValid) {
          result.errors.push('Genesis chain hash verification failed');
        }
      } else {
        result.checks.chain.passed = true;
        result.checks.chain.message = 'First receipt in chain (GENESIS)';
      }
    } else {
      result.checks.chain.passed = true;
      result.checks.chain.message = 'Chain verification skipped (no chain data)';
    }

    // 5. Timestamp validation
    const timestamp = receipt.timestamp;
    if (timestamp) {
      const receiptTime = new Date(timestamp);
      const now = new Date();
      const maxAge = options?.maxAgeMs ?? DEFAULT_MAX_AGE_MS;
      const maxFuture = options?.maxFutureMs ?? DEFAULT_MAX_FUTURE_MS;
      const cutoff = new Date(now.getTime() - maxAge);
      const fiveMinutesFromNow = new Date(now.getTime() + maxFuture);

      if (receiptTime > fiveMinutesFromNow) {
        result.checks.timestamp.passed = false;
        result.checks.timestamp.message = 'Timestamp is in the future';
        result.errors.push(result.checks.timestamp.message);
      } else if (receiptTime < cutoff) {
        result.checks.timestamp.passed = false;
        result.checks.timestamp.message = `Timestamp is older than max age (${Math.round(
          maxAge / (24 * 60 * 60 * 1000)
        )} days)`;
        result.errors.push(result.checks.timestamp.message);
      } else {
        result.checks.timestamp.passed = true;
        result.checks.timestamp.message = `Issued ${receiptTime.toISOString()}`;
      }
    } else {
      result.checks.timestamp.passed = false;
      result.checks.timestamp.message = 'No timestamp present';
      result.errors.push(result.checks.timestamp.message);
    }

    // Calculate trust score from telemetry
    if (typeof receipt.telemetry?.overall_trust_score === 'number') {
      result.trustScore = Math.round(receipt.telemetry.overall_trust_score);
    } else if (receipt.telemetry?.ciq_metrics) {
      const { clarity = 0, integrity = 0, quality = 0 } = receipt.telemetry.ciq_metrics;
      result.trustScore = Math.round(((clarity + integrity + quality) / 3) * 100);
    } else if (receipt.telemetry?.resonance_score !== undefined) {
      result.trustScore = Math.round(receipt.telemetry.resonance_score * 100);
    }

    // Overall validity
    result.valid =
      result.checks.structure.passed &&
      result.checks.hash.passed &&
      result.checks.signature.passed &&
      result.checks.chain.passed &&
      result.checks.timestamp.passed;
  } catch (error) {
    result.errors.push(`Verification error: ${error}`);
  }

  return result;
}

/**
 * Quick verification - returns boolean only
 */
export async function quickVerify(
  receipt: TrustReceipt,
  publicKey: string,
  options?: VerifyOptions
): Promise<boolean> {
  const result = await verify(receipt, publicKey, options);
  return result.valid;
}

/**
 * Verify a batch of receipts
 */
export async function verifyBatch(
  receipts: TrustReceipt[],
  publicKey: string,
  options?: VerifyOptions
): Promise<{
  total: number;
  valid: number;
  invalid: number;
  results: VerificationResult[];
}> {
  const results = await Promise.all(receipts.map((receipt) => verify(receipt, publicKey, options)));

  return {
    total: receipts.length,
    valid: results.filter((r) => r.valid).length,
    invalid: results.filter((r) => !r.valid).length,
    results,
  };
}

/**
 * Calculate trust score from CIQ metrics
 */
export function calculateTrustScore(ciqMetrics: {
  clarity?: number;
  integrity?: number;
  quality?: number;
}): number {
  const { clarity = 0, integrity = 0, quality = 0 } = ciqMetrics;
  return Math.round(((clarity + integrity + quality) / 3) * 100);
}

/**
 * Check if a receipt was issued by a trusted agent
 */
export function isTrustedIssuer(receipt: TrustReceipt, trustedIssuers: string[]): boolean {
  const agentDid = receipt.agent_did;
  if (!agentDid) return false;

  return trustedIssuers.some((trusted) => agentDid === trusted || agentDid.startsWith(trusted));
}
