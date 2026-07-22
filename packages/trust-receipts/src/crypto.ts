/**
 * Cryptographic utilities for Trust Receipts
 *
 * Ed25519 signatures with Node.js crypto sha512.
 * Uses @noble/ed25519 v3 for the actual cryptographic operations.
 */

import { createHash } from 'crypto';

import { canonicalize as canonicalizeRfc8785 } from 'json-canonicalize';

let ed25519Promise: Promise<any> | null = null;

/**
 * Load and configure @noble/ed25519 v3.
 *
 * @noble/ed25519 v3 is pure ESM, so it must be reached via a native dynamic
 * `import()` — never a downleveled `require()`. `tsconfig` uses `module:
 * node16`, which emits CommonJS for this file while preserving this `import()`
 * as-is, so both the built CJS bundle and the vitest source runner work.
 */
async function loadEd25519(): Promise<any> {
  if (!ed25519Promise) {
    ed25519Promise = import('@noble/ed25519').then((ed25519: any) => {
      // Configure sha512 for @noble/ed25519 v3
      ed25519.hashes.sha512 = (message: Uint8Array) =>
        new Uint8Array(createHash('sha512').update(message).digest());
      return ed25519;
    });
  }
  return ed25519Promise;
}

/**
 * Generate a new Ed25519 key pair
 *
 * @returns Object with privateKey and publicKey as Uint8Array (32 bytes each)
 *
 * @example
 * ```typescript
 * const { privateKey, publicKey } = await generateKeyPair();
 * console.log('Private key:', Buffer.from(privateKey).toString('hex'));
 * console.log('Public key:', Buffer.from(publicKey).toString('hex'));
 * ```
 */
export async function generateKeyPair(): Promise<{
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}> {
  const ed25519 = await loadEd25519();
  const privateKey = (ed25519.utils.randomPrivateKey ?? ed25519.utils.randomSecretKey)();
  const publicKey = await ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Assert a key is a 32-byte Ed25519 seed, throwing a clear error otherwise.
 *
 * @noble/ed25519 expects a 32-byte private-key SEED. tweetnacl users migrating
 * from the platform reference often hold a 64-byte `secretKey` (seed + public
 * key) — passing that would fail deep inside the crypto library with an opaque
 * message, so we validate up front. Mirrors the reference `normalizePrivateKeySeed`.
 *
 * @param key - candidate key bytes
 * @param label - what the key is, used in the error message (default: "private key seed")
 */
export function assertEd25519Seed(key: Uint8Array, label = 'private key seed'): void {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    const got = key instanceof Uint8Array ? `${key.length} bytes` : typeof key;
    throw new Error(`Expected 32-byte Ed25519 ${label}, received ${got}`);
  }
}

/**
 * Sign a message with Ed25519
 *
 * @param message - The message to sign (Uint8Array)
 * @param privateKey - The 32-byte Ed25519 private key seed
 * @returns The 64-byte signature
 */
export async function sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  assertEd25519Seed(privateKey);
  const ed25519 = await loadEd25519();
  return ed25519.sign(message, privateKey);
}

/**
 * Verify an Ed25519 signature
 *
 * @param signature - The 64-byte signature to verify
 * @param message - The original message
 * @param publicKey - The 32-byte Ed25519 public key
 * @returns true if valid, false otherwise
 */
export async function verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  const ed25519 = await loadEd25519();
  return ed25519.verify(signature, message, publicKey);
}

/**
 * Derive public key from private key
 *
 * @param privateKey - The 32-byte Ed25519 private key
 * @returns The corresponding 32-byte public key
 */
export async function getPublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  const ed25519 = await loadEd25519();
  return ed25519.getPublicKey(privateKey);
}

/**
 * Compute SHA-256 hash
 *
 * @param data - Data to hash (string or Uint8Array)
 * @returns Hex-encoded hash string
 */
export function sha256(data: string | Uint8Array): string {
  const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return createHash('sha256').update(buffer).digest('hex');
}

/**
 * Recursively strip `undefined` values so canonical output matches the
 * verifier. `undefined` is not representable in JSON, and @sonate/verify-sdk
 * strips it before canonicalizing — producer and verifier must agree
 * byte-for-byte, so we mirror that behaviour exactly.
 */
function stripUndefined(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(stripUndefined);
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>)) {
    const v = (value as Record<string, unknown>)[key];
    if (v !== undefined) out[key] = stripUndefined(v);
  }
  return out;
}

/**
 * Canonicalize an object per RFC 8785 (JSON Canonicalization Scheme).
 *
 * This is the single source of truth for producing signature/hash input
 * bytes. It strips `undefined` first, then delegates to `json-canonicalize`
 * — identical to the pipeline in @sonate/verify-sdk, guaranteeing the bytes
 * this SDK signs are the exact bytes the verifier reconstructs.
 */
export function canonicalize(value: unknown): string {
  return canonicalizeRfc8785(stripUndefined(value));
}

/**
 * Encode bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

/**
 * Decode hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}
