/**
 * Centralized Ed25519 Loader
 *
 * Single lazy-init loader for @noble/ed25519 with sha512 configuration.
 * Handles both ESM dynamic import and CJS require fallback.
 * Supports both @noble/ed25519 v2 (etc.sha512Sync) and v3 (hashes.sha512).
 *
 * All modules in @sonate/core should import from here instead of
 * maintaining private copies of the loader logic.
 */

import { createHash } from 'crypto';
import { createRequire } from 'module';

const requireModule = createRequire(__filename);

let ed25519Promise: Promise<any> | null = null;

/**
 * Load and configure @noble/ed25519 with sha512.
 * Safe to call multiple times — the module is cached after first load.
 */
export async function loadEd25519(): Promise<any> {
  if (!ed25519Promise) {
    ed25519Promise = (async () => {
      let ed25519Mod: any;
      let sha512: (message: Uint8Array) => Uint8Array;

      try {
        const [dynamicEd25519Mod, hashMod] = await Promise.all([
          new Function('return import("@noble/ed25519")')() as Promise<any>,
          new Function('return import("@noble/hashes/sha2.js")')() as Promise<any>,
        ]);
        ed25519Mod = dynamicEd25519Mod;
        sha512 = hashMod.sha512;
      } catch {
        ed25519Mod = requireModule('@noble/ed25519');
        sha512 = (message: Uint8Array) =>
          new Uint8Array(createHash('sha512').update(message).digest());
      }

      const ed25519 = ed25519Mod.default || ed25519Mod;
      if (ed25519.hashes) {
        ed25519.hashes.sha512 = sha512;
      } else if (ed25519.etc) {
        ed25519.etc.sha512Sync = (...m: Uint8Array[]) => sha512(m[0]);
      }
      return ed25519;
    })();
  }
  return ed25519Promise;
}

/**
 * Generate Ed25519 key pair
 */
export async function generateEd25519KeyPair(): Promise<{
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}> {
  const ed25519 = await loadEd25519();
  const privateKey = (ed25519.utils.randomPrivateKey ?? ed25519.utils.randomSecretKey)();
  const publicKey = await ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Sign a message with Ed25519
 */
export async function signEd25519(
  message: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  const ed25519 = await loadEd25519();
  return ed25519.sign(message, privateKey);
}

/**
 * Verify an Ed25519 signature
 */
export async function verifyEd25519(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  const ed25519 = await loadEd25519();
  return ed25519.verify(signature, message, publicKey);
}

/**
 * Get public key from private key
 */
export async function getEd25519PublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  const ed25519 = await loadEd25519();
  return ed25519.getPublicKey(privateKey);
}
