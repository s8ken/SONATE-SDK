/**
 * Base58 encoding/decoding (Bitcoin alphabet)
 *
 * Centralized implementation replacing hand-rolled copies across:
 * - did-vc-manager.ts
 * - verifiable-credentials.service.ts
 * - did.service.ts
 * - crypto-advanced.ts
 *
 * Correctly handles leading zero bytes in both directions.
 */

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE = BigInt(58);

export function base58Encode(bytes: Uint8Array): string {
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leadingZeros++;
  }

  let num = BigInt(0);
  for (const b of bytes) {
    num = num * BigInt(256) + BigInt(b);
  }

  let result = '';
  while (num > BigInt(0)) {
    const remainder = Number(num % BASE);
    num = num / BASE;
    result = ALPHABET[remainder] + result;
  }

  return '1'.repeat(leadingZeros) + result;
}

export function base58Decode(str: string): Uint8Array {
  let leadingOnes = 0;
  for (const c of str) {
    if (c !== '1') break;
    leadingOnes++;
  }

  let num = BigInt(0);
  for (const c of str) {
    const index = ALPHABET.indexOf(c);
    if (index === -1) throw new Error(`Invalid base58 character: ${c}`);
    num = num * BASE + BigInt(index);
  }

  const hex = num === BigInt(0) ? '' : num.toString(16);
  const paddedHex = hex.length % 2 ? '0' + hex : hex;
  const decoded = new Uint8Array(
    (paddedHex.match(/.{2}/g) || []).map((h) => parseInt(h, 16)),
  );

  const result = new Uint8Array(leadingOnes + decoded.length);
  result.set(decoded, leadingOnes);
  return result;
}

/**
 * Encode a hex public key to multibase (z-prefixed base58btc)
 * @param hex - hex string (with or without 0x prefix)
 * @param multicodecPrefix - multicodec prefix bytes (default: ed25519-pub [0xed, 0x01])
 */
export function hexToMultibase(hex: string, multicodecPrefix: number[] = [0xed, 0x01]): string {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const keyBytes = new Uint8Array(
    (cleanHex.match(/.{2}/g) || []).map((h) => parseInt(h, 16)),
  );
  const prefixed = new Uint8Array([...multicodecPrefix, ...keyBytes]);
  return 'z' + base58Encode(prefixed);
}

/**
 * Decode a multibase (z-prefixed base58btc) string to hex
 * @param multibase - multibase string starting with 'z'
 * @param prefixLength - number of multicodec prefix bytes to strip (default: 2)
 */
export function multibaseToHex(multibase: string, prefixLength = 2): string {
  if (!multibase.startsWith('z')) throw new Error('Only z-base58btc multibase supported');
  const decoded = base58Decode(multibase.slice(1));
  const keyBytes = decoded.slice(prefixLength);
  return Array.from(keyBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
