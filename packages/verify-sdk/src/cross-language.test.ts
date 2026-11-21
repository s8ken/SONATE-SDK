/**
 * Cross-language conformance: receipts signed by the Python SDK
 * (packages/trust-receipts-python) must verify with this JavaScript verifier.
 *
 * The Python fixtures are generated from a fixed test seed (32 bytes of 0x42),
 * never a real key. The reverse direction (JS-signed receipts verifying in
 * Python, byte-for-byte reproduction) lives in the Python package's
 * tests/test_conformance.py.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { verify, type TrustReceipt } from './index';

const FIXTURES = join(__dirname, '..', '..', 'trust-receipts-python', 'fixtures');
const manifest = JSON.parse(readFileSync(join(FIXTURES, 'manifest.json'), 'utf8')) as {
  public_key_hex: string;
  chain: string[];
};
const PUBLIC_KEY = manifest.public_key_hex;

// Fixtures carry fixed 2026 timestamps; don't let the verifier's default
// one-year age limit turn this conformance test into a time bomb.
const NO_AGE_LIMIT = { maxAgeMs: Number.MAX_SAFE_INTEGER };

function load(name: string): TrustReceipt {
  return JSON.parse(readFileSync(join(FIXTURES, name), 'utf8')) as TrustReceipt;
}

const receiptFiles = readdirSync(FIXTURES).filter(
  (f) => f.endsWith('.json') && f !== 'keys.json' && f !== 'manifest.json'
);

describe('Python-signed receipts verify in JavaScript', () => {
  it('finds the Python fixtures', () => {
    expect(receiptFiles.length).toBeGreaterThanOrEqual(6);
  });

  it.each(receiptFiles)('%s passes every check', async (file) => {
    const result = await verify(load(file), PUBLIC_KEY, NO_AGE_LIMIT);
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it('links the Python chain: each previous_hash is the prior chain_hash', () => {
    const chain = manifest.chain.map(load);
    expect(chain[0].chain?.previous_hash).toBe('GENESIS');
    for (let i = 1; i < chain.length; i++) {
      expect(chain[i].chain?.previous_hash).toBe(chain[i - 1].chain?.chain_hash);
    }
  });

  it('rejects a Python receipt whose content was changed after signing', async () => {
    const receipt = load('single-constitutional.json');
    const tampered = {
      ...receipt,
      interaction: { ...receipt.interaction, response_hash: '0'.repeat(64) },
    } as TrustReceipt;
    const result = await verify(tampered, PUBLIC_KEY, NO_AGE_LIMIT);
    expect(result.valid).toBe(false);
    expect(result.checks.signature.passed).toBe(false);
    expect(result.checks.hash.passed).toBe(false);
  });

  it('rejects a Python receipt checked against a different public key', async () => {
    const otherKey = 'ab'.repeat(32);
    const result = await verify(load('minimal-directive.json'), otherKey, NO_AGE_LIMIT);
    expect(result.valid).toBe(false);
    expect(result.checks.signature.passed).toBe(false);
  });
});
