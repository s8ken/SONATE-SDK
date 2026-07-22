/**
 * Golden fixture conformance.
 *
 * Loads the committed, deterministic fixtures from `fixtures/*.json` and
 * verifies each with @sonate/verify-sdk. These same files are verified by the
 * Python SDK, giving true cross-language conformance on identical bytes.
 *
 * Fixtures use FIXED timestamps, so a generous `maxAgeMs` is supplied to keep
 * the timestamp check from aging them out over time.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { verify, type TrustReceipt as VerifyReceipt } from '@sonate/verify-sdk';

const FIXTURES_DIR = join(__dirname, '..', '..', 'fixtures');
const HUNDRED_YEARS_MS = 100 * 365 * 24 * 60 * 60 * 1000;

function load(name: string): any {
  return JSON.parse(readFileSync(join(FIXTURES_DIR, name), 'utf-8'));
}

const SINGLE_FIXTURES = ['genesis-hash-only.json', 'full-content.json', 'explicit-dids.json'];

describe('golden fixtures', () => {
  for (const file of SINGLE_FIXTURES) {
    it(`${file} verifies with verify-sdk`, async () => {
      const { public_key, receipt } = load(file);
      const result = await verify(receipt as VerifyReceipt, public_key, {
        maxAgeMs: HUNDRED_YEARS_MS,
      });
      expect(result.valid, JSON.stringify(result.errors)).toBe(true);
    });
  }

  it('chain.json: every receipt verifies and links correctly', async () => {
    const { public_key, receipts } = load('chain.json');
    expect(receipts).toHaveLength(3);

    for (const receipt of receipts) {
      const result = await verify(receipt as VerifyReceipt, public_key, {
        maxAgeMs: HUNDRED_YEARS_MS,
      });
      expect(result.valid, JSON.stringify(result.errors)).toBe(true);
    }

    expect(receipts[0].chain.previous_hash).toBe('GENESIS');
    expect(receipts[1].chain.previous_hash).toBe(receipts[0].chain.chain_hash);
    expect(receipts[2].chain.previous_hash).toBe(receipts[1].chain.chain_hash);
  });

  it('fixtures are deterministic (stable id/signature for the fixed seed)', () => {
    // Guards against accidental drift in the construction pipeline. If the
    // canonicalization or ordering changes, these frozen values change and the
    // Python cross-language fixtures would silently diverge.
    const { receipt } = load('genesis-hash-only.json');
    expect(receipt.id).toBe(
      '4e25e38ea20588a9c49de09cfd9bc73fc577e926848faac7f6810ddd8aea783c'
    );
    expect(receipt.chain.chain_hash).toBe(
      '4147fd708d57a4c480aaa46e4fbf19526fe31cd7ed68d79cd3bf55de3f7d16a5'
    );
    expect(receipt.signature.value).toBe(
      '3aba9cf00ef2ce8d0e42a579554c94f95ef6b4612e78c0bc879d0a738b16a3e972eac16414aa059c5ed4c2c37d3b54e670adcbaf58ce380d0b6b6c8c407e930e'
    );
  });
});
