/**
 * Golden fixture conformance.
 *
 * @sonate/schemas' validators must accept every receipt shape the platform
 * actually produces. The normative source of truth for v2.2.0 receipts is
 * @sonate/trust-receipts, whose committed, deterministic fixtures are also
 * verified cross-language (Python SDK) and by @sonate/verify-sdk. Loading
 * them here (rather than hand-rolled examples) keeps this package's schema
 * honest against real receipts instead of an idealized shape.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

import { receiptValidator } from '../index';

const FIXTURES_DIR = join(__dirname, '..', '..', '..', 'trust-receipts', 'fixtures');

function load(name: string): any {
  return JSON.parse(readFileSync(join(FIXTURES_DIR, name), 'utf-8'));
}

const SINGLE_FIXTURES = ['genesis-hash-only.json', 'full-content.json', 'explicit-dids.json'];

describe('golden fixtures (from @sonate/trust-receipts)', () => {
  for (const file of SINGLE_FIXTURES) {
    it(`${file}: AJV (JSON Schema) accepts the receipt`, () => {
      const { receipt } = load(file);
      const result = receiptValidator.validateJSON(receipt);
      expect(result.errors, JSON.stringify(result.errors)).toEqual([]);
      expect(result.valid).toBe(true);
    });

    it(`${file}: Zod accepts the receipt`, () => {
      const { receipt } = load(file);
      const result = receiptValidator.validateZod(receipt);
      if (!result.success) {
        throw new Error(`${file} failed Zod validation: ${JSON.stringify(result.error.issues, null, 2)}`);
      }
      expect(result.success).toBe(true);
    });
  }

  it('chain.json: every receipt in the chain is accepted by AJV and Zod', () => {
    const { receipts } = load('chain.json');
    expect(receipts).toHaveLength(3);

    for (const receipt of receipts) {
      const jsonResult = receiptValidator.validateJSON(receipt);
      expect(jsonResult.errors, JSON.stringify(jsonResult.errors)).toEqual([]);
      expect(jsonResult.valid).toBe(true);

      const zodResult = receiptValidator.validateZod(receipt);
      expect(zodResult.success, JSON.stringify(!zodResult.success && zodResult.error.issues)).toBe(true);
    }
  });

  it('accepts 2.0.0-shaped receipts with plaintext prompt/response and policy_version (backwards compatibility)', () => {
    const legacyReceipt = {
      id: 'a'.repeat(64),
      version: '2.0.0',
      timestamp: '2026-02-09T18:30:45.123Z',
      session_id: 'session_abc123',
      agent_did: 'did:sonate:a1b2c3d4e5f6',
      human_did: 'did:sonate:x9y8z7w6v5u4',
      policy_version: 'policy_v1.2.0',
      mode: 'constitutional',
      interaction: {
        prompt: 'What is the capital of France?',
        response: 'Paris is the capital of France.',
        model: 'gpt-4-turbo',
        provider: 'openai',
      },
      chain: {
        previous_hash: 'GENESIS',
        chain_hash: 'b'.repeat(64),
      },
      signature: {
        algorithm: 'Ed25519',
        value: 'MEQCIDGrvmTEr7c00rpf5Z+O50Ad5Z8Xxfqfjf9Z8O50Ad5==',
        key_version: 'key_v1',
      },
    };

    const jsonResult = receiptValidator.validateJSON(legacyReceipt);
    expect(jsonResult.errors, JSON.stringify(jsonResult.errors)).toEqual([]);
    expect(jsonResult.valid).toBe(true);

    const zodResult = receiptValidator.validateZod(legacyReceipt);
    expect(zodResult.success, JSON.stringify(!zodResult.success && zodResult.error.issues)).toBe(true);
  });

  it('rejects a receipt whose interaction has neither hashes nor content', () => {
    const { receipt } = load('genesis-hash-only.json');
    const invalid = JSON.parse(JSON.stringify(receipt));
    delete invalid.interaction.prompt_hash;
    delete invalid.interaction.response_hash;
    delete invalid.interaction.prompt;
    delete invalid.interaction.response;

    const jsonResult = receiptValidator.validateJSON(invalid);
    expect(jsonResult.valid).toBe(false);
    expect(jsonResult.errors.length).toBeGreaterThan(0);

    const zodResult = receiptValidator.validateZod(invalid);
    expect(zodResult.success).toBe(false);
  });
});
