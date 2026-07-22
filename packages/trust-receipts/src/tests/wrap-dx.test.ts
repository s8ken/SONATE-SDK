/**
 * wrap() developer-experience integration tests.
 *
 * Validates seamless integration with OpenAI, Anthropic, and Gemini response
 * shapes, plus manual receipts, chaining, content inclusion, error handling,
 * and that the wrapped response object is returned untouched.
 */

import { describe, it, expect } from 'vitest';
import { verify, type TrustReceipt as VerifyReceipt } from '@sonate/verify-sdk';
import { TrustReceipts } from '../index';
import { sha256 } from '../crypto';

describe('provider auto-extraction', () => {
  it('extracts OpenAI chat completion content', async () => {
    const receipts = new TrustReceipts();
    const { receipt } = await receipts.wrap(
      async () => ({ choices: [{ message: { content: 'Hello from OpenAI!' } }] }),
      { sessionId: 'openai', input: 'prompt', provider: 'openai' }
    );
    expect(receipt.interaction.response_hash).toBe(sha256('Hello from OpenAI!'));
    expect(await receipts.verifyReceipt(receipt)).toBe(true);
  });

  it('extracts Anthropic message content', async () => {
    const receipts = new TrustReceipts();
    const { receipt } = await receipts.wrap(
      async () => ({ content: [{ type: 'text', text: 'Hello from Claude!' }] }),
      { sessionId: 'anthropic', input: 'prompt', provider: 'anthropic' }
    );
    expect(receipt.interaction.response_hash).toBe(sha256('Hello from Claude!'));
    expect(await receipts.verifyReceipt(receipt)).toBe(true);
  });

  it('extracts Google Gemini content', async () => {
    const receipts = new TrustReceipts();
    const { receipt } = await receipts.wrap(
      async () => ({
        candidates: [{ content: { parts: [{ text: 'Hello from Gemini!' }], role: 'model' } }],
      }),
      { sessionId: 'gemini', input: 'prompt' }
    );
    expect(receipt.interaction.response_hash).toBe(sha256('Hello from Gemini!'));
    expect(await receipts.verifyReceipt(receipt)).toBe(true);
  });

  it('honours a custom extractResponse', async () => {
    const receipts = new TrustReceipts();
    const { receipt } = await receipts.wrap(async () => ({ nested: { value: 'deep' } }), {
      sessionId: 'custom',
      input: 'prompt',
      extractResponse: (r: any) => r.nested.value,
    });
    expect(receipt.interaction.response_hash).toBe(sha256('deep'));
  });
});

describe('wrap() semantics', () => {
  it('returns the original response object unchanged', async () => {
    const receipts = new TrustReceipts();
    const original = { data: 'value', nested: { field: 123 } };
    const { response } = await receipts.wrap(async () => original, {
      sessionId: 's',
      input: 'prompt',
    });
    expect(response).toBe(original);
  });

  it('propagates errors from the wrapped function', async () => {
    const receipts = new TrustReceipts();
    await expect(
      receipts.wrap(
        async () => {
          throw new Error('API rate limit exceeded');
        },
        { sessionId: 's', input: 'prompt' }
      )
    ).rejects.toThrow('API rate limit exceeded');
  });

  it('handles null and undefined returns', async () => {
    const receipts = new TrustReceipts();
    const nullResult = await receipts.wrap(async () => null, { sessionId: 's', input: 'p' });
    expect(nullResult.response).toBeNull();
    expect(await receipts.verifyReceipt(nullResult.receipt)).toBe(true);
  });

  it('includeContent stores full prompt/response and still verifies', async () => {
    const receipts = new TrustReceipts();
    const { receipt } = await receipts.wrap(
      async () => ({ choices: [{ message: { content: 'Hi!' } }] }),
      { sessionId: 's', input: 'Hello!', includeContent: true }
    );
    expect(receipt.interaction.prompt).toBe('Hello!');
    expect(receipt.interaction.response).toBe('Hi!');
    expect(await receipts.verifyReceipt(receipt)).toBe(true);
  });
});

describe('manual receipts and fixed keys', () => {
  it('createReceipt produces a verifiable receipt', async () => {
    const { privateKey, publicKey } = await TrustReceipts.generateKeyPair();
    const receipts = new TrustReceipts({ privateKey, publicKey });

    const receipt = await receipts.createReceipt({
      sessionId: 'manual',
      prompt: 'Streaming prompt',
      response: 'Accumulated streaming response',
      agentId: 'claude-3',
      provider: 'anthropic',
      scores: { completeness: 0.9 },
    });

    expect(receipt.agent_did).toBe('did:sonate:claude-3');
    expect(await receipts.verifyReceipt(receipt, publicKey)).toBe(true);
    // Also verifies against the oracle with the same public key.
    const result = await verify(receipt as VerifyReceipt, publicKey);
    expect(result.valid).toBe(true);
  });

  it('a fixed private key produces a stable public key', async () => {
    const privateKey = '42'.repeat(32);
    const a = new TrustReceipts({ privateKey });
    const b = new TrustReceipts({ privateKey });
    expect(await a.getPublicKey()).toBe(await b.getPublicKey());
  });
});
