/**
 * Conformance tests: every receipt this SDK produces must verify with the
 * official @sonate/verify-sdk (the normative oracle for the v2.2.0 format).
 *
 * Covers:
 *  - TrustReceipt (direct) and TrustReceipts.wrap() round-trips
 *  - GENESIS receipt
 *  - A 3-receipt hash chain with linkage
 *  - A tamper matrix: mutating any field makes verify() fail
 *  - fromJSON integrity check
 */

import { describe, it, expect } from 'vitest';
import { verify, type TrustReceipt as VerifyReceipt } from '@sonate/verify-sdk';

import { TrustReceipts } from '../wrapper';
import { TrustReceipt } from '../trust-receipt';
import { generateKeyPair, bytesToHex, getPublicKey } from '../crypto';

async function keys() {
  const { privateKey, publicKey } = await generateKeyPair();
  return { privateKey, publicKeyHex: bytesToHex(publicKey) };
}

describe('verify-sdk conformance', () => {
  it('a directly-built, signed receipt verifies (valid=true, all checks pass)', async () => {
    const { privateKey, publicKeyHex } = await keys();

    const receipt = new TrustReceipt({
      sessionId: 'conf-1',
      prompt: 'What is trust?',
      response: 'Trust is the foundation of reliable AI systems.',
      scores: { clarity: 0.9, integrity: 0.85, quality: 0.95 },
      agentId: 'gpt-4',
      provider: 'openai',
    });
    await receipt.sign(privateKey);

    const result = await verify(receipt.toJSON() as VerifyReceipt, publicKeyHex);
    expect(result.valid).toBe(true);
    expect(result.checks.structure.passed).toBe(true);
    expect(result.checks.hash.passed).toBe(true);
    expect(result.checks.signature.passed).toBe(true);
    expect(result.checks.chain.passed).toBe(true);
    expect(result.checks.timestamp.passed).toBe(true);
  });

  it('a GENESIS receipt verifies', async () => {
    const { privateKey, publicKeyHex } = await keys();
    const receipt = new TrustReceipt({
      sessionId: 'genesis',
      prompt: 'first',
      response: 'first response',
    });
    await receipt.sign(privateKey);

    const json = receipt.toJSON();
    expect(json.chain.previous_hash).toBe('GENESIS');
    const result = await verify(json as VerifyReceipt, publicKeyHex);
    expect(result.valid).toBe(true);
  });

  it('a receipt with full content (includeContent) verifies', async () => {
    const { privateKey, publicKeyHex } = await keys();
    const receipt = new TrustReceipt({
      sessionId: 'conf-content',
      prompt: 'public prompt',
      response: 'public response',
      includeContent: true,
    });
    await receipt.sign(privateKey);

    const json = receipt.toJSON();
    expect(json.interaction.prompt).toBe('public prompt');
    expect(json.interaction.response).toBe('public response');
    const result = await verify(json as VerifyReceipt, publicKeyHex);
    expect(result.valid).toBe(true);
  });

  it('every receipt produced by wrap() verifies', async () => {
    const receipts = new TrustReceipts();
    const publicKeyHex = await receipts.getPublicKey();

    const { receipt } = await receipts.wrap(
      async () => ({ choices: [{ message: { content: 'Hi there!' } }] }),
      { sessionId: 'wrap-conf', input: [{ role: 'user', content: 'Hello!' }], provider: 'openai' }
    );

    const result = await verify(receipt as VerifyReceipt, publicKeyHex);
    expect(result.valid).toBe(true);
  });

  it('a 3-receipt chain each verifies and links correctly', async () => {
    const receipts = new TrustReceipts();
    const publicKeyHex = await receipts.getPublicKey();

    const r1 = (await receipts.wrap(async () => 'a', { sessionId: 'chain', input: 'q1' })).receipt;
    const r2 = (
      await receipts.wrap(async () => 'b', { sessionId: 'chain', input: 'q2', previousReceipt: r1 })
    ).receipt;
    const r3 = (
      await receipts.wrap(async () => 'c', { sessionId: 'chain', input: 'q3', previousReceipt: r2 })
    ).receipt;

    // Linkage
    expect(r1.chain.previous_hash).toBe('GENESIS');
    expect(r2.chain.previous_hash).toBe(r1.chain.chain_hash);
    expect(r3.chain.previous_hash).toBe(r2.chain.chain_hash);
    expect(r3.chain.chain_length).toBe(3);

    // Each verifies with the oracle
    for (const r of [r1, r2, r3]) {
      const result = await verify(r as VerifyReceipt, publicKeyHex);
      expect(result.valid).toBe(true);
    }

    // Chain check via the SDK's own verifier
    const chainResult = await receipts.verifyChain([r1, r2, r3]);
    expect(chainResult.valid).toBe(true);
    expect(chainResult.errors).toEqual([]);
  });

  describe('tamper matrix (each mutation must fail verify)', () => {
    it('mutating any field breaks verification', async () => {
      const { privateKey, publicKeyHex } = await keys();
      const receipt = new TrustReceipt({
        sessionId: 'tamper',
        prompt: 'original prompt',
        response: 'original response',
        scores: { clarity: 0.9, integrity: 0.9, quality: 0.9, safety: 0.9 },
        agentId: 'gpt-4',
        provider: 'openai',
        metadata: { tags: ['a'] },
      });
      await receipt.sign(privateKey);
      const good = receipt.toJSON();

      // Sanity: unmutated verifies, and the fields the matrix mutates exist.
      expect((await verify(good as VerifyReceipt, publicKeyHex)).valid).toBe(true);
      expect(good.telemetry?.custom_scores?.safety).toBe(0.9);
      expect(good.interaction.provider).toBe('openai');
      expect(good.chain.chain_length).toBe(1);

      const mutations: Array<(r: any) => void> = [
        (r) => (r.session_id = 'hacked'),
        (r) => (r.agent_did = 'did:sonate:evil'),
        (r) => (r.human_did = 'did:sonate:evil'),
        (r) => (r.mode = r.mode === 'constitutional' ? 'directive' : 'constitutional'),
        (r) => (r.timestamp = new Date(Date.now() - 1000).toISOString()),
        (r) => (r.version = '2.0.0'),
        (r) => (r.interaction.prompt_hash = '0'.repeat(64)),
        (r) => (r.interaction.response_hash = '0'.repeat(64)),
        (r) => (r.interaction.model = 'evil-model'),
        (r) => (r.interaction.provider = 'anthropic'),
        (r) => (r.telemetry.ciq_metrics.clarity = 0.01),
        (r) => (r.telemetry.custom_scores.safety = 0.01),
        (r) => (r.metadata.tags = ['b']),
        (r) => (r.id = '0'.repeat(64)),
        (r) => (r.chain.previous_hash = 'f'.repeat(64)),
        (r) => (r.chain.chain_length = 99),
        (r) => (r.chain.chain_hash = 'a'.repeat(64)),
        (r) => (r.signature.value = 'ab'.repeat(64)),
      ];

      for (const mutate of mutations) {
        const tampered = JSON.parse(JSON.stringify(good));
        mutate(tampered);
        const result = await verify(tampered as VerifyReceipt, publicKeyHex);
        expect(result.valid, `mutation should fail: ${mutate.toString()}`).toBe(false);
      }
    });

    it('mutating unsigned signature-block fields does NOT invalidate (intentional blast radius)', async () => {
      // key_version and timestamp_signed live inside the signature block, which
      // is stripped before all hashing/signing (matching the platform reference).
      // They are therefore unsigned metadata: changing them must NOT flip a valid
      // receipt to invalid. This test documents that boundary on purpose.
      const { privateKey, publicKeyHex } = await keys();
      const receipt = new TrustReceipt({
        sessionId: 'blast-radius',
        prompt: 'p',
        response: 'r',
        agentId: 'gpt-4',
      });
      await receipt.sign(privateKey);
      const good = receipt.toJSON();
      expect((await verify(good as VerifyReceipt, publicKeyHex)).valid).toBe(true);

      const kvMutated = JSON.parse(JSON.stringify(good));
      kvMutated.signature.key_version = 'attacker-relabelled-key';
      expect((await verify(kvMutated as VerifyReceipt, publicKeyHex)).valid).toBe(true);

      const tsMutated = JSON.parse(JSON.stringify(good));
      tsMutated.signature.timestamp_signed = '1999-01-01T00:00:00.000Z';
      expect((await verify(tsMutated as VerifyReceipt, publicKeyHex)).valid).toBe(true);
    });
  });

  describe('fromJSON integrity', () => {
    it('accepts a genuine receipt and re-verifies', async () => {
      const { privateKey, publicKey } = await generateKeyPair();
      const receipt = new TrustReceipt({ sessionId: 'fj', prompt: 'p', response: 'r' });
      await receipt.sign(privateKey);

      const restored = TrustReceipt.fromJSON(receipt.toJSON());
      expect(await restored.verify(publicKey)).toBe(true);
    });

    it('rejects a receipt whose id does not match the payload', async () => {
      const { privateKey } = await generateKeyPair();
      const receipt = new TrustReceipt({ sessionId: 'fj2', prompt: 'p', response: 'r' });
      await receipt.sign(privateKey);

      const json = receipt.toJSON();
      json.id = '0'.repeat(64);
      expect(() => TrustReceipt.fromJSON(json)).toThrow(/id does not match/);
    });

    it('rejects a receipt with a missing/empty id (no silent skip)', async () => {
      const { privateKey } = await generateKeyPair();
      const receipt = new TrustReceipt({ sessionId: 'fj3', prompt: 'p', response: 'r' });
      await receipt.sign(privateKey);

      const json = receipt.toJSON();
      delete (json as any).id;
      expect(() => TrustReceipt.fromJSON(json)).toThrow(/missing id/);

      const emptyId = receipt.toJSON();
      (emptyId as any).id = '';
      expect(() => TrustReceipt.fromJSON(emptyId)).toThrow(/missing id/);
    });
  });
});
