/**
 * Unit tests for the TrustReceipt building blocks and legacy-input mapping.
 */

import { describe, it, expect } from 'vitest';
import {
  TrustReceipts,
  TrustReceipt,
  generateKeyPair,
  bytesToHex,
  hexToBytes,
} from '../index';

describe('key generation', () => {
  it('generateKeyPair creates 32-byte keys', async () => {
    const { privateKey, publicKey } = await generateKeyPair();
    expect(privateKey.length).toBe(32);
    expect(publicKey.length).toBe(32);
  });

  it('TrustReceipts.generateKeyPair returns 64-char hex strings', async () => {
    const { privateKey, publicKey } = await TrustReceipts.generateKeyPair();
    expect(privateKey).toMatch(/^[0-9a-f]{64}$/);
    expect(publicKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('bytesToHex/hexToBytes round-trip', () => {
    const original = new Uint8Array([0, 1, 127, 128, 255]);
    expect(hexToBytes(bytesToHex(original))).toEqual(original);
  });
});

describe('Ed25519 key-length validation', () => {
  it('TrustReceipt.sign rejects a non-32-byte seed with a clear error', async () => {
    const receipt = new TrustReceipt({ sessionId: 's', prompt: 'p', response: 'r' });
    // 64-byte tweetnacl secretKey (seed + public key) is a common migration mistake.
    await expect(receipt.sign(new Uint8Array(64))).rejects.toThrow(
      /Expected 32-byte Ed25519 private key seed, received 64 bytes/
    );
  });

  it('TrustReceipts rejects a non-32-byte private key seed', async () => {
    const receipts = new TrustReceipts({ privateKey: '42'.repeat(64) }); // 64 bytes hex
    await expect(receipts.getPublicKey()).rejects.toThrow(
      /Expected 32-byte Ed25519 private key seed, received 64 bytes/
    );
  });

  it('TrustReceipts rejects a non-32-byte public key', async () => {
    const { privateKey } = await TrustReceipts.generateKeyPair();
    const receipts = new TrustReceipts({ privateKey, publicKey: 'ab'.repeat(16) }); // 16 bytes
    await expect(receipts.getPublicKey()).rejects.toThrow(
      /Expected 32-byte Ed25519 public key, received 16 bytes/
    );
  });
});

describe('legacy input mapping to v2.2.0', () => {
  it('maps sessionId, agentId, and scores onto the wire format', async () => {
    const { privateKey } = await generateKeyPair();
    const receipt = new TrustReceipt({
      sessionId: 'sess-legacy',
      prompt: 'q',
      response: 'a',
      agentId: 'gpt-4',
      provider: 'openai',
      scores: { clarity: 0.9, integrity: 0.8, quality: 0.7, safety: 0.95 },
    });
    await receipt.sign(privateKey);
    const json = receipt.toJSON();

    expect(json.version).toBe('2.2.0');
    expect(json.session_id).toBe('sess-legacy');
    expect(json.agent_did).toBe('did:sonate:gpt-4');
    expect(json.human_did).toBe('did:sonate:anonymous');
    expect(json.interaction.model).toBe('gpt-4');
    expect(json.interaction.provider).toBe('openai');
    // clarity/integrity/quality -> ciq_metrics; everything else -> custom_scores
    expect(json.telemetry?.ciq_metrics).toEqual({ clarity: 0.9, integrity: 0.8, quality: 0.7 });
    expect(json.telemetry?.custom_scores).toEqual({ safety: 0.95 });
  });

  it('passes through existing DIDs unchanged and honours explicit DIDs', async () => {
    const { privateKey } = await generateKeyPair();
    const receipt = new TrustReceipt({
      sessionId: 's',
      prompt: 'q',
      response: 'a',
      agentId: 'did:web:example.com:agent',
      humanDid: 'did:web:example.com:human',
    });
    await receipt.sign(privateKey);
    const json = receipt.toJSON();
    expect(json.agent_did).toBe('did:web:example.com:agent');
    expect(json.human_did).toBe('did:web:example.com:human');
  });

  it('hash-only by default: no plaintext content in interaction', async () => {
    const { privateKey } = await generateKeyPair();
    const receipt = new TrustReceipt({
      sessionId: 's',
      prompt: 'secret prompt',
      response: 'secret response',
    });
    await receipt.sign(privateKey);
    const json = receipt.toJSON();
    expect(json.interaction.prompt).toBeUndefined();
    expect(json.interaction.response).toBeUndefined();
    expect(json.interaction.prompt_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(json.interaction.response_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('defaults mode to constitutional and honours an override', async () => {
    const { privateKey } = await generateKeyPair();
    const a = new TrustReceipt({ sessionId: 's', prompt: 'q', response: 'a' });
    await a.sign(privateKey);
    expect(a.toJSON().mode).toBe('constitutional');

    const b = new TrustReceipt({ sessionId: 's', prompt: 'q', response: 'a', mode: 'directive' });
    await b.sign(privateKey);
    expect(b.toJSON().mode).toBe('directive');
  });
});

describe('TrustReceipt.verify (local)', () => {
  it('valid signature verifies, wrong key fails', async () => {
    const { privateKey, publicKey } = await generateKeyPair();
    const { publicKey: otherPub } = await generateKeyPair();

    const receipt = new TrustReceipt({ sessionId: 's', prompt: 'q', response: 'a' });
    await receipt.sign(privateKey);

    expect(await receipt.verify(publicKey)).toBe(true);
    expect(await receipt.verify(otherPub)).toBe(false);
  });

  it('unsigned receipt cannot be serialized', async () => {
    const receipt = new TrustReceipt({ sessionId: 's', prompt: 'q', response: 'a' });
    expect(receipt.isSigned).toBe(false);
    expect(() => receipt.toJSON()).toThrow(/not signed/);
  });

  it('verifyChain links this.previous_hash to the prior chain_hash', async () => {
    const { privateKey } = await generateKeyPair();
    const r1 = new TrustReceipt({ sessionId: 's', prompt: 'q1', response: 'a1' });
    await r1.sign(privateKey);
    const r2 = new TrustReceipt({
      sessionId: 's',
      prompt: 'q2',
      response: 'a2',
      prevReceiptHash: r1.chainHash,
    });
    await r2.sign(privateKey);

    expect(r2.verifyChain(r1)).toBe(true);
    expect(r2.verifyChain(r1.toJSON())).toBe(true);
  });
});

describe('deterministic hashing', () => {
  it('identical content yields identical prompt/response hashes', async () => {
    const { privateKey } = await generateKeyPair();
    const make = () =>
      new TrustReceipt({
        sessionId: 's',
        prompt: { messages: [{ role: 'user', content: 'Hello' }] },
        response: 'Hi there!',
        timestamp: '2026-01-01T00:00:00.000Z',
      });
    const a = make();
    const b = make();
    await a.sign(privateKey);
    await b.sign(privateKey);
    expect(a.toJSON().interaction.prompt_hash).toBe(b.toJSON().interaction.prompt_hash);
    expect(a.toJSON().interaction.response_hash).toBe(b.toJSON().interaction.response_hash);
    // Fully deterministic inputs (fixed timestamp) -> identical id.
    expect(a.id).toBe(b.id);
  });
});
