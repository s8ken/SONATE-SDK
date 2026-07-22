/**
 * Golden fixture generator for cross-language conformance.
 *
 * Produces deterministic SONATE v2.2.0 receipts using FIXED keys, FIXED
 * timestamps, and FIXED content, then writes them to `fixtures/*.json`.
 *
 * These fixtures are committed and serve two purposes:
 *  1. A TypeScript conformance test (`src/tests/fixtures.test.ts`) loads each
 *     one and verifies it with @sonate/verify-sdk.
 *  2. The Python SDK verifies the same bytes for true cross-language parity.
 *
 * Because everything is fixed (including the signing seed and timestamps),
 * re-running this script reproduces byte-identical receipts. Run with:
 *   npm run generate:fixtures  --workspace=@sonate/trust-receipts
 */

import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { getPublicKey, bytesToHex } from '../src/crypto';
import { TrustReceipt, TrustReceiptData } from '../src/trust-receipt';

// Deterministic 32-byte Ed25519 seed: 0x42 repeated.
const FIXED_SEED = new Uint8Array(32).fill(0x42);
const FIXED_TIMESTAMP = '2026-01-01T00:00:00.000Z';

interface FixtureSpec {
  name: string;
  description: string;
  data: TrustReceiptData;
}

const specs: FixtureSpec[] = [
  {
    name: 'genesis-hash-only',
    description: 'First receipt in a chain (GENESIS), hashes only, CIQ scores.',
    data: {
      sessionId: 'fixture-session-001',
      prompt: 'What is the capital of France?',
      response: 'The capital of France is Paris.',
      scores: { clarity: 0.95, integrity: 0.9, quality: 0.92 },
      agentId: 'gpt-4',
      provider: 'openai',
      mode: 'constitutional',
      timestamp: FIXED_TIMESTAMP,
    },
  },
  {
    name: 'full-content',
    description: 'Receipt with full prompt/response content included plus hashes.',
    data: {
      sessionId: 'fixture-session-002',
      prompt: 'Summarize the SONATE trust model in one sentence.',
      response: 'SONATE issues cryptographically signed, hash-chained receipts for AI interactions.',
      scores: { clarity: 0.88, integrity: 0.99, quality: 0.9, safety: 0.97 },
      agentId: 'claude-3-sonnet',
      provider: 'anthropic',
      mode: 'directive',
      policyVersion: 'policy_v1.2.0',
      includeContent: true,
      metadata: { tags: ['fixture', 'full-content'] },
      timestamp: FIXED_TIMESTAMP,
    },
  },
  {
    name: 'explicit-dids',
    description: 'Receipt built from explicit DIDs and custom telemetry.',
    data: {
      sessionId: 'fixture-session-003',
      prompt: 'ping',
      response: 'pong',
      agentDid: 'did:web:yseeku.com:agents:conformance',
      humanDid: 'did:web:yseeku.com:users:conformance',
      model: 'test-model',
      telemetry: { resonance_score: 0.81, overall_trust_score: 87 },
      timestamp: FIXED_TIMESTAMP,
    },
  },
];

async function main(): Promise<void> {
  const outDir = join(__dirname, '..', 'fixtures');
  mkdirSync(outDir, { recursive: true });

  const publicKey = bytesToHex(await getPublicKey(FIXED_SEED));

  // Standalone fixtures.
  for (const spec of specs) {
    const receipt = new TrustReceipt(spec.data);
    await receipt.sign(FIXED_SEED);
    const fixture = {
      description: spec.description,
      public_key: publicKey,
      receipt: receipt.toJSON(),
    };
    writeFileSync(join(outDir, `${spec.name}.json`), JSON.stringify(fixture, null, 2) + '\n');
    // eslint-disable-next-line no-console
    console.log(`wrote fixtures/${spec.name}.json`);
  }

  // A deterministic 3-receipt chain.
  const chain = [];
  let previous: TrustReceipt | null = null;
  for (let i = 1; i <= 3; i++) {
    const receipt = new TrustReceipt({
      sessionId: 'fixture-chain-session',
      prompt: `chain prompt ${i}`,
      response: `chain response ${i}`,
      scores: { clarity: 0.9, integrity: 0.9, quality: 0.9 },
      agentId: 'gpt-4',
      provider: 'openai',
      prevReceiptHash: previous?.chainHash,
      chainLength: i,
      timestamp: FIXED_TIMESTAMP,
    });
    await receipt.sign(FIXED_SEED);
    chain.push(receipt.toJSON());
    previous = receipt;
  }
  writeFileSync(
    join(outDir, 'chain.json'),
    JSON.stringify(
      {
        description: 'Deterministic 3-receipt hash chain (GENESIS -> 2 -> 3).',
        public_key: publicKey,
        receipts: chain,
      },
      null,
      2
    ) + '\n'
  );
  // eslint-disable-next-line no-console
  console.log('wrote fixtures/chain.json');
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
