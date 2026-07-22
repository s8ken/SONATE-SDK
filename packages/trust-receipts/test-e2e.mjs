/**
 * End-to-end test for @sonate/trust-receipts (SONATE v2.2.0)
 * Verifies the package works correctly without any external dependencies.
 */

import { TrustReceipts, generateKeyPair, sha256, bytesToHex } from './dist/index.js';

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ✗ ${name}: ${err.message}`);
    failed++;
  }
}

async function run() {
  console.log('\n@sonate/trust-receipts — End-to-End Verification (v2.2.0)\n');

  // 1. Key generation
  console.log('1. Key Generation');
  let keyPair;
  await test('generateKeyPair() returns privateKey and publicKey Uint8Arrays', async () => {
    keyPair = await generateKeyPair();
    if (!keyPair.privateKey) throw new Error('Missing privateKey');
    if (!keyPair.publicKey) throw new Error('Missing publicKey');
    if (keyPair.privateKey.length !== 32) throw new Error(`privateKey should be 32 bytes, got ${keyPair.privateKey.length}`);
    if (keyPair.publicKey.length !== 32) throw new Error(`publicKey should be 32 bytes, got ${keyPair.publicKey.length}`);
  });

  await test('bytesToHex() converts Uint8Array keys to hex strings', async () => {
    const privHex = bytesToHex(keyPair.privateKey);
    const pubHex = bytesToHex(keyPair.publicKey);
    if (privHex.length !== 64) throw new Error(`Expected 64-char hex, got ${privHex.length}`);
    if (pubHex.length !== 64) throw new Error(`Expected 64-char hex, got ${pubHex.length}`);
    if (!/^[0-9a-f]+$/.test(privHex)) throw new Error('Not valid hex');
  });

  // 2. TrustReceipts instantiation
  console.log('\n2. TrustReceipts Instantiation');
  let receipts;
  await test('new TrustReceipts({ privateKey: Uint8Array }) succeeds', async () => {
    receipts = new TrustReceipts({ privateKey: keyPair.privateKey });
    if (!receipts) throw new Error('Failed to instantiate');
  });

  await test('new TrustReceipts({ privateKey: hexString }) succeeds', async () => {
    const hexKey = bytesToHex(keyPair.privateKey);
    const r = new TrustReceipts({ privateKey: hexKey });
    if (!r) throw new Error('Failed to instantiate with hex key');
  });

  await test('new TrustReceipts() with auto-generated key succeeds', async () => {
    const r = new TrustReceipts();
    if (!r) throw new Error('Failed to instantiate without key');
  });

  // 3. Receipt creation via wrap()
  console.log('\n3. Receipt Creation (wrap)');
  let firstReceipt;
  await test('wrap() with mock AI call returns response + receipt', async () => {
    const mockAICall = async () => ({
      choices: [{ message: { content: 'Hello! I am an AI assistant.' } }]
    });

    const result = await receipts.wrap(mockAICall, {
      sessionId: 'test-session-001',
      input: [{ role: 'user', content: 'Hello!' }],
      agentId: 'gpt-4-test',
      provider: 'openai',
    });

    if (!result.response) throw new Error('Missing response');
    if (!result.receipt) throw new Error('Missing receipt');
    firstReceipt = result.receipt;
  });

  await test('receipt is a v2.2.0 receipt with the required fields', () => {
    if (firstReceipt.version !== '2.2.0') throw new Error(`Expected version 2.2.0, got ${firstReceipt.version}`);
    if (!firstReceipt.id) throw new Error('Missing receipt.id');
    if (!firstReceipt.timestamp) throw new Error('Missing receipt.timestamp');
    if (!firstReceipt.session_id) throw new Error('Missing receipt.session_id');
    if (!firstReceipt.agent_did) throw new Error('Missing receipt.agent_did');
    if (!firstReceipt.interaction) throw new Error('Missing receipt.interaction');
    if (!firstReceipt.interaction.prompt_hash) throw new Error('Missing receipt.interaction.prompt_hash');
    if (!firstReceipt.interaction.response_hash) throw new Error('Missing receipt.interaction.response_hash');
    if (!firstReceipt.chain) throw new Error('Missing receipt.chain');
    if (!firstReceipt.signature?.value) throw new Error('Missing receipt.signature.value');
  });

  await test('receipt.id is a 64-char hex string (SHA-256)', () => {
    if (firstReceipt.id.length !== 64) throw new Error(`Expected 64 chars, got ${firstReceipt.id.length}`);
    if (!/^[0-9a-f]+$/.test(firstReceipt.id)) throw new Error('Not a valid hex string');
  });

  await test('receipt.signature.value is an Ed25519 signature (128-char hex)', () => {
    const sig = firstReceipt.signature.value;
    if (sig.length !== 128) throw new Error(`Expected 128 chars, got ${sig.length}`);
    if (!/^[0-9a-f]+$/.test(sig)) throw new Error('Not a valid hex string');
    if (firstReceipt.signature.algorithm !== 'Ed25519') throw new Error('Expected Ed25519 algorithm');
  });

  await test('interaction.prompt_hash and response_hash are 64-char SHA-256 hashes', () => {
    const { prompt_hash, response_hash } = firstReceipt.interaction;
    if (prompt_hash.length !== 64) throw new Error(`prompt_hash: expected 64 chars, got ${prompt_hash.length}`);
    if (response_hash.length !== 64) throw new Error(`response_hash: expected 64 chars, got ${response_hash.length}`);
  });

  await test('first receipt is GENESIS (chain.previous_hash === "GENESIS")', () => {
    if (firstReceipt.chain.previous_hash !== 'GENESIS') {
      throw new Error(`Expected GENESIS previous_hash, got ${firstReceipt.chain.previous_hash}`);
    }
    if (!firstReceipt.chain.chain_hash) throw new Error('Missing chain.chain_hash');
  });

  await test('first receipt verifies with its public key', async () => {
    const valid = await receipts.verifyReceipt(firstReceipt);
    if (!valid) throw new Error('First receipt failed verification');
  });

  // 4. Hash chaining
  console.log('\n4. Hash Chaining');
  let secondReceipt;
  await test('second receipt chains to first via chain.previous_hash', async () => {
    const mockAICall2 = async () => ({
      choices: [{ message: { content: 'The capital of France is Paris.' } }]
    });

    const result2 = await receipts.wrap(mockAICall2, {
      sessionId: 'test-session-001',
      input: [{ role: 'user', content: 'What is the capital of France?' }],
      agentId: 'gpt-4-test',
      provider: 'openai',
      previousReceipt: firstReceipt,
    });

    secondReceipt = result2.receipt;
    if (!secondReceipt.chain.previous_hash) throw new Error('Missing previous_hash on second receipt');
    if (secondReceipt.chain.previous_hash !== firstReceipt.chain.chain_hash) {
      throw new Error(`Chain broken: expected ${firstReceipt.chain.chain_hash.substring(0,16)}... got ${secondReceipt.chain.previous_hash.substring(0,16)}...`);
    }
  });

  await test('chain is immutable — different inputs produce different hashes', () => {
    if (firstReceipt.id === secondReceipt.id) throw new Error('Receipts should have different ids');
    if (firstReceipt.interaction.prompt_hash === secondReceipt.interaction.prompt_hash) throw new Error('Different prompts should have different hashes');
    if (firstReceipt.interaction.response_hash === secondReceipt.interaction.response_hash) throw new Error('Different responses should have different hashes');
  });

  await test('chain verifies via verifyChain([first, second])', async () => {
    const result = await receipts.verifyChain([firstReceipt, secondReceipt]);
    if (!result.valid) throw new Error(`Chain invalid: ${result.errors.join(', ')}`);
  });

  // 5. Manual receipt creation
  console.log('\n5. Manual Receipt Creation');
  await test('createReceipt() works without wrapping an AI call', async () => {
    const receipt = await receipts.createReceipt({
      sessionId: 'manual-session-001',
      prompt: 'What is 2+2?',
      response: '4',
      agentId: 'manual-agent',
    });
    if (!receipt.id) throw new Error('Missing receipt.id');
    if (!receipt.signature?.value) throw new Error('Missing receipt.signature.value');
    if (!receipt.interaction.prompt_hash) throw new Error('Missing receipt.interaction.prompt_hash');
    if (!(await receipts.verifyReceipt(receipt))) throw new Error('Manual receipt failed verification');
  });

  // 6. SHA-256 utility
  console.log('\n6. Cryptographic Utilities');
  await test('sha256() produces consistent 64-char hex hashes', async () => {
    const hash1 = await sha256('hello world');
    const hash2 = await sha256('hello world');
    const hash3 = await sha256('different input');
    if (hash1 !== hash2) throw new Error('Same input should produce same hash');
    if (hash1 === hash3) throw new Error('Different inputs should produce different hashes');
    if (hash1.length !== 64) throw new Error(`Expected 64 chars, got ${hash1.length}`);
    if (!/^[0-9a-f]+$/.test(hash1)) throw new Error('Not valid hex output');
  });

  // 7. JSON serialization
  console.log('\n7. JSON Serialization');
  await test('receipt serializes to valid JSON and back', () => {
    const json = JSON.stringify(firstReceipt);
    const parsed = JSON.parse(json);
    if (parsed.id !== firstReceipt.id) throw new Error('id mismatch after serialization');
    if (parsed.signature.value !== firstReceipt.signature.value) throw new Error('Signature mismatch after serialization');
    if (parsed.interaction.prompt_hash !== firstReceipt.interaction.prompt_hash) throw new Error('prompt_hash mismatch after serialization');
  });

  await test('receipt JSON contains all required v2.2.0 fields', () => {
    const json = JSON.parse(JSON.stringify(firstReceipt));
    const required = ['id', 'version', 'timestamp', 'session_id', 'agent_did', 'human_did', 'mode', 'interaction', 'chain', 'signature'];
    for (const field of required) {
      if (json[field] === undefined) throw new Error(`Missing field in JSON: ${field}`);
    }
    if (json.interaction.prompt_hash === undefined) throw new Error('Missing interaction.prompt_hash');
    if (json.interaction.response_hash === undefined) throw new Error('Missing interaction.response_hash');
    if (json.chain.previous_hash === undefined) throw new Error('Missing chain.previous_hash');
    if (json.chain.chain_hash === undefined) throw new Error('Missing chain.chain_hash');
    if (json.signature.value === undefined) throw new Error('Missing signature.value');
  });

  // Summary
  console.log(`\n${'─'.repeat(55)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed === 0) {
    console.log('✅ All checks passed — package is working correctly\n');
    console.log('Field Reference (SONATE v2.2.0 receipt):');
    console.log('─'.repeat(55));
    console.log('  receipt.id                       — SHA-256 receipt id');
    console.log('  receipt.interaction.prompt_hash  — SHA-256 hash of the prompt');
    console.log('  receipt.interaction.response_hash— SHA-256 hash of the AI response');
    console.log('  receipt.chain.previous_hash      — prior chain_hash ("GENESIS" if first)');
    console.log('  receipt.chain.chain_hash         — this receipt\'s chain hash');
    console.log('  receipt.signature.value          — Ed25519 signature (128-char hex)');
    console.log('  receipt.session_id               — session identifier');
    console.log('  receipt.agent_did                — agent DID');
    console.log('  receipt.timestamp                — ISO 8601 timestamp');
    console.log('  receipt.version                  — "2.2.0"');
    console.log('\nQuick integration example:');
    console.log('─'.repeat(55));
    console.log(`
import { TrustReceipts } from '@sonate/trust-receipts';
import { verify } from '@sonate/verify-sdk';
import OpenAI from 'openai';

const receipts = new TrustReceipts({
  privateKey: process.env.SONATE_PRIVATE_KEY,
});

const openai = new OpenAI();
const messages = [{ role: 'user', content: 'Hello!' }];

const { response, receipt } = await receipts.wrap(
  () => openai.chat.completions.create({ model: 'gpt-4', messages }),
  { sessionId: 'user-123', input: messages, provider: 'openai' }
);

console.log('Receipt id:', receipt.id);
console.log('Signature:', receipt.signature.value);

// Verifies with the official verifier:
const result = await verify(receipt, await receipts.getPublicKey());
console.log('Valid:', result.valid);
`);
  } else {
    console.log('❌ Some checks failed — review output above\n');
    process.exit(1);
  }
}

run().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
