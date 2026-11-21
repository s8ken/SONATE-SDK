/**
 * Sign two chained receipts with @sonate/trust-receipts, then verify them
 * independently with @sonate/verify-sdk. Runs offline: no API keys, no network.
 *
 *   npm install && npm run build && npm run example
 */
import { TrustReceipts } from '@sonate/trust-receipts';
import { verify } from '@sonate/verify-sdk';

const show = (label, result) => {
  const checks = Object.entries(result.checks)
    .map(([name, c]) => `${c.passed ? '✓' : '✗'} ${name}`)
    .join('  ');
  console.log(`${result.valid ? 'VALID  ' : 'INVALID'}  ${label}\n         ${checks}`);
};

// 1. The producer holds an Ed25519 key. Only the public half is shared.
const { privateKey, publicKey } = await TrustReceipts.generateKeyPair();
const producer = new TrustReceipts({ privateKey, defaultAgentId: 'refund-agent' });

// 2. Sign a receipt for each decision. By default only SHA-256 hashes of the
//    prompt and response go into the receipt, not the text itself.
const first = await producer.createReceipt({
  sessionId: 'session-42',
  prompt: 'Customer asks for a $40 refund on order #1042.',
  response: 'Approved: under the $50 auto-approve limit.',
  model: 'example-model',
});
const second = await producer.createReceipt({
  sessionId: 'session-42',
  prompt: 'Customer asks for a $900 refund on order #1043.',
  response: 'Escalated to a human: over the $50 auto-approve limit.',
  model: 'example-model',
  previousReceipt: first, // hash-chains this receipt to the previous one
});

console.log(`receipt 1  id ${first.id.slice(0, 16)}…  chain ${first.chain.previous_hash}`);
console.log(`receipt 2  id ${second.id.slice(0, 16)}…  chain ← ${second.chain.previous_hash.slice(0, 16)}…\n`);

// 3. Anyone with the public key can verify, using a separate package.
show('receipt 1', await verify(first, publicKey));
show('receipt 2', await verify(second, publicKey));
console.log(
  `         chain link: ${second.chain.previous_hash === first.chain.chain_hash ? '✓' : '✗'} receipt 2 points at receipt 1\n`
);

// 4. Change one field after signing: verification fails.
const tampered = structuredClone(second);
tampered.interaction.response_hash = 'f'.repeat(64);
show('receipt 2, response hash edited after signing', await verify(tampered, publicKey));

// 5. A different key cannot vouch for these receipts.
const { publicKey: otherKey } = await TrustReceipts.generateKeyPair();
show('receipt 1, checked against the wrong public key', await verify(first, otherKey));
