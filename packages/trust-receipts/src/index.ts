/**
 * @sonate/trust-receipts
 *
 * SSL/TLS for AI — cryptographically sign and verify every interaction.
 *
 * Trust Receipts create verifiable audit trails for AI interactions:
 * - Hash prompt and response content (RFC 8785 canonicalization)
 * - Chain receipts with cryptographic links
 * - Sign with Ed25519 for non-repudiation
 * - Track attestation scores
 *
 * @example
 * ```typescript
 * import { TrustReceipts } from '@sonate/trust-receipts';
 * import OpenAI from 'openai';
 *
 * const receipts = new TrustReceipts({
 *   privateKey: process.env.SONATE_PRIVATE_KEY,
 * });
 *
 * const openai = new OpenAI();
 * const messages = [{ role: 'user', content: 'Hello!' }];
 *
 * const { response, receipt } = await receipts.wrap(
 *   () => openai.chat.completions.create({ model: 'gpt-4', messages }),
 *   { sessionId: 'user-123', input: messages, provider: 'openai' }
 * );
 *
 * // receipt.id = SHA-256 of the canonical receipt content
 * // receipt.interaction.prompt_hash / response_hash = SHA-256 hashes
 * // receipt.signature.value = Ed25519 signature (hex)
 * // receipt verifies with @sonate/verify-sdk's verify()
 * ```
 *
 * @packageDocumentation
 */

// Main wrapper class
export { TrustReceipts } from './wrapper';
export type {
  TrustReceiptsConfig,
  WrapOptions,
  CreateReceiptOptions,
  WrappedResponse,
} from './wrapper';

// Trust Receipt class and types
export { TrustReceipt, computeReceiptId, computeChainHash } from './trust-receipt';
export type {
  TrustReceiptData,
  SonateReceipt,
  SignedReceipt,
  Scores,
  // Backwards compatibility
  QualityMetrics,
} from './trust-receipt';

// Cryptographic utilities
export {
  generateKeyPair,
  sign,
  verify,
  getPublicKey,
  sha256,
  bytesToHex,
  hexToBytes,
  canonicalize,
} from './crypto';

// Anchoring (OpenTimestamps)
export {
  anchor,
  upgradeAnchor,
  verifyAnchor,
  anchorChain,
} from './anchor';
export type { AnchorProof } from './anchor';
