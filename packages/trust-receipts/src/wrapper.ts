/**
 * TrustReceipts Wrapper - SSL for AI
 *
 * Wrap any AI API call to automatically generate cryptographic audit trails.
 * Works with OpenAI, Anthropic, Gemini, or any async function. Produces
 * SONATE v2.2.0 receipts that verify with @sonate/verify-sdk.
 */

import { TrustReceipt, TrustReceiptData, SonateReceipt, Scores } from './trust-receipt';
import { generateKeyPair, hexToBytes, bytesToHex, getPublicKey, assertEd25519Seed } from './crypto';

/**
 * Configuration for TrustReceipts
 */
export interface TrustReceiptsConfig {
  /** Ed25519 private key (hex string or 32-byte Uint8Array) */
  privateKey?: string | Uint8Array;
  /** Ed25519 public key (hex string or Uint8Array) - derived from private if not provided */
  publicKey?: string | Uint8Array;
  /** Default agent/model identifier -> `agent_did` + `interaction.model` */
  defaultAgentId?: string;
  /** Default human identifier -> `human_did` */
  defaultHumanId?: string;
  /** Key version label recorded in `signature.key_version` (default: `key_v1`) */
  keyVersion?: string;
  /** Custom scores calculator */
  calculateScores?: (prompt: unknown, response: unknown) => Scores;
}

/**
 * Options for wrapping an AI call
 */
export interface WrapOptions<TInput = unknown> {
  /** Session identifier for this interaction */
  sessionId: string;
  /** The prompt/input being sent to the AI */
  input: TInput;
  /** Agent/model identifier (overrides default) -> `agent_did` + `interaction.model` */
  agentId?: string;
  /** Human identifier (overrides default) -> `human_did` */
  humanId?: string;
  /** Model identifier -> `interaction.model` (defaults to `agentId`) */
  model?: string;
  /** Provider -> `interaction.provider` (e.g. 'openai', 'anthropic') */
  provider?: string;
  /** Governance mode (default: 'constitutional') */
  mode?: 'constitutional' | 'directive';
  /** Previous receipt for hash chaining */
  previousReceipt?: SonateReceipt;
  /** Custom metadata to include */
  metadata?: Record<string, unknown>;
  /** Attestation scores (if not using calculator) */
  scores?: Scores;
  /** Custom response extractor for hashing */
  extractResponse?: (response: unknown) => unknown;
  /** Include full prompt/response content in receipt (default: false, hashes only) */
  includeContent?: boolean;
}

/**
 * Options for creating a receipt manually
 */
export interface CreateReceiptOptions {
  /** Session identifier */
  sessionId: string;
  /** The prompt/input */
  prompt: unknown;
  /** The response/output */
  response: unknown;
  /** Agent/model identifier */
  agentId?: string;
  /** Human identifier -> `human_did` */
  humanId?: string;
  /** Model identifier -> `interaction.model` */
  model?: string;
  /** Provider -> `interaction.provider` */
  provider?: string;
  /** Governance mode (default: 'constitutional') */
  mode?: 'constitutional' | 'directive';
  /** Previous receipt for hash chaining */
  previousReceipt?: SonateReceipt;
  /** Custom metadata */
  metadata?: Record<string, unknown>;
  /** Attestation scores */
  scores?: Scores;
  /** Include full prompt/response content in receipt (default: false, hashes only) */
  includeContent?: boolean;
}

/**
 * Result from a wrapped AI call
 */
export interface WrappedResponse<T> {
  /** The original response from the AI call */
  response: T;
  /** The signed SONATE v2.2.0 trust receipt */
  receipt: SonateReceipt;
}

/**
 * Extract text content from common AI response formats
 * (OpenAI, Anthropic, Google Gemini).
 */
function extractResponseContent(response: unknown): unknown {
  if (!response || typeof response !== 'object') {
    return response;
  }

  const r = response as Record<string, any>;

  // OpenAI format: { choices: [{ message: { content: "..." } }] }
  if (Array.isArray(r.choices) && r.choices[0]?.message?.content) {
    return r.choices[0].message.content;
  }

  // Anthropic format: { content: [{ text: "..." }] }
  if (Array.isArray(r.content) && r.content[0]?.text) {
    return r.content[0].text;
  }

  // Google Gemini format: { candidates: [{ content: { parts: [{ text: "..." }] } }] }
  if (Array.isArray(r.candidates) && r.candidates[0]?.content?.parts?.[0]?.text) {
    return r.candidates[0].content.parts[0].text;
  }

  // Fallback: return as-is
  return response;
}

/**
 * TrustReceipts - Main SDK class
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
 * console.log(response.choices[0].message.content);
 * console.log('Receipt id:', receipt.id);
 * ```
 */
export class TrustReceipts {
  private privateKey: Uint8Array;
  private publicKey: Uint8Array;
  private defaultAgentId?: string;
  private defaultHumanId?: string;
  private keyVersion?: string;
  private calculateScores?: (prompt: unknown, response: unknown) => Scores;
  private initialized: Promise<void>;

  constructor(config: TrustReceiptsConfig = {}) {
    this.defaultAgentId = config.defaultAgentId;
    this.defaultHumanId = config.defaultHumanId;
    this.keyVersion = config.keyVersion;
    this.calculateScores = config.calculateScores;

    // Initialize keys (may be async)
    this.privateKey = new Uint8Array(32);
    this.publicKey = new Uint8Array(32);

    this.initialized = this.initializeKeys(config);
  }

  /**
   * Initialize cryptographic keys
   */
  private async initializeKeys(config: TrustReceiptsConfig): Promise<void> {
    if (config.privateKey) {
      // Use provided private key (32-byte Ed25519 seed)
      this.privateKey =
        typeof config.privateKey === 'string'
          ? hexToBytes(config.privateKey)
          : config.privateKey;
      assertEd25519Seed(this.privateKey);

      // Derive or use provided public key
      if (config.publicKey) {
        this.publicKey =
          typeof config.publicKey === 'string'
            ? hexToBytes(config.publicKey)
            : config.publicKey;
        if (this.publicKey.length !== 32) {
          throw new Error(
            `Expected 32-byte Ed25519 public key, received ${this.publicKey.length} bytes`
          );
        }
      } else {
        this.publicKey = await getPublicKey(this.privateKey);
      }
    } else {
      // Generate new key pair
      const keyPair = await generateKeyPair();
      this.privateKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
    }
  }

  /**
   * Wrap an async AI call with trust receipt generation
   *
   * @param fn - Async function that calls the AI API
   * @param options - Configuration for this specific call
   * @returns The AI response and a signed SONATE v2.2.0 trust receipt
   */
  async wrap<T>(fn: () => Promise<T>, options: WrapOptions): Promise<WrappedResponse<T>> {
    // Ensure keys are ready
    await this.initialized;

    // Execute the AI call
    const response = await fn();

    // Extract response content for hashing
    const responseContent = options.extractResponse
      ? options.extractResponse(response)
      : extractResponseContent(response);

    // Calculate scores
    const scores =
      options.scores ?? this.calculateScores?.(options.input, responseContent) ?? undefined;

    const receipt = new TrustReceipt(
      this.buildReceiptData({
        sessionId: options.sessionId,
        prompt: options.input,
        response: responseContent,
        scores,
        agentId: options.agentId,
        humanId: options.humanId,
        model: options.model,
        provider: options.provider,
        mode: options.mode,
        previousReceipt: options.previousReceipt,
        metadata: options.metadata,
        includeContent: options.includeContent,
      })
    );
    await receipt.sign(this.privateKey);

    return {
      response,
      receipt: receipt.toJSON(),
    };
  }

  /**
   * Create a receipt manually (without wrapping a call).
   *
   * Useful for streaming responses or custom scenarios.
   *
   * @param options - Receipt options
   * @returns Signed SONATE v2.2.0 trust receipt
   */
  async createReceipt(options: CreateReceiptOptions): Promise<SonateReceipt> {
    await this.initialized;

    const receipt = new TrustReceipt(
      this.buildReceiptData({
        sessionId: options.sessionId,
        prompt: options.prompt,
        response: options.response,
        scores: options.scores,
        agentId: options.agentId,
        humanId: options.humanId,
        model: options.model,
        provider: options.provider,
        mode: options.mode,
        previousReceipt: options.previousReceipt,
        metadata: options.metadata,
        includeContent: options.includeContent,
      })
    );
    await receipt.sign(this.privateKey);

    return receipt.toJSON();
  }

  /** Assemble TrustReceiptData from wrap/create options and instance defaults. */
  private buildReceiptData(opts: {
    sessionId: string;
    prompt: unknown;
    response: unknown;
    scores?: Scores;
    agentId?: string;
    humanId?: string;
    model?: string;
    provider?: string;
    mode?: 'constitutional' | 'directive';
    previousReceipt?: SonateReceipt;
    metadata?: Record<string, unknown>;
    includeContent?: boolean;
  }): TrustReceiptData {
    const agentId = opts.agentId ?? this.defaultAgentId;
    return {
      sessionId: opts.sessionId,
      prompt: opts.prompt,
      response: opts.response,
      scores: opts.scores,
      agentId,
      humanId: opts.humanId ?? this.defaultHumanId,
      model: opts.model ?? agentId,
      provider: opts.provider,
      mode: opts.mode,
      prevReceiptHash: opts.previousReceipt?.chain?.chain_hash,
      chainLength: opts.previousReceipt?.chain?.chain_length
        ? opts.previousReceipt.chain.chain_length + 1
        : undefined,
      metadata: opts.metadata,
      includeContent: opts.includeContent,
      keyVersion: this.keyVersion,
    };
  }

  /**
   * Verify a receipt's signature and integrity.
   *
   * @param receipt - Receipt to verify
   * @param publicKey - Optional public key (uses instance key if not provided)
   * @returns true if the receipt is intact and the signature is valid
   */
  async verifyReceipt(receipt: SonateReceipt, publicKey?: string | Uint8Array): Promise<boolean> {
    await this.initialized;

    const trustReceipt = TrustReceipt.fromJSON(receipt);
    const key = publicKey
      ? typeof publicKey === 'string'
        ? hexToBytes(publicKey)
        : publicKey
      : this.publicKey;

    return trustReceipt.verify(key);
  }

  /**
   * Verify a chain of receipts (signatures + linkage).
   *
   * @param receipts - Array of receipts in chronological order
   * @param publicKey - Optional public key for signature verification
   * @returns Object with validity status and any errors
   */
  async verifyChain(
    receipts: SonateReceipt[],
    publicKey?: string | Uint8Array
  ): Promise<{ valid: boolean; errors: string[] }> {
    await this.initialized;

    const errors: string[] = [];

    if (receipts.length === 0) {
      return { valid: true, errors: [] };
    }

    for (let i = 0; i < receipts.length; i++) {
      const current = receipts[i];

      // Verify signature + integrity
      const sigValid = await this.verifyReceipt(current, publicKey);
      if (!sigValid) {
        errors.push(`Receipt ${i}: Invalid signature`);
      }

      // Verify chain linkage (skip first receipt)
      if (i > 0) {
        const previous = receipts[i - 1];
        if (current.chain?.previous_hash !== previous.chain?.chain_hash) {
          errors.push(`Receipt ${i}: Chain broken (previous_hash mismatch)`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Get the public key (hex string)
   */
  async getPublicKey(): Promise<string> {
    await this.initialized;
    return bytesToHex(this.publicKey);
  }

  /**
   * Generate a new key pair
   *
   * @returns Object with privateKey and publicKey as hex strings
   */
  static async generateKeyPair(): Promise<{ privateKey: string; publicKey: string }> {
    const { privateKey, publicKey } = await generateKeyPair();
    return {
      privateKey: bytesToHex(privateKey),
      publicKey: bytesToHex(publicKey),
    };
  }
}

// Re-export for convenience
export { Scores, SonateReceipt, SignedReceipt, TrustReceipt, TrustReceiptData } from './trust-receipt';
