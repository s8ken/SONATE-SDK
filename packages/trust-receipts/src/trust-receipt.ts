/**
 * TrustReceipt - Cryptographically signed AI interaction records (SONATE v2.2.0)
 *
 * Each receipt is a SONATE v2.2.0 Trust Receipt that verifies successfully with
 * @sonate/verify-sdk. It captures:
 * - Hashes of the prompt/input and response/output (raw content optional)
 * - Attestation scores mapped into telemetry
 * - A hash chain linking to the previous receipt
 * - An Ed25519 signature over the canonical receipt
 *
 * Cryptographic contract (must match @sonate/verify-sdk byte-for-byte):
 *  - Canonicalization: RFC 8785 (json-canonicalize) with `undefined` stripped first.
 *  - id           = sha256hex(canonical(receipt WITHOUT signature, WITHOUT id, chain.chain_hash=''))
 *  - chain_hash   = sha256hex(canonical(receipt WITHOUT signature, chain.chain_hash='') + previous_hash)
 *                   (note: `id` IS present in this canonical payload)
 *  - signature    = Ed25519 over utf-8 bytes of canonical(receipt WITHOUT signature)
 *                   (note: `id` AND the real `chain_hash` ARE present)
 *
 * Construction order is therefore: build base -> compute id -> compute chain_hash -> sign.
 *
 * SECURITY — the ENTIRE `signature` block is stripped before the id/chain/sign
 * hashes are computed, so every field inside it (`key_version`,
 * `timestamp_signed`, and any others) is UNSIGNED metadata. It matches the
 * platform reference deliberately. Consumers MUST NOT trust or act on those
 * fields, and MUST NEVER select the verification public key from receipt
 * contents — the public key always comes from a trusted external source (a
 * pinned key, a `.well-known` endpoint, a DID document, etc.).
 */

import { sha256, sign, verify, bytesToHex, hexToBytes, canonicalize } from './crypto';

/**
 * Attestation scores for the AI interaction.
 * All scores are user-defined floats, conventionally between 0 and 1.
 * `clarity`, `integrity`, and `quality` map to `telemetry.ciq_metrics`;
 * any other keys are preserved under `telemetry.custom_scores`.
 */
export interface Scores {
  [key: string]: number;
}

/**
 * A SONATE v2.2.0 Trust Receipt.
 *
 * This shape is the wire format produced by this SDK and consumed by
 * @sonate/verify-sdk. It intentionally mirrors that verifier's `TrustReceipt`
 * interface (the normative oracle for this package).
 */
export interface SonateReceipt {
  /** Receipt ID (SHA-256 hex of the canonical content) */
  id: string;
  /** Receipt schema version */
  version: '2.2.0';
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Session identifier */
  session_id: string;
  /** DID of the AI agent */
  agent_did: string;
  /** DID of the human user */
  human_did: string;
  /** Optional policy version */
  policy_version?: string;
  /** Governance mode */
  mode: 'constitutional' | 'directive';
  /** AI interaction data (hash-only by default) */
  interaction: {
    prompt?: string;
    response?: string;
    prompt_hash: string;
    response_hash: string;
    model: string;
    provider?: string;
    temperature?: number;
    max_tokens?: number;
    [key: string]: unknown;
  };
  /** Trust / attestation metrics */
  telemetry?: {
    ciq_metrics?: {
      clarity?: number;
      integrity?: number;
      quality?: number;
    };
    custom_scores?: Record<string, number>;
    [key: string]: unknown;
  };
  /** Hash chain for immutability */
  chain: {
    previous_hash: string;
    chain_hash: string;
    chain_length?: number;
  };
  /** Ed25519 signature */
  signature: {
    algorithm: 'Ed25519';
    value: string;
    key_version: string;
    public_key?: string;
    timestamp_signed?: string;
  };
  /** Optional application metadata */
  metadata?: Record<string, unknown>;
}

/**
 * A signed receipt ready for storage or transmission.
 *
 * Alias of {@link SonateReceipt} — kept as a named export for API continuity.
 */
export type SignedReceipt = SonateReceipt;

/**
 * Data required to create a TrustReceipt.
 *
 * Legacy camelCase inputs from the 2.x SDK are still accepted and mapped onto
 * the v2.2.0 wire format (see the field docs below).
 */
export interface TrustReceiptData {
  /** Session identifier -> `session_id` */
  sessionId: string;
  /** The prompt/input sent to the AI (hashed into `interaction.prompt_hash`) */
  prompt: unknown;
  /** The response/output from the AI (hashed into `interaction.response_hash`) */
  response: unknown;
  /** Attestation scores -> `telemetry.ciq_metrics` / `telemetry.custom_scores` */
  scores?: Scores;
  /** Agent/model identifier. Becomes `agent_did` (prefixed `did:sonate:` if not a DID). */
  agentId?: string;
  /** Explicit agent DID (overrides `agentId` for `agent_did`) */
  agentDid?: string;
  /** Human identifier -> `human_did` (prefixed `did:sonate:` if not a DID) */
  humanId?: string;
  /** Explicit human DID (overrides `humanId`) */
  humanDid?: string;
  /** Model identifier -> `interaction.model` (defaults to `agentId`) */
  model?: string;
  /** Provider -> `interaction.provider` */
  provider?: string;
  /** Governance mode (default: `constitutional`) */
  mode?: 'constitutional' | 'directive';
  /** Policy version -> `policy_version` */
  policyVersion?: string;
  /** Chain hash of the previous receipt -> `chain.previous_hash` */
  prevReceiptHash?: string;
  /** Position of this receipt in the chain -> `chain.chain_length` */
  chainLength?: number;
  /** Explicit telemetry object (merged with mapped `scores`) */
  telemetry?: Record<string, unknown>;
  /** Custom metadata -> `metadata` */
  metadata?: Record<string, unknown>;
  /** Include full prompt/response content in the receipt (default: false, hashes only) */
  includeContent?: boolean;
  /** Override the ISO 8601 timestamp (deterministic fixtures). Defaults to now. */
  timestamp?: string;
  /** Key version label recorded in `signature.key_version` (default: `key_v1`) */
  keyVersion?: string;
}

const DID_PREFIX = 'did:sonate:';

/** Prefix a bare identifier with `did:sonate:`; pass through existing DIDs. */
function toDid(value: string | undefined, fallback: string): string {
  const v = (value ?? '').trim();
  if (!v) return fallback;
  return v.startsWith('did:') ? v : `${DID_PREFIX}${v}`;
}

/** Hash arbitrary content: strings directly, structured content via RFC 8785. */
function hashContent(content: unknown): string {
  if (content === undefined || content === null) return sha256('');
  if (typeof content === 'string') return sha256(content);
  return sha256(canonicalize(content));
}

/** Render content for inline inclusion (`includeContent: true`). */
function contentToString(content: unknown): string {
  if (content === undefined || content === null) return '';
  return typeof content === 'string' ? content : canonicalize(content);
}

const CIQ_KEYS = ['clarity', 'integrity', 'quality'] as const;

/** Map user scores + optional explicit telemetry into the v2.2.0 telemetry block. */
function buildTelemetry(
  scores: Scores | undefined,
  explicit: Record<string, unknown> | undefined
): SonateReceipt['telemetry'] | undefined {
  const telemetry: Record<string, unknown> = explicit ? { ...explicit } : {};

  if (scores && Object.keys(scores).length > 0) {
    const ciq: Record<string, number> = {};
    const custom: Record<string, number> = {};
    for (const [key, value] of Object.entries(scores)) {
      if ((CIQ_KEYS as readonly string[]).includes(key)) ciq[key] = value;
      else custom[key] = value;
    }
    if (Object.keys(ciq).length > 0) {
      telemetry.ciq_metrics = { ...(telemetry.ciq_metrics as object), ...ciq };
    }
    if (Object.keys(custom).length > 0) {
      telemetry.custom_scores = { ...(telemetry.custom_scores as object), ...custom };
    }
  }

  return Object.keys(telemetry).length > 0
    ? (telemetry as SonateReceipt['telemetry'])
    : undefined;
}

/** Clone a receipt payload (JSON round-trip drops `undefined`, matching the wire form). */
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** Build the canonical payload for id computation (no signature, no id, empty chain_hash). */
function payloadForId(receipt: Record<string, any>): Record<string, any> {
  const base = clone(receipt);
  delete base.signature;
  delete base.id;
  if (base.chain) base.chain = { ...base.chain, chain_hash: '' };
  return base;
}

/** Build the canonical payload for chain-hash computation (no signature, empty chain_hash, id kept). */
function payloadForChain(receipt: Record<string, any>): Record<string, any> {
  const base = clone(receipt);
  delete base.signature;
  if (base.chain) base.chain = { ...base.chain, chain_hash: '' };
  return base;
}

/** Build the canonical payload for signing/verification (no signature; id + real chain_hash kept). */
function payloadForSignature(receipt: Record<string, any>): Record<string, any> {
  const base = clone(receipt);
  delete base.signature;
  return base;
}

/** id = sha256hex(canonical(payloadForId)). */
export function computeReceiptId(receipt: Record<string, any>): string {
  return sha256(canonicalize(payloadForId(receipt)));
}

/** chain_hash = sha256hex(canonical(payloadForChain) + previous_hash). */
export function computeChainHash(receipt: Record<string, any>): string {
  const chainReady = payloadForChain(receipt);
  // `|| 'GENESIS'` (not `??`) so an empty-string previous_hash also falls back
  // to 'GENESIS', matching the platform reference (generateChainHash) exactly.
  const previousHash = chainReady.chain?.previous_hash || 'GENESIS';
  return sha256(canonicalize(chainReady) + previousHash);
}

/**
 * TrustReceipt — builds, signs, and verifies SONATE v2.2.0 receipts.
 */
export class TrustReceipt {
  /** The receipt payload, without the signature block. `id` and `chain.chain_hash` are final. */
  private readonly payload: Omit<SonateReceipt, 'signature'>;
  private readonly keyVersion: string;
  private signatureBlock: SonateReceipt['signature'] | null = null;

  constructor(data: TrustReceiptData) {
    const timestamp = data.timestamp ?? new Date().toISOString();
    const model = data.model ?? data.agentId ?? 'unknown';

    const interaction: SonateReceipt['interaction'] = {
      prompt_hash: hashContent(data.prompt),
      response_hash: hashContent(data.response),
      model,
    };
    if (data.provider) interaction.provider = data.provider;
    if (data.includeContent) {
      interaction.prompt = contentToString(data.prompt);
      interaction.response = contentToString(data.response);
    }

    const previousHash = data.prevReceiptHash ?? 'GENESIS';
    const chainLength =
      data.chainLength ?? (previousHash === 'GENESIS' ? 1 : undefined);

    const base: Omit<SonateReceipt, 'signature' | 'id'> = {
      version: '2.2.0',
      timestamp,
      session_id: data.sessionId,
      agent_did: data.agentDid ?? toDid(data.agentId, `${DID_PREFIX}anonymous`),
      human_did: data.humanDid ?? toDid(data.humanId, `${DID_PREFIX}anonymous`),
      policy_version: data.policyVersion,
      mode: data.mode ?? 'constitutional',
      interaction,
      telemetry: buildTelemetry(data.scores, data.telemetry),
      chain: {
        previous_hash: previousHash,
        chain_hash: '',
        chain_length: chainLength,
      },
      metadata: data.metadata,
    };

    // Compute id (excludes id + chain_hash + signature), then chain_hash (includes id).
    const id = computeReceiptId(base);
    const withId = { ...base, id } as Omit<SonateReceipt, 'signature'>;
    const chainHash = computeChainHash(withId);

    this.payload = {
      ...withId,
      chain: { ...withId.chain, chain_hash: chainHash },
    };
    this.keyVersion = data.keyVersion ?? 'key_v1';
  }

  /** Receipt ID (SHA-256 hex). */
  get id(): string {
    return this.payload.id;
  }

  /** Chain hash of this receipt (used as the next receipt's `previous_hash`). */
  get chainHash(): string {
    return this.payload.chain.chain_hash;
  }

  /** Signature (hex) or empty string when unsigned. */
  get signature(): string {
    return this.signatureBlock?.value ?? '';
  }

  /** Whether the receipt has been signed. */
  get isSigned(): boolean {
    return this.signatureBlock !== null;
  }

  /**
   * Sign the receipt with an Ed25519 private key (32-byte seed).
   *
   * Signs the utf-8 bytes of the canonical receipt (without the signature
   * block, with `id` and the real `chain_hash` present) — the exact bytes
   * @sonate/verify-sdk reconstructs.
   *
   * @param privateKey - 32-byte Ed25519 private key
   */
  async sign(privateKey: Uint8Array): Promise<void> {
    const canonical = canonicalize(payloadForSignature(this.payload));
    const message = new TextEncoder().encode(canonical);
    const signatureBytes = await sign(message, privateKey);

    this.signatureBlock = {
      algorithm: 'Ed25519',
      value: bytesToHex(signatureBytes),
      key_version: this.keyVersion,
      // timestamp_signed is metadata OUTSIDE the signed bytes (the whole
      // signature block is stripped before hashing/signing). It is set to the
      // receipt timestamp so the wire signature block shape matches the SONATE
      // platform reference (receipt-generator.ts) and the Python SDK exactly,
      // and so deterministic fixtures are fully byte-identical across languages.
      timestamp_signed: this.payload.timestamp,
    };
  }

  /**
   * Verify this receipt's integrity and signature against a public key.
   *
   * Recomputes `id` and `chain_hash` (tamper guard), then verifies the
   * Ed25519 signature over the canonical payload.
   *
   * @param publicKey - 32-byte Ed25519 public key
   * @returns true if the receipt is intact and the signature is valid
   */
  async verify(publicKey: Uint8Array): Promise<boolean> {
    if (!this.signatureBlock) return false;
    try {
      if (computeReceiptId(this.payload) !== this.payload.id) return false;
      if (computeChainHash(this.payload) !== this.payload.chain.chain_hash) return false;

      const canonical = canonicalize(payloadForSignature(this.payload));
      const message = new TextEncoder().encode(canonical);
      return await verify(hexToBytes(this.signatureBlock.value), message, publicKey);
    } catch {
      return false;
    }
  }

  /**
   * Check that this receipt chains from a previous one
   * (`this.chain.previous_hash === previous.chain.chain_hash`).
   */
  verifyChain(previous: TrustReceipt | SonateReceipt): boolean {
    const prevHash =
      previous instanceof TrustReceipt ? previous.chainHash : previous.chain?.chain_hash;
    return this.payload.chain.previous_hash === prevHash;
  }

  /** Export the signed v2.2.0 receipt as a plain object. */
  toJSON(): SonateReceipt {
    if (!this.signatureBlock) {
      throw new Error('Receipt is not signed; call sign() before toJSON()');
    }
    return clone({ ...this.payload, signature: this.signatureBlock }) as SonateReceipt;
  }

  /**
   * Reconstruct a TrustReceipt from a serialized v2.2.0 receipt.
   *
   * This performs an **id-integrity check ONLY**: it requires a non-empty `id`
   * and rejects the receipt if that `id` does not equal the SHA-256 of the
   * canonical payload. It does NOT verify the Ed25519 signature or the chain
   * hash — call {@link TrustReceipt.verify} (with a public key from a trusted
   * source) for signature + chain verification.
   *
   * @throws if `id` is missing/empty, or does not match the recomputed payload hash
   */
  static fromJSON(data: SonateReceipt): TrustReceipt {
    const receipt = Object.create(TrustReceipt.prototype) as TrustReceipt;
    const { signature, ...rest } = clone(data);

    if (!rest.id) {
      throw new Error('Invalid receipt: missing id');
    }
    const computedId = computeReceiptId(rest);
    if (rest.id !== computedId) {
      throw new Error('Invalid receipt: id does not match canonical payload');
    }

    (receipt as any).payload = rest;
    (receipt as any).keyVersion = signature?.key_version ?? 'key_v1';
    (receipt as any).signatureBlock = signature ?? null;
    return receipt;
  }
}

// Re-export old alias for backwards compatibility during transition.
/** @deprecated Use {@link Scores} instead */
export type QualityMetrics = Scores;
