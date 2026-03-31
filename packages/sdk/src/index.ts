import type { TrustReceipt } from '@sonate/schemas';
import { fetchPublicKey, verify, type VerificationResult } from '@sonate/verify-sdk';

const DEFAULT_BASE_URL = 'https://yseeku-backend.fly.dev';

export interface GovernanceContext {
  hasExplicitConsent?: boolean;
  consentTimestamp?: number;
  hasOverrideButton?: boolean;
  hasExitButton?: boolean;
  exitRequiresConfirmation?: boolean;
  humanInLoop?: boolean;
  canDeleteData?: boolean;
  noExitPenalty?: boolean;
  receiptGenerated?: boolean;
  isReceiptVerifiable?: boolean;
  auditLogExists?: boolean;
}

export interface PreviousMessage {
  sender: 'user' | 'assistant';
  content: string;
}

export interface EvaluateInteractionRequest {
  prompt: string;
  response: string;
  sessionId?: string;
  conversationId?: string;
  agentId?: string;
  model?: string;
  provider?: string;
  previousMessages?: PreviousMessage[];
  governanceContext?: GovernanceContext;
}

export interface EvaluateInteractionResult {
  receipt: TrustReceipt;
  receiptHash: string;
  trustScore: {
    overall: number;
    principles: Record<string, number>;
    violations: string[];
    timestamp: number;
  };
  status: 'PASS' | 'PARTIAL' | 'FAIL';
  detection: {
    reality_index?: number;
    trust_protocol: string;
    ethical_alignment: number;
    resonance_quality: string;
    canvas_parity?: number;
  };
  reasoning?: string;
  rawReasoning?: string;
  kernelSummary?: string;
  kernelRulesTriggered?: Array<{
    id?: string;
    severity?: 'info' | 'warning' | 'critical';
    message?: string;
  }>;
  verificationPath: string;
  verificationUrl: string;
  sessionId: string;
  conversationId: string;
}

export interface SonateClientOptions {
  apiKey: string;
  baseUrl?: string;
  tenantId?: string;
  fetch?: typeof globalThis.fetch;
  userAgent?: string;
}

export interface WrapOptions<TResult> extends Omit<EvaluateInteractionRequest, 'response'> {
  extractResponse?: (result: TResult) => string;
}

export interface WrappedEvaluation<TResult> {
  result: TResult;
  evaluation: EvaluateInteractionResult;
}

interface ApiEnvelope<T> {
  success: boolean;
  data: T;
  message?: string;
  error?: string;
}

export class SonateApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(message: string, status: number, body?: unknown) {
    super(message);
    this.name = 'SonateApiError';
    this.status = status;
    this.body = body;
  }
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '');
}

function extractTextResponse(result: unknown): string {
  if (typeof result === 'string') return result;

  if (result && typeof result === 'object') {
    const record = result as Record<string, unknown>;

    if (typeof record.output_text === 'string') return record.output_text;

    const choices = record.choices;
    if (Array.isArray(choices)) {
      for (const choice of choices) {
        if (!choice || typeof choice !== 'object') continue;

        const choiceRecord = choice as Record<string, unknown>;
        const message = choiceRecord.message;
        if (message && typeof message === 'object') {
          const content = (message as Record<string, unknown>).content;
          if (typeof content === 'string') return content;
        }

        const text = choiceRecord.text;
        if (typeof text === 'string') return text;
      }
    }

    if (typeof record.content === 'string') return record.content;
  }

  throw new Error(
    'Unable to extract response text automatically. Pass wrap(..., { extractResponse }) to control how the SDK reads your model result.'
  );
}

export class SonateClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly tenantId?: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly userAgent?: string;

  constructor(options: SonateClientOptions) {
    if (!options.apiKey?.trim()) {
      throw new Error('SONATE apiKey is required');
    }

    const fetchImpl = options.fetch || globalThis.fetch;
    if (!fetchImpl) {
      throw new Error(
        'No fetch implementation available. Pass fetch in SonateClientOptions when running in older Node environments.'
      );
    }

    this.apiKey = options.apiKey;
    this.baseUrl = trimTrailingSlash(options.baseUrl || DEFAULT_BASE_URL);
    this.tenantId = options.tenantId;
    this.fetchImpl = fetchImpl;
    this.userAgent = options.userAgent;
  }

  async evaluate(input: EvaluateInteractionRequest): Promise<EvaluateInteractionResult> {
    const response = await this.request<ApiEnvelope<EvaluateInteractionResult>>(
      '/api/v1/receipts/evaluate',
      {
        method: 'POST',
        body: JSON.stringify({
          prompt: input.prompt,
          response: input.response,
          session_id: input.sessionId,
          conversation_id: input.conversationId,
          agent_id: input.agentId,
          model: input.model,
          provider: input.provider,
          previous_messages: input.previousMessages,
          governance_context: input.governanceContext,
        }),
      }
    );

    return response.data;
  }

  async wrap<TResult>(
    operation: () => Promise<TResult>,
    options: WrapOptions<TResult>
  ): Promise<WrappedEvaluation<TResult>> {
    const result = await operation();
    const response =
      typeof options.extractResponse === 'function'
        ? options.extractResponse(result)
        : extractTextResponse(result);

    const evaluation = await this.evaluate({
      ...options,
      response,
    });

    return { result, evaluation };
  }

  async getReceipt(receiptHash: string): Promise<TrustReceipt> {
    const response = await this.request<ApiEnvelope<TrustReceipt>>(
      `/api/v1/receipts/${encodeURIComponent(receiptHash)}`,
      { method: 'GET' }
    );
    return response.data;
  }

  async verifyReceipt(receiptHash: string): Promise<unknown> {
    return this.request(`/api/proof/verify/${encodeURIComponent(receiptHash)}`, {
      method: 'GET',
    });
  }

  async verifyReceiptOffline(receipt: TrustReceipt, publicKey?: string): Promise<VerificationResult> {
    const resolvedKey = publicKey || (await fetchPublicKey());
    return verify(receipt as any, resolvedKey);
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const headers = new Headers(init.headers || {});
    headers.set('Content-Type', 'application/json');
    headers.set('x-api-key', this.apiKey);

    if (this.tenantId) headers.set('x-tenant-id', this.tenantId);
    if (this.userAgent) headers.set('x-sonate-client', this.userAgent);

    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      ...init,
      headers,
    });

    const raw = await response.text();
    let parsed: unknown = undefined;

    if (raw) {
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = raw;
      }
    }

    if (!response.ok) {
      const message =
        typeof parsed === 'object' && parsed && 'message' in parsed
          ? String((parsed as Record<string, unknown>).message)
          : typeof parsed === 'object' && parsed && 'error' in parsed
            ? String((parsed as Record<string, unknown>).error)
            : `SONATE API request failed with status ${response.status}`;
      throw new SonateApiError(message, response.status, parsed);
    }

    return parsed as T;
  }
}

export { fetchPublicKey, verify };
