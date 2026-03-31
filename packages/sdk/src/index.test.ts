import { describe, expect, it, vi } from 'vitest';
import { SonateApiError, SonateClient } from './index';

describe('@sonate/sdk', () => {
  it('sends evaluate requests with platform key auth and camelCase normalization', async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      text: async () =>
        JSON.stringify({
          success: true,
          data: {
            receipt: { id: 'rec_123' },
            receiptHash: 'hash_123',
            trustScore: { overall: 8.7, principles: {}, violations: [], timestamp: 1 },
            status: 'PASS',
            detection: {
              trust_protocol: 'PASS',
              ethical_alignment: 4.5,
              resonance_quality: 'STRONG',
            },
            verificationPath: '/api/proof/verify/hash_123',
            verificationUrl: 'https://www.yseeku.com/verify?id=hash_123',
            sessionId: 'session-1',
            conversationId: 'conversation-1',
          },
        }),
    })) as unknown as typeof fetch;

    const client = new SonateClient({
      apiKey: 'sk_test_123',
      baseUrl: 'https://api.example.com/',
      tenantId: 'tenant_123',
      fetch: fetchMock,
    });

    const result = await client.evaluate({
      prompt: 'hello',
      response: 'world',
      sessionId: 'session-1',
      conversationId: 'conversation-1',
      agentId: 'agent-1',
      model: 'gpt-4o-mini',
      previousMessages: [{ sender: 'user', content: 'prior' }],
      governanceContext: { hasExplicitConsent: true },
    });

    expect(result.receiptHash).toBe('hash_123');

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.example.com/api/v1/receipts/evaluate');
    expect((init?.headers as Headers).get('x-api-key')).toBe('sk_test_123');
    expect((init?.headers as Headers).get('x-tenant-id')).toBe('tenant_123');

    expect(JSON.parse(String(init?.body))).toMatchObject({
      prompt: 'hello',
      response: 'world',
      session_id: 'session-1',
      conversation_id: 'conversation-1',
      agent_id: 'agent-1',
      previous_messages: [{ sender: 'user', content: 'prior' }],
      governance_context: { hasExplicitConsent: true },
    });
  });

  it('wraps a provider call and extracts OpenAI-style content by default', async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      text: async () =>
        JSON.stringify({
          success: true,
          data: {
            receipt: { id: 'rec_123' },
            receiptHash: 'hash_123',
            trustScore: { overall: 6.6, principles: {}, violations: [], timestamp: 1 },
            status: 'PARTIAL',
            detection: {
              trust_protocol: 'PARTIAL',
              ethical_alignment: 3.1,
              resonance_quality: 'STRONG',
            },
            verificationPath: '/api/proof/verify/hash_123',
            verificationUrl: 'https://www.yseeku.com/verify?id=hash_123',
            sessionId: 'session-1',
            conversationId: 'conversation-1',
          },
        }),
    })) as unknown as typeof fetch;

    const client = new SonateClient({
      apiKey: 'sk_test_123',
      fetch: fetchMock,
    });

    const wrapped = await client.wrap(
      async () => ({
        choices: [
          {
            message: {
              content: 'Assistant response',
            },
          },
        ],
      }),
      {
        prompt: 'User prompt',
        sessionId: 'session-1',
      }
    );

    expect(wrapped.evaluation.status).toBe('PARTIAL');
    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(String(init?.body)).response).toBe('Assistant response');
  });

  it('throws SonateApiError with parsed API message on non-2xx responses', async () => {
    const fetchMock = vi.fn(async () => ({
      ok: false,
      status: 401,
      text: async () => JSON.stringify({ success: false, message: 'Invalid API key' }),
    })) as unknown as typeof fetch;

    const client = new SonateClient({
      apiKey: 'bad-key',
      fetch: fetchMock,
    });

    await expect(client.evaluate({ prompt: 'hello', response: 'world' })).rejects.toMatchObject({
      name: 'SonateApiError',
      status: 401,
      message: 'Invalid API key',
    } satisfies Partial<SonateApiError>);
  });
});
