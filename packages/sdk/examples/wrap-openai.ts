import OpenAI from 'openai';
import { SonateClient } from '@sonate/sdk';

async function main() {
  const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
  });

  const sonate = new SonateClient({
    apiKey: process.env.SONATE_API_KEY!,
  });

  const { result, evaluation } = await sonate.wrap(
    () =>
      openai.chat.completions.create({
        model: 'gpt-4o-mini',
        messages: [
          {
            role: 'user',
            content: 'Summarize why independent verification matters for AI governance receipts.',
          },
        ],
      }),
    {
      sessionId: 'wrap-demo-001',
      conversationId: 'wrap-demo-conversation-001',
      prompt: 'Summarize why independent verification matters for AI governance receipts.',
      model: 'gpt-4o-mini',
      provider: 'openai',
      governanceContext: {
        hasExplicitConsent: true,
        hasOverrideButton: true,
        hasExitButton: true,
        humanInLoop: true,
        canDeleteData: true,
        noExitPenalty: true,
        receiptGenerated: true,
        isReceiptVerifiable: true,
        auditLogExists: true,
      },
    }
  );

  console.log('Model response:', result.choices[0].message.content);
  console.log('Status:', evaluation.status);
  console.log('Receipt hash:', evaluation.receiptHash);
  console.log('Verification URL:', evaluation.verificationUrl);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
