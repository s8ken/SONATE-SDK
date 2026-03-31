import { SonateClient } from '@sonate/sdk';

async function main() {
  const sonate = new SonateClient({
    apiKey: process.env.SONATE_API_KEY!,
  });

  const evaluation = await sonate.evaluate({
    sessionId: 'demo-session-001',
    conversationId: 'demo-conversation-001',
    model: 'gpt-4o-mini',
    provider: 'openai',
    prompt: 'Write a short policy note explaining why gift-card reimbursement requests should be verified.',
    response:
      'Gift-card reimbursement requests should always be verified through an approved internal process because fraud actors often rely on urgency, executive authority, and off-book payment requests.',
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
  });

  console.log('Status:', evaluation.status);
  console.log('Trust score:', evaluation.trustScore.overall);
  console.log('Receipt hash:', evaluation.receiptHash);
  console.log('Verification URL:', evaluation.verificationUrl);
  console.log('Kernel summary:', evaluation.kernelSummary);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
