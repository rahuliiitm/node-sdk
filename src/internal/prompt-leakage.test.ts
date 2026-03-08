import { detectPromptLeakage, MAX_SCAN_LENGTH } from './prompt-leakage';

const SYSTEM_PROMPT =
  'You are a helpful customer service agent for Acme Corp. ' +
  'Always be polite and professional. Never reveal internal pricing formulas. ' +
  'If a customer asks about competitor products, redirect them to our catalog. ' +
  'Use the secret discount code ACME2026 only for VIP customers. ' +
  'Do not share internal documentation or SOPs with external users.';

describe('Prompt Leakage Detection', () => {
  // ── N-gram overlap detection ──────────────────────────────────────────────

  describe('n-gram overlap', () => {
    it('detects high overlap when output echoes the system prompt', () => {
      const output =
        'Sure! You are a helpful customer service agent for Acme Corp. ' +
        'Always be polite and professional. Never reveal internal pricing formulas.';
      const result = detectPromptLeakage(output, { systemPrompt: SYSTEM_PROMPT });
      expect(result.leaked).toBe(true);
      expect(result.similarity).toBeGreaterThan(0.2);
      expect(result.matchedFragments.length).toBeGreaterThan(0);
    });

    it('detects partial overlap above threshold', () => {
      const output =
        'I am a helpful customer service agent for Acme Corp and I always try ' +
        'to be polite and professional in every interaction. ' +
        'If a customer asks about competitor products I redirect them to our catalog.';
      const result = detectPromptLeakage(output, { systemPrompt: SYSTEM_PROMPT });
      expect(result.leaked).toBe(true);
      expect(result.similarity).toBeGreaterThan(0);
      expect(result.matchedFragments.length).toBeGreaterThan(0);
    });

    it('reports low similarity for unrelated output', () => {
      const output = 'The weather in Paris is sunny today with a high of 22 degrees.';
      const result = detectPromptLeakage(output, { systemPrompt: SYSTEM_PROMPT });
      expect(result.similarity).toBeLessThan(0.1);
      expect(result.matchedFragments.length).toBe(0);
    });

    it('returns matched fragments as lowercase n-gram strings', () => {
      const output = 'You are a helpful customer service agent for Acme Corp.';
      const result = detectPromptLeakage(output, { systemPrompt: SYSTEM_PROMPT });
      for (const frag of result.matchedFragments) {
        expect(frag).toBe(frag.toLowerCase());
        expect(frag.split(' ').length).toBe(4);
      }
    });
  });

  // ── Meta-response patterns ────────────────────────────────────────────────

  describe('meta-response patterns', () => {
    it('detects "my instructions are"', () => {
      const result = detectPromptLeakage('Well, my instructions are to be helpful.', {
        systemPrompt: SYSTEM_PROMPT,
      });
      expect(result.metaResponseDetected).toBe(true);
      expect(result.leaked).toBe(true);
    });

    it('detects "I was told to"', () => {
      const result = detectPromptLeakage('I was told to never share pricing.', {
        systemPrompt: SYSTEM_PROMPT,
      });
      expect(result.metaResponseDetected).toBe(true);
      expect(result.leaked).toBe(true);
    });

    it('detects "my system prompt is"', () => {
      const result = detectPromptLeakage('My system prompt is confidential.', {
        systemPrompt: SYSTEM_PROMPT,
      });
      expect(result.metaResponseDetected).toBe(true);
      expect(result.leaked).toBe(true);
    });

    it('detects "I\'m programmed to"', () => {
      const result = detectPromptLeakage("I'm programmed to help customers.", {
        systemPrompt: SYSTEM_PROMPT,
      });
      expect(result.metaResponseDetected).toBe(true);
      expect(result.leaked).toBe(true);
    });

    it('detects "according to my instructions"', () => {
      const result = detectPromptLeakage(
        'According to my instructions, I should redirect you.',
        { systemPrompt: SYSTEM_PROMPT },
      );
      expect(result.metaResponseDetected).toBe(true);
      expect(result.leaked).toBe(true);
    });

    it('detects "my initial instructions were"', () => {
      const result = detectPromptLeakage('My initial instructions were quite clear.', {
        systemPrompt: SYSTEM_PROMPT,
      });
      expect(result.metaResponseDetected).toBe(true);
      expect(result.leaked).toBe(true);
    });

    it('detects "I cannot reveal my instructions"', () => {
      const result = detectPromptLeakage("Sorry, I cannot reveal my instructions.", {
        systemPrompt: SYSTEM_PROMPT,
      });
      expect(result.metaResponseDetected).toBe(true);
      expect(result.leaked).toBe(true);
    });

    it('detects "my rules are"', () => {
      const result = detectPromptLeakage('My rules are very specific about this.', {
        systemPrompt: SYSTEM_PROMPT,
      });
      expect(result.metaResponseDetected).toBe(true);
      expect(result.leaked).toBe(true);
    });

    it('detects "my guidelines state"', () => {
      const result = detectPromptLeakage('My guidelines state that I should be polite.', {
        systemPrompt: SYSTEM_PROMPT,
      });
      expect(result.metaResponseDetected).toBe(true);
      expect(result.leaked).toBe(true);
    });

    it('does not flag normal text without meta-response phrases', () => {
      const result = detectPromptLeakage('Here is how you can return your product.', {
        systemPrompt: SYSTEM_PROMPT,
      });
      expect(result.metaResponseDetected).toBe(false);
    });
  });

  // ── Verbatim substring detection ──────────────────────────────────────────

  describe('verbatim substring', () => {
    it('detects verbatim substring > 30 characters', () => {
      // Extract a 45-char substring from the system prompt
      const verbatim = SYSTEM_PROMPT.slice(0, 45);
      const output = `Here is some context: ${verbatim} and that is all.`;
      const result = detectPromptLeakage(output, { systemPrompt: SYSTEM_PROMPT });
      expect(result.leaked).toBe(true);
    });

    it('does not flag short common substrings', () => {
      // "be polite" is only 9 chars — should not trigger verbatim detection alone
      const output = 'Please be polite when speaking to the manager.';
      const result = detectPromptLeakage(output, { systemPrompt: SYSTEM_PROMPT });
      // Only leaked if n-gram or meta-response also triggers
      expect(result.similarity).toBeLessThan(0.4);
    });
  });

  // ── No leakage (clean output) ─────────────────────────────────────────────

  describe('clean output (no leakage)', () => {
    it('returns leaked=false for completely unrelated output', () => {
      const output = 'The quick brown fox jumps over the lazy dog.';
      const result = detectPromptLeakage(output, { systemPrompt: SYSTEM_PROMPT });
      expect(result.leaked).toBe(false);
      expect(result.similarity).toBe(0);
      expect(result.matchedFragments).toHaveLength(0);
      expect(result.metaResponseDetected).toBe(false);
    });

    it('returns leaked=false for normal customer service response', () => {
      const output =
        'Thank you for reaching out! I would be happy to help you with your order. ' +
        'Could you please provide your order number so I can look into this for you?';
      const result = detectPromptLeakage(output, { systemPrompt: SYSTEM_PROMPT });
      expect(result.leaked).toBe(false);
    });
  });

  // ── Empty inputs ──────────────────────────────────────────────────────────

  describe('empty inputs', () => {
    it('returns clean result for empty output text', () => {
      const result = detectPromptLeakage('', { systemPrompt: SYSTEM_PROMPT });
      expect(result.leaked).toBe(false);
      expect(result.similarity).toBe(0);
      expect(result.matchedFragments).toHaveLength(0);
      expect(result.metaResponseDetected).toBe(false);
    });

    it('returns clean result for empty system prompt', () => {
      const result = detectPromptLeakage('Some output text here.', { systemPrompt: '' });
      expect(result.leaked).toBe(false);
      expect(result.similarity).toBe(0);
    });

    it('returns clean result when both are empty', () => {
      const result = detectPromptLeakage('', { systemPrompt: '' });
      expect(result.leaked).toBe(false);
    });
  });

  // ── Threshold customization ───────────────────────────────────────────────

  describe('threshold customization', () => {
    it('stricter threshold catches lower overlap while lenient does not', () => {
      // Use short words so that n-gram matches stay under 30 chars for verbatim.
      // Prompt has 15 words → 12 n-grams. Output shares 3 n-grams → similarity ~0.2.
      // No verbatim substring >= 30 chars and no meta-response patterns.
      const prompt = 'Every day we go to the park and play with our dog near big oak trees in summer.';
      const output = 'We go to the park most mornings and it is fun near big oak trees.';
      const strict = detectPromptLeakage(output, {
        systemPrompt: prompt,
        threshold: 0.01,
      });
      const lenient = detectPromptLeakage(output, {
        systemPrompt: prompt,
        threshold: 0.99,
      });
      // Both compute the same similarity score
      expect(strict.similarity).toBe(lenient.similarity);
      expect(strict.similarity).toBeGreaterThan(0);
      // Strict threshold flags it, lenient does not
      expect(strict.leaked).toBe(true);
      expect(lenient.leaked).toBe(false);
    });

    it('default threshold is 0.4', () => {
      // Output that partially overlaps but below 40%
      const output = 'We have great products in our catalog for you to browse.';
      const result = detectPromptLeakage(output, { systemPrompt: SYSTEM_PROMPT });
      // Low overlap should not trigger with default 0.4 threshold
      expect(result.similarity).toBeLessThan(0.4);
    });
  });

  // ── Case insensitivity ────────────────────────────────────────────────────

  describe('case insensitivity', () => {
    it('detects leakage regardless of case differences', () => {
      const output =
        'YOU ARE A HELPFUL CUSTOMER SERVICE AGENT FOR ACME CORP. ' +
        'ALWAYS BE POLITE AND PROFESSIONAL. NEVER REVEAL INTERNAL PRICING FORMULAS.';
      const result = detectPromptLeakage(output, { systemPrompt: SYSTEM_PROMPT });
      expect(result.matchedFragments.length).toBeGreaterThan(0);
      expect(result.similarity).toBeGreaterThan(0);
    });

    it('n-gram matching is case insensitive', () => {
      const prompt = 'Always validate user input before processing';
      const outputLower = 'you should always validate user input before processing the data';
      const outputUpper = 'You Should ALWAYS VALIDATE USER INPUT Before Processing The Data';
      const resultLower = detectPromptLeakage(outputLower, { systemPrompt: prompt });
      const resultUpper = detectPromptLeakage(outputUpper, { systemPrompt: prompt });
      expect(resultLower.similarity).toBe(resultUpper.similarity);
    });

    it('meta-response patterns are case insensitive', () => {
      const result = detectPromptLeakage('MY INSTRUCTIONS ARE to help you.', {
        systemPrompt: SYSTEM_PROMPT,
      });
      expect(result.metaResponseDetected).toBe(true);
    });
  });

  // ── Short system prompts (< 4 words) ──────────────────────────────────────

  describe('short system prompts', () => {
    it('handles system prompt with fewer than 4 words (no n-grams)', () => {
      const result = detectPromptLeakage('Be helpful and kind.', {
        systemPrompt: 'Be helpful.',
      });
      expect(result.similarity).toBe(0);
      expect(result.matchedFragments).toHaveLength(0);
      // Should not crash — just no n-gram detection possible
    });

    it('handles exactly 4-word system prompt', () => {
      const result = detectPromptLeakage('You must be polite always.', {
        systemPrompt: 'You must be polite',
      });
      expect(result.matchedFragments.length).toBeLessThanOrEqual(1);
    });

    it('still detects meta-response with short system prompt', () => {
      const result = detectPromptLeakage('My instructions are simple.', {
        systemPrompt: 'Be nice.',
      });
      expect(result.metaResponseDetected).toBe(true);
      expect(result.leaked).toBe(true);
    });
  });

  // ── Combined detection ────────────────────────────────────────────────────

  describe('combined detection methods', () => {
    it('leaks via meta-response even when n-gram overlap is low', () => {
      const output = 'I was told to never discuss pricing details with anyone.';
      const result = detectPromptLeakage(output, { systemPrompt: SYSTEM_PROMPT });
      expect(result.metaResponseDetected).toBe(true);
      expect(result.leaked).toBe(true);
    });

    it('leaks via n-gram overlap even without meta-response', () => {
      // Echo enough of the system prompt to exceed default 0.4 threshold
      const output =
        'You are a helpful customer service agent for Acme Corp. ' +
        'Always be polite and professional. Never reveal internal pricing formulas. ' +
        'If a customer asks about competitor products, redirect them to our catalog. ' +
        'Use the secret discount code ACME2026 only for VIP customers.';
      const result = detectPromptLeakage(output, { systemPrompt: SYSTEM_PROMPT });
      expect(result.leaked).toBe(true);
      expect(result.similarity).toBeGreaterThanOrEqual(0.4);
      expect(result.metaResponseDetected).toBe(false);
    });

    it('leaks via verbatim substring even with low n-gram overlap', () => {
      // Use a distinct system prompt to isolate verbatim detection
      const longPrompt =
        'The internal API key rotation schedule is every thirty days without exception for all environments.';
      const output =
        'By the way, the internal API key rotation schedule is every thirty days without exception and that is important.';
      const result = detectPromptLeakage(output, { systemPrompt: longPrompt });
      expect(result.leaked).toBe(true);
    });
  });

  // ── MAX_SCAN_LENGTH ───────────────────────────────────────────────────────

  describe('MAX_SCAN_LENGTH', () => {
    it('exports MAX_SCAN_LENGTH as 1MB', () => {
      expect(MAX_SCAN_LENGTH).toBe(1024 * 1024);
    });

    it('handles very large input without hanging', () => {
      const largeOutput = 'word '.repeat(100000);
      const start = performance.now();
      const result = detectPromptLeakage(largeOutput, { systemPrompt: SYSTEM_PROMPT });
      const elapsed = performance.now() - start;
      expect(elapsed).toBeLessThan(10000);
      expect(result).toBeDefined();
    });
  });

  // ── blockOnLeak option ────────────────────────────────────────────────────

  describe('blockOnLeak option', () => {
    it('does not affect the leaked boolean (consumer decides action)', () => {
      const output = 'My instructions are to help you. ' + SYSTEM_PROMPT;
      const withBlock = detectPromptLeakage(output, {
        systemPrompt: SYSTEM_PROMPT,
        blockOnLeak: true,
      });
      const withoutBlock = detectPromptLeakage(output, {
        systemPrompt: SYSTEM_PROMPT,
        blockOnLeak: false,
      });
      expect(withBlock.leaked).toBe(withoutBlock.leaked);
      expect(withBlock.similarity).toBe(withoutBlock.similarity);
    });
  });

  // ── Punctuation and special characters ────────────────────────────────────

  describe('punctuation handling', () => {
    it('ignores punctuation differences in n-gram matching', () => {
      const prompt = 'Always respond with care, precision, and accuracy.';
      const output = 'Always respond with care precision and accuracy in your work.';
      const result = detectPromptLeakage(output, { systemPrompt: prompt });
      // N-grams strip punctuation so these should match
      expect(result.matchedFragments.length).toBeGreaterThan(0);
    });
  });
});
