import { checkModelPolicy, type ModelPolicyOptions } from './model-policy';

describe('checkModelPolicy', () => {
  // ── Model whitelist ──────────────────────────────────────────────────────

  describe('allowedModels', () => {
    const opts: ModelPolicyOptions = {
      allowedModels: ['gpt-4o', 'gpt-4o-mini', 'claude-sonnet-4-20250514'],
    };

    it('allows a model on the whitelist', () => {
      const result = checkModelPolicy(
        { model: 'gpt-4o', messages: [{ role: 'user' }] },
        opts,
      );
      expect(result).toBeNull();
    });

    it('blocks a model not on the whitelist', () => {
      const result = checkModelPolicy(
        { model: 'gpt-3.5-turbo', messages: [{ role: 'user' }] },
        opts,
      );
      expect(result).not.toBeNull();
      expect(result!.rule).toBe('model_not_allowed');
      expect(result!.actual).toBe('gpt-3.5-turbo');
      expect(result!.limit).toEqual(opts.allowedModels);
    });

    it('passes when allowedModels is empty', () => {
      const result = checkModelPolicy(
        { model: 'any-model', messages: [] },
        { allowedModels: [] },
      );
      expect(result).toBeNull();
    });

    it('passes when allowedModels is not set', () => {
      const result = checkModelPolicy(
        { model: 'any-model', messages: [] },
        {},
      );
      expect(result).toBeNull();
    });
  });

  // ── Max tokens ───────────────────────────────────────────────────────────

  describe('maxTokens', () => {
    const opts: ModelPolicyOptions = { maxTokens: 4096 };

    it('allows max_tokens within limit', () => {
      const result = checkModelPolicy(
        { model: 'gpt-4o', max_tokens: 2048, messages: [] },
        opts,
      );
      expect(result).toBeNull();
    });

    it('allows max_tokens exactly at limit', () => {
      const result = checkModelPolicy(
        { model: 'gpt-4o', max_tokens: 4096, messages: [] },
        opts,
      );
      expect(result).toBeNull();
    });

    it('blocks max_tokens exceeding limit', () => {
      const result = checkModelPolicy(
        { model: 'gpt-4o', max_tokens: 8192, messages: [] },
        opts,
      );
      expect(result).not.toBeNull();
      expect(result!.rule).toBe('max_tokens_exceeded');
      expect(result!.actual).toBe(8192);
      expect(result!.limit).toBe(4096);
    });

    it('passes when max_tokens is not provided in params', () => {
      const result = checkModelPolicy(
        { model: 'gpt-4o', messages: [] },
        opts,
      );
      expect(result).toBeNull();
    });
  });

  // ── Temperature ──────────────────────────────────────────────────────────

  describe('maxTemperature', () => {
    const opts: ModelPolicyOptions = { maxTemperature: 1.0 };

    it('allows temperature within limit', () => {
      const result = checkModelPolicy(
        { model: 'gpt-4o', temperature: 0.7, messages: [] },
        opts,
      );
      expect(result).toBeNull();
    });

    it('allows temperature exactly at limit', () => {
      const result = checkModelPolicy(
        { model: 'gpt-4o', temperature: 1.0, messages: [] },
        opts,
      );
      expect(result).toBeNull();
    });

    it('blocks temperature exceeding limit', () => {
      const result = checkModelPolicy(
        { model: 'gpt-4o', temperature: 1.5, messages: [] },
        opts,
      );
      expect(result).not.toBeNull();
      expect(result!.rule).toBe('temperature_exceeded');
      expect(result!.actual).toBe(1.5);
      expect(result!.limit).toBe(1.0);
    });

    it('allows temperature 0', () => {
      const result = checkModelPolicy(
        { model: 'gpt-4o', temperature: 0, messages: [] },
        opts,
      );
      expect(result).toBeNull();
    });

    it('passes when temperature is not provided', () => {
      const result = checkModelPolicy(
        { model: 'gpt-4o', messages: [] },
        opts,
      );
      expect(result).toBeNull();
    });
  });

  // ── System prompt blocking ───────────────────────────────────────────────

  describe('blockSystemPromptOverride', () => {
    const opts: ModelPolicyOptions = { blockSystemPromptOverride: true };

    it('blocks when messages contain a system role (OpenAI-style)', () => {
      const result = checkModelPolicy(
        {
          model: 'gpt-4o',
          messages: [
            { role: 'system' },
            { role: 'user' },
          ],
        },
        opts,
      );
      expect(result).not.toBeNull();
      expect(result!.rule).toBe('system_prompt_blocked');
    });

    it('blocks when system field is provided (Anthropic-style)', () => {
      const result = checkModelPolicy(
        {
          model: 'claude-sonnet-4-20250514',
          messages: [{ role: 'user' }],
          system: 'You are a helpful assistant',
        },
        opts,
      );
      expect(result).not.toBeNull();
      expect(result!.rule).toBe('system_prompt_blocked');
    });

    it('allows when no system prompt is present', () => {
      const result = checkModelPolicy(
        {
          model: 'gpt-4o',
          messages: [{ role: 'user' }],
        },
        opts,
      );
      expect(result).toBeNull();
    });

    it('passes when blockSystemPromptOverride is false', () => {
      const result = checkModelPolicy(
        {
          model: 'gpt-4o',
          messages: [
            { role: 'system' },
            { role: 'user' },
          ],
        },
        { blockSystemPromptOverride: false },
      );
      expect(result).toBeNull();
    });
  });

  // ── Combined policies ────────────────────────────────────────────────────

  describe('combined policies', () => {
    const opts: ModelPolicyOptions = {
      allowedModels: ['gpt-4o'],
      maxTokens: 4096,
      maxTemperature: 1.0,
      blockSystemPromptOverride: true,
    };

    it('returns first violation (model check comes first)', () => {
      const result = checkModelPolicy(
        {
          model: 'gpt-3.5-turbo',
          max_tokens: 10000,
          temperature: 2.0,
          messages: [{ role: 'system' }],
        },
        opts,
      );
      expect(result).not.toBeNull();
      expect(result!.rule).toBe('model_not_allowed');
    });

    it('passes when all policies are satisfied', () => {
      const result = checkModelPolicy(
        {
          model: 'gpt-4o',
          max_tokens: 1024,
          temperature: 0.5,
          messages: [{ role: 'user' }],
        },
        opts,
      );
      expect(result).toBeNull();
    });

    it('returns empty config passes everything', () => {
      const result = checkModelPolicy(
        {
          model: 'anything',
          max_tokens: 999999,
          temperature: 99,
          messages: [{ role: 'system' }],
        },
        {},
      );
      expect(result).toBeNull();
    });
  });
});
