/**
 * Model policy enforcement — pre-call guard that validates LLM
 * request parameters against a configurable policy.
 *
 * @module
 */

/** Configuration for the model policy guard. */
export interface ModelPolicyOptions {
  /** Whitelist of allowed model identifiers. If set, calls to other models are blocked. */
  allowedModels?: string[];
  /** Maximum allowed value for max_tokens. Requests exceeding this are blocked. */
  maxTokens?: number;
  /** Maximum allowed temperature. Requests exceeding this are blocked. */
  maxTemperature?: number;
  /** When true, requests that include a system prompt are blocked. */
  blockSystemPromptOverride?: boolean;
  /** Called when a policy violation is detected (before throwing). */
  onViolation?: (violation: ModelPolicyViolation) => void;
}

/** Describes a single model policy violation. */
export interface ModelPolicyViolation {
  rule: 'model_not_allowed' | 'max_tokens_exceeded' | 'temperature_exceeded' | 'system_prompt_blocked';
  message: string;
  /** The value that violated the policy. */
  actual?: string | number;
  /** The policy limit that was violated. */
  limit?: string | number | string[];
}

/**
 * Enforce model policy on an outgoing LLM request.
 *
 * Returns the first violation found, or `null` if the request passes all checks.
 * Checks are run in order: model whitelist → max tokens → temperature → system prompt.
 */
export function checkModelPolicy(
  params: {
    model: string;
    max_tokens?: number;
    temperature?: number;
    messages?: ReadonlyArray<{ role: string }>;
    system?: unknown;
  },
  options: ModelPolicyOptions,
): ModelPolicyViolation | null {
  // 1. Model whitelist
  if (options.allowedModels && options.allowedModels.length > 0) {
    if (!options.allowedModels.some(m => params.model === m || params.model.startsWith(m + '-'))) {
      return {
        rule: 'model_not_allowed',
        message: `Model "${params.model}" is not in the allowed list: ${options.allowedModels.join(', ')}`,
        actual: params.model,
        limit: options.allowedModels,
      };
    }
  }

  // 2. Max tokens cap
  if (options.maxTokens !== undefined && params.max_tokens !== undefined) {
    if (params.max_tokens > options.maxTokens) {
      return {
        rule: 'max_tokens_exceeded',
        message: `max_tokens (${params.max_tokens}) exceeds policy limit (${options.maxTokens})`,
        actual: params.max_tokens,
        limit: options.maxTokens,
      };
    }
  }

  // 3. Temperature cap
  if (options.maxTemperature !== undefined && params.temperature !== undefined) {
    if (params.temperature > options.maxTemperature) {
      return {
        rule: 'temperature_exceeded',
        message: `temperature (${params.temperature}) exceeds policy limit (${options.maxTemperature})`,
        actual: params.temperature,
        limit: options.maxTemperature,
      };
    }
  }

  // 4. Block system prompt override
  if (options.blockSystemPromptOverride) {
    // OpenAI-style: system message in messages array
    const hasSystemMessage = params.messages?.some((m) => m.role === 'system');
    // Anthropic-style: top-level system field
    const hasSystemField = params.system !== undefined && params.system !== null;

    if (hasSystemMessage || hasSystemField) {
      return {
        rule: 'system_prompt_blocked',
        message: 'System prompts are blocked by model policy',
      };
    }
  }

  return null;
}
