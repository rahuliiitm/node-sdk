/**
 * Auto-resolve ML providers based on useML configuration.
 *
 * Handles lazy creation of ML detectors and merging them into SecurityOptions.
 * @internal
 */

import type { SecurityOptions, MLGuardrailType } from '../types';
import type { InjectionDetectorProvider } from './injection';
import type { JailbreakDetectorProvider } from './jailbreak';
import type { PIIDetectorProvider } from './pii';
import type { ContentFilterProvider } from './content-filter';
import type { HallucinationDetectorProvider } from './hallucination';

/** Map of accepted guardrail names to canonical MLGuardrailType. */
const GUARDRAIL_ALIASES: Record<string, MLGuardrailType> = {
  injection: 'injection',
  jailbreak: 'jailbreak',
  pii: 'pii',
  toxicity: 'toxicity',
  contentFilter: 'toxicity', // alias
  hallucination: 'hallucination',
};

const ALL_ML_GUARDRAILS: MLGuardrailType[] = [
  'injection',
  'jailbreak',
  'pii',
  'toxicity',
  'hallucination',
];

export interface ResolvedMLProviders {
  injection?: InjectionDetectorProvider;
  jailbreak?: JailbreakDetectorProvider;
  pii?: PIIDetectorProvider;
  toxicity?: ContentFilterProvider;
  hallucination?: HallucinationDetectorProvider;
}

/**
 * Normalize useML value into a deduplicated list of canonical guardrail types.
 */
export function resolveGuardrailList(useML: boolean | MLGuardrailType[]): MLGuardrailType[] {
  if (useML === true) return [...ALL_ML_GUARDRAILS];
  if (useML === false || !useML) return [];

  const result = new Set<MLGuardrailType>();
  for (const name of useML) {
    const normalized = GUARDRAIL_ALIASES[name];
    if (!normalized) {
      throw new Error(
        `Invalid useML guardrail: "${name}". ` +
        `Valid values: ${Object.keys(GUARDRAIL_ALIASES).join(', ')}`,
      );
    }
    result.add(normalized);
  }
  return [...result];
}

/**
 * Create ML providers for the requested guardrails.
 * Dynamically imports from the ml/ module to avoid loading models when not needed.
 *
 * @throws Error if @huggingface/transformers is not installed
 */
export async function createMLProviders(
  useML: boolean | MLGuardrailType[],
): Promise<ResolvedMLProviders> {
  const guardrails = new Set(resolveGuardrailList(useML));
  if (guardrails.size === 0) return {};

  // Verify dependency availability once upfront
  try {
    await import('@huggingface/transformers');
  } catch {
    throw new Error(
      'useML requires @huggingface/transformers. ' +
      'Install with: npm install @huggingface/transformers',
    );
  }

  const result: ResolvedMLProviders = {};
  const tasks: Promise<void>[] = [];

  if (guardrails.has('injection')) {
    tasks.push(
      import('../ml/injection-detector').then(async ({ MLInjectionDetector }) => {
        result.injection = await MLInjectionDetector.create();
      }),
    );
  }
  if (guardrails.has('jailbreak')) {
    tasks.push(
      import('../ml/jailbreak-detector').then(async ({ MLJailbreakDetector }) => {
        result.jailbreak = await MLJailbreakDetector.create();
      }),
    );
  }
  if (guardrails.has('pii')) {
    tasks.push(
      import('../ml/pii-detector').then(async ({ MLPIIDetector }) => {
        result.pii = await MLPIIDetector.create();
      }),
    );
  }
  if (guardrails.has('toxicity')) {
    tasks.push(
      import('../ml/toxicity-detector').then(async ({ MLToxicityDetector }) => {
        result.toxicity = await MLToxicityDetector.create();
      }),
    );
  }
  if (guardrails.has('hallucination')) {
    tasks.push(
      import('../ml/hallucination-detector').then(async ({ MLHallucinationDetector }) => {
        result.hallucination = await MLHallucinationDetector.create();
      }),
    );
  }

  await Promise.all(tasks);
  return result;
}

/**
 * Merge resolved ML providers into SecurityOptions.
 * ML providers are appended to any existing providers (not replaced).
 * Returns a new SecurityOptions object (does not mutate the original).
 */
export function mergeMLProviders(
  security: SecurityOptions,
  mlProviders: ResolvedMLProviders,
): SecurityOptions {
  const merged = { ...security };

  if (mlProviders.injection) {
    merged.injection = {
      ...merged.injection,
      providers: [...(merged.injection?.providers ?? []), mlProviders.injection],
    };
  }
  if (mlProviders.jailbreak) {
    merged.jailbreak = {
      ...merged.jailbreak,
      providers: [...(merged.jailbreak?.providers ?? []), mlProviders.jailbreak],
    };
  }
  if (mlProviders.pii) {
    merged.pii = {
      ...merged.pii,
      providers: [...(merged.pii?.providers ?? []), mlProviders.pii],
    };
  }
  if (mlProviders.toxicity) {
    merged.contentFilter = {
      ...merged.contentFilter,
      providers: [...(merged.contentFilter?.providers ?? []), mlProviders.toxicity],
    };
  }
  if (mlProviders.hallucination) {
    merged.hallucination = {
      ...merged.hallucination,
      providers: [...(merged.hallucination?.providers ?? []), mlProviders.hallucination],
    };
  }

  return merged;
}
