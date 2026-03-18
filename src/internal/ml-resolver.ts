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
import type { ResponseJudgeProvider } from './response-judge';
import type { ContextExtractorProvider } from './context-engine';

/** Map of accepted guardrail names to canonical MLGuardrailType. */
const GUARDRAIL_ALIASES: Record<string, MLGuardrailType> = {
  injection: 'injection',
  jailbreak: 'jailbreak',
  pii: 'pii',
  toxicity: 'toxicity',
  contentFilter: 'toxicity', // alias
  hallucination: 'hallucination',
  nliJudge: 'nliJudge',
  contextEngine: 'contextEngine',
};

const ALL_ML_GUARDRAILS: MLGuardrailType[] = [
  'injection',
  'jailbreak',
  'pii',
  'toxicity',
  'hallucination',
  'nliJudge',
  'contextEngine',
];

export interface ResolvedMLProviders {
  injection?: InjectionDetectorProvider;
  jailbreak?: JailbreakDetectorProvider;
  pii?: PIIDetectorProvider;
  toxicity?: ContentFilterProvider;
  hallucination?: HallucinationDetectorProvider;
  nliJudge?: ResponseJudgeProvider;
  contextEngine?: ContextExtractorProvider;
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

  // Verify at least one ML runtime is available
  let hasOnnx = false;
  try {
    await import('onnxruntime-node');
    hasOnnx = true;
  } catch { /* not installed */ }

  if (!hasOnnx) {
    try {
      await import('@huggingface/transformers');
    } catch {
      throw new Error(
        'useML requires onnxruntime-node (recommended) or @huggingface/transformers. ' +
        'Install with: npm install onnxruntime-node @huggingface/transformers',
      );
    }
  }

  const result: ResolvedMLProviders = {};
  const tasks: Array<{ name: string; task: Promise<void> }> = [];

  if (guardrails.has('injection')) {
    tasks.push({
      name: 'injection',
      task: import('../ml/injection-detector').then(async ({ MLInjectionDetector }) => {
        result.injection = await MLInjectionDetector.create();
      }),
    });
  }
  if (guardrails.has('jailbreak')) {
    tasks.push({
      name: 'jailbreak',
      task: import('../ml/jailbreak-detector').then(async ({ MLJailbreakDetector }) => {
        result.jailbreak = await MLJailbreakDetector.create();
      }),
    });
  }
  if (guardrails.has('pii')) {
    tasks.push({
      name: 'pii',
      task: import('../ml/pii-detector').then(async ({ MLPIIDetector }) => {
        result.pii = await MLPIIDetector.create();
      }),
    });
  }
  if (guardrails.has('toxicity')) {
    tasks.push({
      name: 'toxicity',
      task: import('../ml/toxicity-detector').then(async ({ MLToxicityDetector }) => {
        result.toxicity = await MLToxicityDetector.create();
      }),
    });
  }
  if (guardrails.has('hallucination')) {
    tasks.push({
      name: 'hallucination',
      task: import('../ml/hallucination-detector').then(async ({ MLHallucinationDetector }) => {
        result.hallucination = await MLHallucinationDetector.create();
      }),
    });
  }
  if (guardrails.has('nliJudge')) {
    tasks.push({
      name: 'nliJudge',
      task: import('../ml/nli-judge').then(async ({ MLResponseJudge }) => {
        result.nliJudge = await MLResponseJudge.create();
      }),
    });
  }
  if (guardrails.has('contextEngine')) {
    tasks.push({
      name: 'contextEngine',
      task: import('../ml/context-extractor').then(async ({ MLContextExtractor }) => {
        result.contextEngine = await MLContextExtractor.create();
      }),
    });
  }

  // Load independently — one model failure doesn't block the others
  const outcomes = await Promise.allSettled(tasks.map((t) => t.task));
  for (let i = 0; i < outcomes.length; i++) {
    if (outcomes[i].status === 'rejected') {
      const reason = (outcomes[i] as PromiseRejectedResult).reason;
      console.warn(`[ml-resolver] ${tasks[i].name} model failed to load:`, (reason as Error)?.message ?? reason);
    }
  }

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
  if (mlProviders.nliJudge) {
    merged.responseJudge = {
      ...merged.responseJudge,
      providers: [...(merged.responseJudge?.providers ?? []), mlProviders.nliJudge],
    };
  }
  if (mlProviders.contextEngine) {
    merged.contextEngine = {
      ...merged.contextEngine,
      providers: [...(merged.contextEngine?.providers ?? []), mlProviders.contextEngine],
    };
  }

  return merged;
}
