/**
 * LaunchPromptly ML plugin — optional ML-based security detectors.
 *
 * Install via: npm install onnxruntime-node @huggingface/transformers
 *
 * Uses ONNX Runtime for native inference (8-20ms) when onnxruntime-node is installed.
 * Falls back to @huggingface/transformers WASM (500ms-2s) otherwise.
 *
 * Detectors:
 * - {@link MLInjectionDetector} — Prompt injection detection
 * - {@link MLJailbreakDetector} — Jailbreak detection
 * - {@link MLToxicityDetector} — Toxicity / content-safety detection
 * - {@link MLPIIDetector} — NER-based PII detection (person names, orgs, locations)
 * - {@link MLHallucinationDetector} — Hallucination detection (cross-encoder)
 *
 * Each provider satisfies the corresponding provider interface defined in the
 * core SDK so it can be registered as a drop-in replacement.
 *
 * @example
 * ```ts
 * import { LaunchPromptly } from 'launchpromptly';
 * import { MLToxicityDetector, MLInjectionDetector } from 'launchpromptly/ml';
 *
 * const toxicity = await MLToxicityDetector.create();
 * const injection = await MLInjectionDetector.create();
 *
 * const lp = LaunchPromptly.init({ apiKey: 'lp_live_...' });
 * const wrapped = lp.wrap(openai, {
 *   security: {
 *     contentFilter: { providers: [toxicity] },
 *     injection: { providers: [injection] },
 *   },
 * });
 * ```
 *
 * @module
 */

export { MLToxicityDetector } from './toxicity-detector';
export type { MLToxicityDetectorOptions } from './toxicity-detector';

export { MLInjectionDetector } from './injection-detector';
export type { MLInjectionDetectorOptions } from './injection-detector';

export { MLPIIDetector } from './pii-detector';
export type { MLPIIDetectorOptions } from './pii-detector';

export { MLJailbreakDetector } from './jailbreak-detector';
export type { MLJailbreakDetectorOptions } from './jailbreak-detector';

export { MLHallucinationDetector } from './hallucination-detector';
export type { MLHallucinationDetectorOptions } from './hallucination-detector';

export { MLEmbeddingProvider } from './embedding-provider';
export type { MLEmbeddingProviderOptions } from './embedding-provider';

export { MLResponseJudge } from './nli-judge';
export type { MLResponseJudgeOptions } from './nli-judge';

export { MLContextExtractor } from './context-extractor';
export type { MLContextExtractorOptions } from './context-extractor';

export { MLAttackClassifier } from './attack-classifier';
export type { MLAttackClassifierOptions, AttackClassification, AttackLabel } from './attack-classifier';

export { loadAttackIndex, matchAgainstIndex, hasAttackMatch } from './attack-embeddings';
export type { AttackEmbeddingIndex, AttackMatch, AttackCategory } from './attack-embeddings';

export { OnnxSession } from './onnx-runtime';
export type { OnnxSessionOptions } from './onnx-runtime';

export {
  ensureModel,
  getCacheDir,
  removeModel,
  listCachedModels,
  getRegisteredModels,
  MODEL_NAME_MAP,
} from './model-cache';
export type { EnsureModelOptions } from './model-cache';
