/**
 * LaunchPromptly ML plugin — optional ML-based security detectors.
 *
 * Install via: npm install @huggingface/transformers
 *
 * This module provides three ML-powered providers that can be used alongside
 * (or in place of) the built-in regex / rule-based detectors:
 *
 * - {@link MLToxicityDetector} — Transformer-based toxicity / content-safety detection
 * - {@link MLInjectionDetector} — Transformer-based prompt injection detection
 * - {@link MLPIIDetector} — NER-based PII detection (person names, orgs, locations)
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
