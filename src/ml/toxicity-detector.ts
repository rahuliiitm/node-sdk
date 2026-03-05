/**
 * ML-based toxicity / content-safety detector.
 *
 * Uses a small toxicity classifier (unitary/toxic-bert) for nuanced content
 * detection that keyword rules miss.
 *
 * Requires: npm install @huggingface/transformers
 *
 * @module
 */

import type { ContentFilterProvider, ContentViolation } from '../internal/content-filter';

/** Mapping from toxic-bert labels to our ContentCategory strings. */
const TOXICITY_LABEL_MAP: Record<string, string> = {
  toxic: 'hate_speech',
  severe_toxic: 'hate_speech',
  obscene: 'sexual',
  threat: 'violence',
  insult: 'hate_speech',
  identity_hate: 'hate_speech',
};

/** Default confidence threshold below which a label is not reported. */
const DEFAULT_THRESHOLD = 0.5;

/** Labels whose score at or above this level are considered "block" severity. */
const BLOCK_THRESHOLD = 0.8;

export interface MLToxicityDetectorOptions {
  /** HuggingFace model name/path. Default: 'unitary/toxic-bert' */
  modelName?: string;
  /** Minimum confidence to report a detection. Default: 0.5 */
  threshold?: number;
}

type ClassifierFn = (text: string, options?: Record<string, unknown>) => Promise<Array<{ label: string; score: number }> | Array<Array<{ label: string; score: number }>>>;

/**
 * ML-based toxicity / content-safety detector.
 *
 * Uses the `unitary/toxic-bert` classifier by default for nuanced content
 * detection that keyword rules miss.
 *
 * @example
 * ```ts
 * import { MLToxicityDetector } from 'launchpromptly/ml';
 * const detector = await MLToxicityDetector.create();
 * const violations = await detector.detect('You are a terrible person', 'input');
 * ```
 */
export class MLToxicityDetector implements ContentFilterProvider {
  readonly name = 'ml-toxicity';

  private _classifier: ClassifierFn;
  private _modelName: string;
  private _threshold: number;

  private constructor(
    classifier: ClassifierFn,
    modelName: string,
    threshold: number,
  ) {
    this._classifier = classifier;
    this._modelName = modelName;
    this._threshold = threshold;
  }

  /**
   * Create an MLToxicityDetector by loading the model.
   * This is async because model loading requires downloading/caching.
   */
  static async create(options?: MLToxicityDetectorOptions): Promise<MLToxicityDetector> {
    const modelName = options?.modelName ?? 'Xenova/toxic-bert';
    const threshold = options?.threshold ?? DEFAULT_THRESHOLD;

    let pipeline: (task: string, model: string, opts?: Record<string, unknown>) => Promise<ClassifierFn>;
    try {
      const transformers = await import('@huggingface/transformers');
      pipeline = transformers.pipeline as unknown as typeof pipeline;
    } catch {
      throw new Error(
        'MLToxicityDetector requires @huggingface/transformers. ' +
        'Install with: npm install @huggingface/transformers',
      );
    }

    const classifier = await pipeline('text-classification', modelName, {
      top_k: null, // Return all labels with scores
    });

    return new MLToxicityDetector(classifier as unknown as ClassifierFn, modelName, threshold);
  }

  /**
   * For testing: create with a pre-built classifier function.
   * @internal
   */
  static _createForTest(
    classifier: ClassifierFn,
    options?: MLToxicityDetectorOptions,
  ): MLToxicityDetector {
    return new MLToxicityDetector(
      classifier,
      options?.modelName ?? 'Xenova/toxic-bert',
      options?.threshold ?? DEFAULT_THRESHOLD,
    );
  }

  async detect(
    text: string,
    location: 'input' | 'output',
  ): Promise<ContentViolation[]> {
    if (!text) return [];

    const rawResults = await this._classifier(text, { top_k: null });

    // Normalise: the pipeline wraps results in an outer list for a single input.
    let labelScores: Array<{ label: string; score: number }>;
    if (rawResults && Array.isArray(rawResults[0])) {
      labelScores = rawResults[0] as Array<{ label: string; score: number }>;
    } else {
      labelScores = (rawResults ?? []) as Array<{ label: string; score: number }>;
    }

    const violations: ContentViolation[] = [];
    const seenCategories = new Set<string>();

    for (const item of labelScores) {
      const label = (item.label ?? '').toLowerCase();
      const score = Number(item.score ?? 0);

      if (score < this._threshold) continue;

      const category = TOXICITY_LABEL_MAP[label];
      if (!category) continue;

      if (seenCategories.has(category)) continue;
      seenCategories.add(category);

      const severity: 'warn' | 'block' = score >= BLOCK_THRESHOLD ? 'block' : 'warn';

      violations.push({ category, matched: text, severity, location });
    }

    return violations;
  }
}
