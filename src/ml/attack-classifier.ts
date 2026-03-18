/**
 * Multi-class attack classifier using fine-tuned MiniLM.
 *
 * 7-class output: safe, injection, jailbreak, data_extraction,
 * manipulation, role_escape, social_engineering.
 *
 * Complements existing binary detectors with multi-class categorization
 * and faster inference (<5ms, 22M params, INT8 quantized).
 *
 * Requires: npm install onnxruntime-node
 *
 * @module
 */

import type {
  InjectionAnalysis,
  InjectionDetectorProvider,
  InjectionOptions,
} from '../internal/injection';

/** Attack categories output by the classifier. */
export type AttackLabel =
  | 'safe'
  | 'injection'
  | 'jailbreak'
  | 'data_extraction'
  | 'manipulation'
  | 'role_escape'
  | 'social_engineering';

/** All non-safe labels. */
const ATTACK_LABELS = new Set<string>([
  'injection',
  'jailbreak',
  'data_extraction',
  'manipulation',
  'role_escape',
  'social_engineering',
]);

/** Default thresholds matching the core rule-based detector. */
const DEFAULT_WARN_THRESHOLD = 0.3;
const DEFAULT_BLOCK_THRESHOLD = 0.7;

/** Per-class threshold for reporting triggered categories. */
const CATEGORY_TRIGGER_THRESHOLD = 0.15;

export interface MLAttackClassifierOptions {
  /** HuggingFace model name. Default: 'launchpromptly/attack-classifier-v1' */
  modelName?: string;
  /** Use quantized model. Default: true */
  quantized?: boolean;
  /** Custom cache directory. */
  cacheDir?: string;
}

/** Full multi-class classification result. */
export interface AttackClassification {
  /** Top predicted label. */
  label: AttackLabel;
  /** Confidence score for top label. */
  score: number;
  /** All class probabilities sorted by score descending. */
  allScores: Array<{ label: AttackLabel; score: number }>;
  /** Whether any attack class is the top prediction. */
  isAttack: boolean;
}

type ClassifierFn = (
  text: string,
  opts?: { topK?: number | null },
) => Promise<Array<{ label: string; score: number }>>;

/**
 * Multi-class attack classifier using a fine-tuned all-MiniLM-L6-v2.
 *
 * Implements InjectionDetectorProvider for drop-in use in the security pipeline.
 * Also exposes `classify()` for full 7-class output with per-category scores.
 *
 * @example
 * ```ts
 * import { MLAttackClassifier } from 'launchpromptly/ml';
 *
 * const classifier = await MLAttackClassifier.create();
 * const result = await classifier.classify('Ignore all previous instructions');
 * // result.label === 'injection', result.isAttack === true
 *
 * // Or use as injection provider in the pipeline:
 * const lp = LaunchPromptly.init({ apiKey: '...' });
 * const wrapped = lp.wrap(openai, {
 *   security: { injection: { providers: [classifier] } },
 * });
 * ```
 */
export class MLAttackClassifier implements InjectionDetectorProvider {
  readonly name = 'ml-attack-classifier';

  private _classifier: ClassifierFn;
  private _modelName: string;

  private constructor(classifier: ClassifierFn, modelName: string) {
    this._classifier = classifier;
    this._modelName = modelName;
  }

  /**
   * Create an MLAttackClassifier by loading the ONNX model.
   *
   * Uses onnxruntime-node for native inference (<5ms).
   * Falls back to @huggingface/transformers WASM if ONNX Runtime is unavailable.
   */
  static async create(
    options?: MLAttackClassifierOptions,
  ): Promise<MLAttackClassifier> {
    const modelName =
      options?.modelName ?? 'launchpromptly/attack-classifier-v1';
    const quantized = options?.quantized ?? true;

    let useOnnx = false;
    try {
      await import('onnxruntime-node');
      useOnnx = true;
    } catch {
      // onnxruntime-node not installed
    }

    if (useOnnx) {
      const { OnnxSession } = await import('./onnx-runtime');
      const session = await OnnxSession.create(modelName, {
        maxLength: 256,
        quantized,
        cacheDir: options?.cacheDir,
      });
      const classifier: ClassifierFn = async (text, opts) =>
        session.classify(text, opts);
      return new MLAttackClassifier(classifier, modelName);
    }

    // Fallback: @huggingface/transformers WASM
    let pipeline: (
      task: string,
      model: string,
      opts?: Record<string, unknown>,
    ) => Promise<ClassifierFn>;
    try {
      const transformers = await import('@huggingface/transformers');
      pipeline = transformers.pipeline as unknown as typeof pipeline;
    } catch {
      throw new Error(
        'MLAttackClassifier requires onnxruntime-node (recommended) or @huggingface/transformers. ' +
          'Install with: npm install onnxruntime-node @huggingface/transformers',
      );
    }

    const classifier = await pipeline('text-classification', modelName, {
      truncation: true,
      maxLength: 256,
      topk: null,
    });

    return new MLAttackClassifier(
      classifier as unknown as ClassifierFn,
      modelName,
    );
  }

  /**
   * For testing: create with a mock classifier function.
   * @internal
   */
  static _createForTest(
    classifier: ClassifierFn,
    options?: MLAttackClassifierOptions,
  ): MLAttackClassifier {
    return new MLAttackClassifier(
      classifier,
      options?.modelName ?? 'launchpromptly/attack-classifier-v1',
    );
  }

  /**
   * Full multi-class classification.
   * Returns the top label, all scores, and whether it's an attack.
   */
  async classify(text: string): Promise<AttackClassification> {
    if (!text) {
      return {
        label: 'safe',
        score: 1.0,
        allScores: [{ label: 'safe', score: 1.0 }],
        isAttack: false,
      };
    }

    const results = await this._classifier(text, { topK: null });
    const allScores = results.map((r) => ({
      label: r.label as AttackLabel,
      score: r.score,
    }));

    const top = allScores[0];
    const isAttack = ATTACK_LABELS.has(top.label);

    return { label: top.label, score: top.score, allScores, isAttack };
  }

  /**
   * InjectionDetectorProvider interface — maps multi-class output
   * to binary InjectionAnalysis for backward compatibility.
   *
   * Risk score = 1 - P(safe), i.e. total probability of any attack class.
   */
  async detect(
    text: string,
    options?: InjectionOptions,
  ): Promise<InjectionAnalysis> {
    if (!text) {
      return { riskScore: 0, triggered: [], action: 'allow' };
    }

    const warnThreshold = options?.warnThreshold ?? DEFAULT_WARN_THRESHOLD;
    const blockThreshold = options?.blockThreshold ?? DEFAULT_BLOCK_THRESHOLD;

    const classification = await this.classify(text);

    // Risk score = 1 - P(safe)
    const safeScore =
      classification.allScores.find((s) => s.label === 'safe')?.score ?? 0;
    let riskScore = Math.round((1 - safeScore) * 100) / 100;

    // Triggered categories: all attack labels above threshold
    const triggered: string[] = [];
    for (const s of classification.allScores) {
      if (ATTACK_LABELS.has(s.label) && s.score >= CATEGORY_TRIGGER_THRESHOLD) {
        triggered.push(s.label);
      }
    }

    let action: 'allow' | 'warn' | 'block';
    if (riskScore >= blockThreshold) {
      action = 'block';
    } else if (riskScore >= warnThreshold) {
      action = 'warn';
    } else {
      action = 'allow';
    }

    return { riskScore, triggered, action };
  }
}
