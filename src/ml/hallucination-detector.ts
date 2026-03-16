/**
 * ML-based hallucination detector using a cross-encoder model.
 *
 * Compares generated text against source text to score faithfulness.
 * Requires a cross-encoder model (e.g. vectara/HHEM) with ONNX weights.
 *
 * Prefers onnxruntime-node for native inference (8-20ms).
 * Falls back to @huggingface/transformers WASM if onnxruntime-node is not installed.
 *
 * Requires: npm install onnxruntime-node @huggingface/transformers
 *
 * @module
 */

import type { HallucinationDetectorProvider, HallucinationResult } from '../internal/hallucination';

export interface MLHallucinationDetectorOptions {
  /** HuggingFace model name/path. Must have ONNX weights. */
  modelName?: string;
  /** Faithfulness threshold (0-1). Below this = hallucination. Default: 0.5 */
  threshold?: number;
  /** Custom cache directory for baked models. Default: ~/.launchpromptly/models */
  cacheDir?: string;
}

type ClassifierFn = (
  inputs: { text: string; text_pair: string },
) => Promise<Array<{ label: string; score: number }>>;

/**
 * ML-based hallucination detector using a cross-encoder model.
 *
 * Requires a cross-encoder model with ONNX weights.
 * Defaults to `vectara/hallucination_evaluation_model` (137M params).
 *
 * @example
 * ```ts
 * import { MLHallucinationDetector } from 'launchpromptly/ml';
 * const detector = await MLHallucinationDetector.create();
 * const result = await detector.detect('Paris is in Germany', 'Paris is the capital of France');
 * ```
 */
export class MLHallucinationDetector implements HallucinationDetectorProvider {
  readonly name = 'ml-hallucination';

  private _classifier: ClassifierFn;
  private _modelName: string;
  private _threshold: number;

  private constructor(classifier: ClassifierFn, modelName: string, threshold: number) {
    this._classifier = classifier;
    this._modelName = modelName;
    this._threshold = threshold;
  }

  /**
   * Create an MLHallucinationDetector by loading the cross-encoder model.
   *
   * Tries onnxruntime-node first (native, 8-20ms inference).
   * Falls back to @huggingface/transformers WASM if ONNX Runtime is not installed.
   */
  static async create(options?: MLHallucinationDetectorOptions): Promise<MLHallucinationDetector> {
    const modelName = options?.modelName ?? 'vectara/hallucination_evaluation_model';
    const threshold = options?.threshold ?? 0.5;

    // Try ONNX Runtime first (25-100x faster than WASM)
    let useOnnx = false;
    try {
      await import('onnxruntime-node');
      useOnnx = true;
    } catch {
      // onnxruntime-node not installed
    }

    if (useOnnx) {
      const { OnnxSession } = await import('./onnx-runtime');
      const session = await OnnxSession.create(modelName, { maxLength: 512, cacheDir: options?.cacheDir });
      // Wrap OnnxSession.classifyPair to match ClassifierFn signature
      const classifier: ClassifierFn = async (inputs: {
        text: string;
        text_pair: string;
      }) => session.classifyPair(inputs.text, inputs.text_pair);
      return new MLHallucinationDetector(classifier, modelName, threshold);
    }

    // Fallback: @huggingface/transformers WASM pipeline
    let pipeline: (task: string, model: string, opts?: Record<string, unknown>) => Promise<ClassifierFn>;
    try {
      const transformers = await import('@huggingface/transformers');
      pipeline = transformers.pipeline as unknown as typeof pipeline;
    } catch {
      throw new Error(
        'MLHallucinationDetector requires onnxruntime-node (recommended) or @huggingface/transformers. ' +
        'Install with: npm install onnxruntime-node @huggingface/transformers',
      );
    }

    const classifier = await pipeline('text-classification', modelName, {
      truncation: true,
      maxLength: 512,
    });

    return new MLHallucinationDetector(classifier as unknown as ClassifierFn, modelName, threshold);
  }

  /**
   * For testing: create with a pre-built classifier function.
   * @internal
   */
  static _createForTest(
    classifier: ClassifierFn,
    options?: MLHallucinationDetectorOptions,
  ): MLHallucinationDetector {
    return new MLHallucinationDetector(
      classifier,
      options?.modelName ?? 'vectara/hallucination_evaluation_model',
      options?.threshold ?? 0.5,
    );
  }

  async detect(generated: string, source: string): Promise<HallucinationResult> {
    if (!generated || !source) {
      return { hallucinated: false, faithfulnessScore: 1.0, severity: 'low' };
    }

    const result = await this._classifier({ text: source, text_pair: generated });

    if (!Array.isArray(result) || result.length === 0) {
      return { hallucinated: false, faithfulnessScore: 1.0, severity: 'low' };
    }

    const prediction = result[0];
    const label = (prediction.label ?? '').toUpperCase();
    const score = Number(prediction.score ?? 0);

    // HHEM outputs labels like 'CONSISTENT' / 'HALLUCINATED'
    // Score for CONSISTENT = faithfulness; Score for HALLUCINATED = 1 - faithfulness
    let faithfulnessScore: number;
    if (label === 'CONSISTENT' || label === 'ENTAILMENT' || label === 'LABEL_1') {
      faithfulnessScore = score;
    } else if (label === 'HALLUCINATED' || label === 'CONTRADICTION' || label === 'LABEL_0') {
      faithfulnessScore = 1.0 - score;
    } else {
      // Unknown label — use raw score
      faithfulnessScore = score;
    }

    faithfulnessScore = Math.round(faithfulnessScore * 100) / 100;

    const hallucinated = faithfulnessScore < this._threshold;

    let severity: 'low' | 'medium' | 'high';
    if (faithfulnessScore >= 0.7) {
      severity = 'low';
    } else if (faithfulnessScore >= 0.4) {
      severity = 'medium';
    } else {
      severity = 'high';
    }

    return { hallucinated, faithfulnessScore, severity };
  }
}
