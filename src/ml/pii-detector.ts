/**
 * ML-based PII detector using Named Entity Recognition (NER).
 *
 * Catches PII that regex patterns cannot: person names, organization names,
 * and locations.
 *
 * Prefers onnxruntime-node for native inference (8-20ms).
 * Falls back to @huggingface/transformers WASM if onnxruntime-node is not installed.
 *
 * Requires: npm install onnxruntime-node @huggingface/transformers
 *
 * @module
 */

import type {
  PIIDetection,
  PIIDetectOptions,
  PIIDetectorProvider,
  PIIType,
} from '../internal/pii';

/** Mapping from NER entity labels to our PII type strings. */
const NER_LABEL_MAP: Record<string, string> = {
  // Standard IOB/BIO labels
  'B-PER': 'person_name',
  'I-PER': 'person_name',
  'B-ORG': 'org_name',
  'I-ORG': 'org_name',
  'B-LOC': 'us_address',
  'I-LOC': 'us_address',
  'B-MISC': 'misc_entity',
  'I-MISC': 'misc_entity',
  // Some models use full names
  PER: 'person_name',
  ORG: 'org_name',
  LOC: 'us_address',
  PERSON: 'person_name',
  ORGANIZATION: 'org_name',
  LOCATION: 'us_address',
};

/** Core PIIType values this detector supports. */
const CORE_SUPPORTED_TYPES: PIIType[] = ['us_address'];

/** Extended types that NER adds beyond regex capabilities. */
const EXTENDED_TYPES = ['person_name', 'org_name'];

interface NERResult {
  entity: string;
  entity_group?: string;
  score: number;
  word: string;
  start: number;
  end: number;
}

export interface MLPIIDetectorOptions {
  /** HuggingFace model name/path. Default: 'Xenova/bert-base-NER' */
  modelName?: string;
  /** Minimum confidence to report a detection. Default: 0.5 */
  threshold?: number;
  /** Custom cache directory for baked models. Default: ~/.launchpromptly/models */
  cacheDir?: string;
}

type NERPipelineFn = (text: string) => Promise<NERResult[]>;

/**
 * ML-based PII detector using Named Entity Recognition.
 *
 * Catches PII that regex can't: person names, organization names, locations.
 * Uses transformer-based NER models via @huggingface/transformers.
 *
 * @example
 * ```ts
 * import { MLPIIDetector } from 'launchpromptly/ml';
 * const detector = await MLPIIDetector.create();
 * const detections = await detector.detect('John Smith works at Acme Corp');
 * ```
 */
export class MLPIIDetector implements PIIDetectorProvider {
  readonly name = 'ml-ner';
  readonly supportedTypes: (PIIType | string)[] = [...CORE_SUPPORTED_TYPES, ...EXTENDED_TYPES];

  private _pipeline: NERPipelineFn;
  private _modelName: string;
  private _threshold: number;

  private constructor(
    pipeline: NERPipelineFn,
    modelName: string,
    threshold: number,
  ) {
    this._pipeline = pipeline;
    this._modelName = modelName;
    this._threshold = threshold;
  }

  /**
   * Create an MLPIIDetector by loading the NER model.
   *
   * Tries onnxruntime-node first (native, 8-20ms inference).
   * Falls back to @huggingface/transformers WASM if ONNX Runtime is not installed.
   */
  static async create(options?: MLPIIDetectorOptions): Promise<MLPIIDetector> {
    const modelName = options?.modelName ?? 'Xenova/bert-base-NER';
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
      // Wrap OnnxSession.tokenClassify to match NERPipelineFn signature
      const nerPipeline: NERPipelineFn = async (text: string) => {
        const entities = await session.tokenClassify(text);
        return entities.map((e) => ({
          entity: e.entity_group,
          entity_group: e.entity_group,
          score: e.score,
          word: e.word,
          start: e.start,
          end: e.end,
        }));
      };
      return new MLPIIDetector(nerPipeline, modelName, threshold);
    }

    // Fallback: @huggingface/transformers WASM pipeline
    let pipeline: (task: string, model: string, opts?: Record<string, unknown>) => Promise<NERPipelineFn>;
    try {
      const transformers = await import('@huggingface/transformers');
      pipeline = transformers.pipeline as unknown as typeof pipeline;
    } catch {
      throw new Error(
        'MLPIIDetector requires onnxruntime-node (recommended) or @huggingface/transformers. ' +
        'Install with: npm install onnxruntime-node @huggingface/transformers',
      );
    }

    const nerPipeline = await pipeline('token-classification', modelName, {
      aggregation_strategy: 'simple',
    });

    return new MLPIIDetector(nerPipeline as unknown as NERPipelineFn, modelName, threshold);
  }

  /**
   * For testing: create with a pre-built pipeline function.
   * @internal
   */
  static _createForTest(
    pipeline: NERPipelineFn,
    options?: MLPIIDetectorOptions,
  ): MLPIIDetector {
    return new MLPIIDetector(
      pipeline,
      options?.modelName ?? 'Xenova/bert-base-NER',
      options?.threshold ?? 0.5,
    );
  }

  async detect(
    text: string,
    options?: PIIDetectOptions,
  ): Promise<PIIDetection[]> {
    if (!text) return [];

    const allowedTypes = options?.types ? new Set<string>(options.types) : null;

    const results = await this._pipeline(text);

    const detections: PIIDetection[] = [];

    for (const result of results) {
      // Use entity_group (aggregated) or entity label
      const entityLabel = result.entity_group ?? result.entity ?? '';
      const mappedType = NER_LABEL_MAP[entityLabel];

      if (!mappedType) continue;
      if (result.score < this._threshold) continue;
      if (allowedTypes && !allowedTypes.has(mappedType)) continue;

      // Skip misc entities by default (too noisy)
      if (mappedType === 'misc_entity') continue;

      detections.push({
        type: mappedType as PIIType,
        value: result.word,
        start: result.start,
        end: result.end,
        confidence: Math.round(result.score * 100) / 100,
      });
    }

    // Sort by start position, then by confidence descending
    detections.sort((a, b) => a.start - b.start || b.confidence - a.confidence);

    return detections;
  }
}
