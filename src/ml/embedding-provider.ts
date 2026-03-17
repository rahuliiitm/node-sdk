/**
 * Shared sentence embedding provider using all-MiniLM-L6-v2.
 *
 * Loads the model once (singleton via OnnxSession cache) and provides
 * embeddings to all L3-L4 guards:
 * - Response Judge: semantic topic matching
 * - Conversation Guard: embedding-based drift detection
 * - CoT Guard: goal drift via embeddings
 *
 * Requires: npm install onnxruntime-node @huggingface/transformers
 *
 * @module
 */

import { OnnxSession } from './onnx-runtime';
import type { OnnxSessionOptions } from './onnx-runtime';

const DEFAULT_MODEL = 'Xenova/all-MiniLM-L6-v2';

export interface MLEmbeddingProviderOptions {
  /** HuggingFace model name/path. Must be a sentence-transformer with ONNX weights. */
  modelName?: string;
  /** Custom cache directory. Default: ~/.launchpromptly/models */
  cacheDir?: string;
}

/**
 * Shared embedding provider — load once, use across all guards.
 *
 * @example
 * ```ts
 * import { MLEmbeddingProvider } from 'launchpromptly/ml';
 * const emb = await MLEmbeddingProvider.create();
 * const vec = await emb.embed('Hello world');
 * ```
 */
export class MLEmbeddingProvider {
  readonly name = 'ml-embedding';

  private _session: OnnxSession;
  private _modelName: string;

  private constructor(session: OnnxSession, modelName: string) {
    this._session = session;
    this._modelName = modelName;
  }

  /**
   * Create an MLEmbeddingProvider by loading the sentence-transformer model.
   */
  static async create(options?: MLEmbeddingProviderOptions): Promise<MLEmbeddingProvider> {
    const modelName = options?.modelName ?? DEFAULT_MODEL;
    const sessionOpts: OnnxSessionOptions = {
      maxLength: 256, // Sentence embeddings rarely need > 256 tokens
      cacheDir: options?.cacheDir,
    };
    const session = await OnnxSession.create(modelName, sessionOpts);
    return new MLEmbeddingProvider(session, modelName);
  }

  /**
   * For testing: create with a pre-built OnnxSession.
   * @internal
   */
  static _createForTest(session: OnnxSession): MLEmbeddingProvider {
    return new MLEmbeddingProvider(session, 'test-model');
  }

  /** Embed a single text. Returns a Float32Array of dimension 384. */
  async embed(text: string): Promise<Float32Array> {
    return this._session.embed(text);
  }

  /** Embed multiple texts. */
  async embedBatch(texts: string[]): Promise<Float32Array[]> {
    return Promise.all(texts.map((t) => this._session.embed(t)));
  }

  /** Cosine similarity between two embeddings. */
  cosine(a: Float32Array, b: Float32Array): number {
    return OnnxSession.cosine(a, b);
  }

  /** The underlying model name. */
  get modelName(): string {
    return this._modelName;
  }
}
