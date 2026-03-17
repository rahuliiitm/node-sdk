/**
 * ONNX Runtime integration for ML detectors.
 *
 * Replaces @huggingface/transformers WASM inference (500ms-2s) with native
 * onnxruntime-node inference (8-20ms) — a 25-100x speedup.
 *
 * Tokenization still uses @huggingface/transformers (pure JS, < 1ms).
 * Only the inference engine changes.
 *
 * Requires: npm install onnxruntime-node @huggingface/transformers
 *
 * @module
 */

import * as path from 'path';
import * as fs from 'fs';

/** Softmax: converts logits to probabilities. */
function softmax(logits: number[]): number[] {
  const max = Math.max(...logits);
  const exps = logits.map((x) => Math.exp(x - max));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps.map((x) => x / sum);
}

/** Session cache — avoids reloading the same model. */
const sessionCache = new Map<string, OnnxSession>();

export interface OnnxSessionOptions {
  /** Maximum token length. Default: 512 */
  maxLength?: number;
  /** Use quantized (INT8) model. Default: true */
  quantized?: boolean;
  /** Custom cache directory for baked models. Default: ~/.launchpromptly/models */
  cacheDir?: string;
}

/**
 * Wraps an ONNX Runtime inference session with tokenization.
 *
 * Provides three inference modes:
 * - `classify()` — text classification (injection, toxicity)
 * - `classifyPair()` — cross-encoder classification (hallucination)
 * - `tokenClassify()` — token classification / NER (PII)
 */
export class OnnxSession {
  private _session: any; // ort.InferenceSession
  private _tokenizer: any; // AutoTokenizer instance
  private _config: Record<string, any>;
  private _maxLength: number;
  private _modelId: string;

  private constructor(
    session: any,
    tokenizer: any,
    config: Record<string, any>,
    maxLength: number,
    modelId: string,
  ) {
    this._session = session;
    this._tokenizer = tokenizer;
    this._config = config;
    this._maxLength = maxLength;
    this._modelId = modelId;
  }

  /**
   * Create (or retrieve cached) ONNX session for a model.
   * Downloads model files on first use.
   */
  static async create(
    modelId: string,
    options?: OnnxSessionOptions,
  ): Promise<OnnxSession> {
    const quantized = options?.quantized ?? true;
    const cacheKey = `${modelId}:${quantized}`;

    const cached = sessionCache.get(cacheKey);
    if (cached) return cached;

    // Download model files
    const { ensureModel } = await import('./model-cache');
    const modelDir = await ensureModel(modelId, { quantized, cacheDir: options?.cacheDir });

    // Load ONNX Runtime
    let ort: any;
    try {
      ort = await import('onnxruntime-node');
    } catch {
      throw new Error(
        'OnnxSession requires onnxruntime-node. ' +
          'Install with: npm install onnxruntime-node',
      );
    }

    const modelPath = path.join(modelDir, 'model.onnx');
    let session: any;
    try {
      session = await ort.InferenceSession.create(modelPath, {
        executionProviders: ['cpu'],
      });
    } catch (err) {
      // Detect corrupted ONNX files (protobuf parse errors, truncated files)
      const msg = err instanceof Error ? err.message : String(err);
      if (/protobuf|onnx|parse|corrupt|truncat/i.test(msg)) {
        // Delete corrupted model and re-download
        const { removeModel } = await import('./model-cache');
        removeModel(modelId, options?.cacheDir);
        sessionCache.delete(cacheKey);

        const freshDir = await ensureModel(modelId, { quantized, cacheDir: options?.cacheDir });
        const freshPath = path.join(freshDir, 'model.onnx');
        session = await ort.InferenceSession.create(freshPath, {
          executionProviders: ['cpu'],
        });
      } else {
        throw err;
      }
    }

    // Load tokenizer via @huggingface/transformers
    let AutoTokenizer: any;
    try {
      const transformers: any = await import('@huggingface/transformers');
      AutoTokenizer = transformers.AutoTokenizer;
    } catch {
      throw new Error(
        'OnnxSession requires @huggingface/transformers for tokenization. ' +
          'Install with: npm install @huggingface/transformers',
      );
    }

    // Load tokenizer from local directory (model-cache already downloaded the files)
    let tokenizer: any;
    try {
      tokenizer = await AutoTokenizer.from_pretrained(modelDir);
    } catch {
      // Fallback: load from HuggingFace Hub by model ID
      tokenizer = await AutoTokenizer.from_pretrained(modelId);
    }

    // Load config.json for label mapping
    const configPath = path.join(modelDir, 'config.json');
    const config = fs.existsSync(configPath)
      ? JSON.parse(fs.readFileSync(configPath, 'utf-8'))
      : {};

    const maxLength = options?.maxLength ?? 512;
    const instance = new OnnxSession(
      session,
      tokenizer,
      config,
      maxLength,
      modelId,
    );
    sessionCache.set(cacheKey, instance);
    return instance;
  }

  /** id → label mapping from config.json. */
  get id2label(): Record<number, string> {
    return this._config.id2label ?? {};
  }

  /**
   * Text classification — returns labels sorted by score (descending).
   *
   * For injection detection, toxicity, etc.
   */
  async classify(
    text: string,
    options?: { topK?: number | null },
  ): Promise<Array<{ label: string; score: number }>> {
    const feeds = await this._tokenize(text);
    const logits = await this._runInference(feeds);
    return this._logitsToLabels(logits, options);
  }

  /**
   * Cross-encoder classification — takes a text pair (premise, hypothesis).
   *
   * For hallucination detection (source vs generated text).
   */
  async classifyPair(
    text: string,
    textPair: string,
    options?: { topK?: number | null },
  ): Promise<Array<{ label: string; score: number }>> {
    const feeds = await this._tokenize(text, textPair);
    const logits = await this._runInference(feeds);
    return this._logitsToLabels(logits, options);
  }

  /**
   * Token classification (NER) — returns entity spans with scores.
   *
   * Implements simple BIO tag aggregation: contiguous I- tokens following
   * a B- token are merged into a single entity span.
   */
  async tokenClassify(
    text: string,
  ): Promise<
    Array<{
      entity_group: string;
      score: number;
      word: string;
      start: number;
      end: number;
    }>
  > {
    const ort = await import('onnxruntime-node');

    const encoded = this._tokenizer(text, {
      truncation: true,
      max_length: this._maxLength,
      padding: false,
      return_offsets_mapping: true,
    });

    const inputIds = toBigInt64Array(encoded.input_ids);
    const attentionMask = toBigInt64Array(encoded.attention_mask);
    const seqLen = inputIds.length;

    const feeds: Record<string, any> = {
      input_ids: new ort.Tensor('int64', inputIds, [1, seqLen]),
      attention_mask: new ort.Tensor('int64', attentionMask, [1, seqLen]),
    };

    if (this._session.inputNames.includes('token_type_ids')) {
      const tokenTypeIds = encoded.token_type_ids
        ? toBigInt64Array(encoded.token_type_ids)
        : new BigInt64Array(seqLen);
      feeds.token_type_ids = new ort.Tensor('int64', tokenTypeIds, [
        1,
        seqLen,
      ]);
    }

    const output = await this._session.run(feeds);
    const logits = output.logits.data as Float32Array;
    const numLabels =
      Object.keys(this.id2label).length || logits.length / seqLen;

    // Extract offset mapping for character-level span info
    const offsets: Array<[number, number]> = [];
    if (encoded.offsets_mapping) {
      const raw = encoded.offsets_mapping;
      const data = raw.data ?? raw;
      for (let i = 0; i < seqLen; i++) {
        offsets.push([Number(data[i * 2] ?? 0), Number(data[i * 2 + 1] ?? 0)]);
      }
    }

    // Aggregate tokens into entity spans (simple BIO aggregation)
    const entities: Array<{
      entity_group: string;
      score: number;
      word: string;
      start: number;
      end: number;
    }> = [];

    let current: {
      label: string;
      scoreSum: number;
      count: number;
      start: number;
      end: number;
    } | null = null;

    const flushCurrent = () => {
      if (!current) return;
      entities.push({
        entity_group: current.label,
        score: Math.round((current.scoreSum / current.count) * 100) / 100,
        word: text.slice(current.start, current.end),
        start: current.start,
        end: current.end,
      });
      current = null;
    };

    for (let i = 0; i < seqLen; i++) {
      const offset = offsets[i];
      // Skip special tokens (CLS, SEP, PAD have offset [0,0] except for the first real token)
      if (!offset || (offset[0] === 0 && offset[1] === 0 && i > 0)) {
        flushCurrent();
        continue;
      }

      // Get best label for this token
      const tokenLogits: number[] = [];
      for (let j = 0; j < numLabels; j++) {
        tokenLogits.push(logits[i * numLabels + j]);
      }
      const probs = softmax(tokenLogits);
      let bestIdx = 0;
      for (let j = 1; j < probs.length; j++) {
        if (probs[j] > probs[bestIdx]) bestIdx = j;
      }
      const label = this.id2label[bestIdx] ?? `LABEL_${bestIdx}`;
      const score = probs[bestIdx];

      // Outside entity
      if (label === 'O' || label === 'LABEL_0') {
        flushCurrent();
        continue;
      }

      // Extract base label (strip B-/I- prefix)
      const baseLabel = label.replace(/^[BI]-/, '');
      const isBeginning = label.startsWith('B-');

      if (current && current.label === baseLabel && !isBeginning) {
        // Continue existing entity
        current.scoreSum += score;
        current.count += 1;
        current.end = offset[1];
      } else {
        // Start new entity
        flushCurrent();
        current = {
          label: baseLabel,
          scoreSum: score,
          count: 1,
          start: offset[0],
          end: offset[1],
        };
      }
    }
    flushCurrent();

    return entities;
  }

  /**
   * Sentence embedding — mean-pooled hidden states.
   *
   * For semantic similarity, topic matching, drift detection.
   * Works with sentence-transformer models (e.g. all-MiniLM-L6-v2).
   */
  async embed(text: string): Promise<Float32Array> {
    const feeds = await this._tokenize(text);
    const output = await this._session.run(feeds);

    // Embedding models may output 'sentence_embedding' (already pooled)
    // or 'last_hidden_state' / 'token_embeddings' (needs mean pooling)
    if (output.sentence_embedding) {
      return new Float32Array(output.sentence_embedding.data as Float32Array);
    }

    const hiddenKey = output.last_hidden_state
      ? 'last_hidden_state'
      : output.token_embeddings
        ? 'token_embeddings'
        : Object.keys(output)[0];
    const data = output[hiddenKey].data as Float32Array;
    const dims = output[hiddenKey].dims as number[]; // [1, seq_len, hidden_dim]
    const seqLen = dims[1];
    const hiddenDim = dims[2];

    // Mean pooling over attended tokens
    const mask = feeds.attention_mask.data;
    const pooled = new Float32Array(hiddenDim);
    let count = 0;
    for (let i = 0; i < seqLen; i++) {
      if (Number(mask[i]) === 1) {
        for (let j = 0; j < hiddenDim; j++) {
          pooled[j] += data[i * hiddenDim + j];
        }
        count++;
      }
    }
    if (count > 0) {
      for (let j = 0; j < hiddenDim; j++) pooled[j] /= count;
    }
    return pooled;
  }

  /**
   * Compute cosine similarity between two embedding vectors.
   * Returns a value in [-1, 1], where 1 = identical.
   */
  static cosine(a: Float32Array, b: Float32Array): number {
    let dot = 0;
    let normA = 0;
    let normB = 0;
    for (let i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    return denom === 0 ? 0 : dot / denom;
  }

  /** Clear all cached sessions. */
  static clearCache(): void {
    sessionCache.clear();
  }

  // -- Private helpers --------------------------------------------------------

  /** Tokenize text (and optional text pair) into ONNX-compatible tensors. */
  private async _tokenize(
    text: string,
    textPair?: string,
  ): Promise<Record<string, any>> {
    const ort = await import('onnxruntime-node');

    const tokenizerArgs: any[] = [text];
    const tokenizerOpts: Record<string, any> = {
      truncation: true,
      max_length: this._maxLength,
      padding: false,
    };

    if (textPair) {
      tokenizerOpts.text_pair = textPair;
    }

    const encoded = this._tokenizer(...tokenizerArgs, tokenizerOpts);

    const inputIds = toBigInt64Array(encoded.input_ids);
    const attentionMask = toBigInt64Array(encoded.attention_mask);
    const seqLen = inputIds.length;

    const feeds: Record<string, any> = {
      input_ids: new ort.Tensor('int64', inputIds, [1, seqLen]),
      attention_mask: new ort.Tensor('int64', attentionMask, [1, seqLen]),
    };

    if (this._session.inputNames.includes('token_type_ids')) {
      const tokenTypeIds = encoded.token_type_ids
        ? toBigInt64Array(encoded.token_type_ids)
        : new BigInt64Array(seqLen);
      feeds.token_type_ids = new ort.Tensor('int64', tokenTypeIds, [
        1,
        seqLen,
      ]);
    }

    return feeds;
  }

  /** Run ONNX inference and return raw logits. */
  private async _runInference(feeds: Record<string, any>): Promise<number[]> {
    const output = await this._session.run(feeds);
    return Array.from(output.logits.data as Float32Array);
  }

  /** Convert logits to sorted label-score pairs. */
  private _logitsToLabels(
    logits: number[],
    options?: { topK?: number | null },
  ): Array<{ label: string; score: number }> {
    const probs = softmax(logits);
    const results = probs.map((score, i) => ({
      label: this.id2label[i] ?? `LABEL_${i}`,
      score,
    }));
    results.sort((a, b) => b.score - a.score);

    if (options?.topK === null) return results;
    return results.slice(0, options?.topK ?? 1);
  }
}

/**
 * Convert tokenizer output (Tensor, BigInt64Array, or number[])
 * to BigInt64Array for ONNX Runtime.
 */
function toBigInt64Array(data: any): BigInt64Array {
  // Handle @huggingface/transformers Tensor objects
  if (data?.data) {
    const arr = data.data;
    if (arr instanceof BigInt64Array) return arr;
    return new BigInt64Array(Array.from(arr, (v: any) => BigInt(v)));
  }
  if (data instanceof BigInt64Array) return data;
  if (Array.isArray(data)) {
    return new BigInt64Array(data.map((v: any) => BigInt(v)));
  }
  return new BigInt64Array(Array.from(data, (v: any) => BigInt(v)));
}
