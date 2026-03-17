/**
 * Model cache — downloads and caches ONNX model files from HuggingFace Hub.
 *
 * Models are stored in ~/.launchpromptly/models/<model-id>/
 * and reused across sessions.
 *
 * @module
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const DEFAULT_CACHE_DIR = path.join(os.homedir(), '.launchpromptly', 'models');

const MIN_ONNX_FILE_SIZE = 1024; // 1KB — any valid model is much larger
const MAX_DOWNLOAD_RETRIES = 3;
const BASE_RETRY_DELAY_MS = 1000;

/**
 * Check that a cached ONNX file looks valid.
 * Verifies minimum file size and ONNX protobuf magic byte (0x08 = ir_version field).
 */
export function validateOnnxFile(filePath: string): boolean {
  try {
    const stats = fs.statSync(filePath);
    if (stats.size < MIN_ONNX_FILE_SIZE) return false;

    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(4);
    fs.readSync(fd, buf, 0, 4, 0);
    fs.closeSync(fd);

    return buf[0] === 0x08;
  } catch {
    return false;
  }
}

interface ModelEntry {
  /** HuggingFace repo to download from. Defaults to the model ID. */
  repo?: string;
  /** Path to FP32 ONNX model file within the repo. */
  onnxFile: string;
  /** Path to quantized (INT8) ONNX model file within the repo. */
  quantizedFile?: string;
  /** Additional files to download alongside the ONNX model. */
  files: string[];
}

/**
 * Registry of supported models and their HuggingFace file paths.
 *
 * The ONNX files live in the `onnx/` subdirectory of each repo
 * (the layout used by @huggingface/transformers and onnx-community).
 */
const MODEL_REGISTRY: Record<string, ModelEntry> = {
  'Xenova/bert-base-NER': {
    onnxFile: 'onnx/model.onnx',
    quantizedFile: 'onnx/model_quantized.onnx',
    files: [
      'tokenizer.json',
      'tokenizer_config.json',
      'config.json',
    ],
  },
  'Xenova/toxic-bert': {
    onnxFile: 'onnx/model.onnx',
    quantizedFile: 'onnx/model_quantized.onnx',
    files: [
      'tokenizer.json',
      'tokenizer_config.json',
      'config.json',
    ],
  },
  'protectai/deberta-v3-base-prompt-injection-v2': {
    onnxFile: 'onnx/model.onnx',
    files: [
      'onnx/tokenizer.json',
      'tokenizer_config.json',
      'config.json',
      'special_tokens_map.json',
    ],
  },
  'protectai/deberta-v3-small-prompt-injection-v2': {
    onnxFile: 'onnx/model.onnx',
    files: [
      'onnx/tokenizer.json',
      'tokenizer_config.json',
      'config.json',
      'special_tokens_map.json',
    ],
  },
  'Xenova/all-MiniLM-L6-v2': {
    onnxFile: 'onnx/model.onnx',
    quantizedFile: 'onnx/model_quantized.onnx',
    files: [
      'tokenizer.json',
      'tokenizer_config.json',
      'config.json',
    ],
  },
  'cross-encoder/ms-marco-MiniLM-L-6-v2': {
    onnxFile: 'onnx/model.onnx',
    quantizedFile: 'onnx/model_quantized.onnx',
    files: [
      'tokenizer.json',
      'tokenizer_config.json',
      'config.json',
    ],
  },
};

/** Friendly name → model ID mapping for the CLI. */
export const MODEL_NAME_MAP: Record<string, string> = {
  toxicity: 'Xenova/toxic-bert',
  injection: 'protectai/deberta-v3-base-prompt-injection-v2',
  'injection-small': 'protectai/deberta-v3-small-prompt-injection-v2',
  ner: 'Xenova/bert-base-NER',
  embedding: 'Xenova/all-MiniLM-L6-v2',
  nli: 'cross-encoder/ms-marco-MiniLM-L-6-v2',
};

/** Get list of all registered model IDs. */
export function getRegisteredModels(): string[] {
  return Object.keys(MODEL_REGISTRY);
}

export interface EnsureModelOptions {
  /** Use quantized model for faster inference and smaller size. Default: true */
  quantized?: boolean;
  /** Custom cache directory. Default: ~/.launchpromptly/models */
  cacheDir?: string;
}

/**
 * Ensure model files are downloaded and cached locally.
 * Returns the local directory path containing model.onnx and config files.
 *
 * Downloads on first call; subsequent calls return the cached path immediately.
 */
export async function ensureModel(
  modelId: string,
  options?: EnsureModelOptions,
): Promise<string> {
  const quantized = options?.quantized ?? true;
  const cacheDir = options?.cacheDir ?? DEFAULT_CACHE_DIR;
  const modelDir = path.join(cacheDir, modelId.replace(/\//g, '--'));

  const entry = MODEL_REGISTRY[modelId];
  if (!entry) {
    throw new Error(
      `Unknown model: ${modelId}. Supported models: ${Object.keys(MODEL_REGISTRY).join(', ')}`,
    );
  }

  const onnxRemotePath =
    quantized && entry.quantizedFile ? entry.quantizedFile : entry.onnxFile;
  const localOnnxPath = path.join(modelDir, 'model.onnx');

  // Fast path: already cached and valid
  if (
    fs.existsSync(localOnnxPath) &&
    fs.existsSync(path.join(modelDir, 'config.json')) &&
    validateOnnxFile(localOnnxPath)
  ) {
    return modelDir;
  }

  // Remove corrupted ONNX file so it gets re-downloaded
  if (fs.existsSync(localOnnxPath) && !validateOnnxFile(localOnnxPath)) {
    fs.unlinkSync(localOnnxPath);
  }

  fs.mkdirSync(modelDir, { recursive: true });

  const repo = entry.repo ?? modelId;

  // Download ONNX model file (always saved as model.onnx locally)
  if (!fs.existsSync(localOnnxPath)) {
    await downloadHFFile(repo, onnxRemotePath, localOnnxPath);
  }

  // Validate downloaded file
  if (!validateOnnxFile(localOnnxPath)) {
    fs.unlinkSync(localOnnxPath);
    throw new Error(
      `Downloaded ONNX file for ${modelId} failed integrity check. The file may be corrupted or incomplete.`,
    );
  }

  // Download supporting files (tokenizer, config, etc.)
  for (const file of entry.files) {
    const localPath = path.join(modelDir, path.basename(file));
    if (!fs.existsSync(localPath)) {
      await downloadHFFile(repo, file, localPath);
    }
  }

  return modelDir;
}

/**
 * Download a single file from HuggingFace Hub.
 * Retries up to 3 times with exponential backoff on server/network errors.
 * Uses atomic write (temp file + rename) to prevent partial downloads.
 */
async function downloadHFFile(
  repo: string,
  filePath: string,
  localPath: string,
): Promise<void> {
  const url = `https://huggingface.co/${repo}/resolve/main/${filePath}`;

  const headers: Record<string, string> = {};
  const hfToken = process.env.HF_TOKEN ?? process.env.HUGGING_FACE_HUB_TOKEN;
  if (hfToken) {
    headers['Authorization'] = `Bearer ${hfToken}`;
  }

  for (let attempt = 0; attempt < MAX_DOWNLOAD_RETRIES; attempt++) {
    try {
      const response = await fetch(url, { headers, redirect: 'follow' });

      if (!response.ok) {
        // Client errors (401, 404) won't change on retry
        if (response.status < 500) {
          const hint =
            response.status === 401
              ? ' This model may require authentication. Set the HF_TOKEN environment variable.'
              : response.status === 404
                ? ` File not found at ${url}. The ONNX weights may not be published for this model.`
                : '';
          throw new Error(
            `Failed to download ${filePath} from ${repo}: ${response.status} ${response.statusText}.${hint}`,
          );
        }
        // Server error — retryable
        throw new Error(`Server error ${response.status} downloading ${filePath} from ${repo}`);
      }

      const buffer = await response.arrayBuffer();
      fs.mkdirSync(path.dirname(localPath), { recursive: true });

      // Atomic write: temp file then rename
      const tmpPath = localPath + '.tmp';
      fs.writeFileSync(tmpPath, Buffer.from(buffer));
      fs.renameSync(tmpPath, localPath);
      return;
    } catch (err) {
      // Don't retry client errors
      if (err instanceof Error && /\b(401|404)\b/.test(err.message)) {
        throw err;
      }
      if (attempt < MAX_DOWNLOAD_RETRIES - 1) {
        const delay = BASE_RETRY_DELAY_MS * Math.pow(2, attempt);
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }
      throw err;
    }
  }
}

/** Get the default cache directory. */
export function getCacheDir(): string {
  return DEFAULT_CACHE_DIR;
}

/** Remove a cached model. */
export function removeModel(modelId: string, cacheDir?: string): void {
  const dir = path.join(
    cacheDir ?? DEFAULT_CACHE_DIR,
    modelId.replace(/\//g, '--'),
  );
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true });
  }
}

/** List all cached model IDs. */
export function listCachedModels(cacheDir?: string): string[] {
  const dir = cacheDir ?? DEFAULT_CACHE_DIR;
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((name) =>
      fs.existsSync(path.join(dir, name, 'model.onnx')),
    )
    .map((name) => name.replace(/--/g, '/'));
}
