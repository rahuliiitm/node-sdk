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
  'meta-llama/Prompt-Guard-86M': {
    onnxFile: 'onnx/model.onnx',
    quantizedFile: 'onnx/model_quantized.onnx',
    files: [
      'tokenizer.json',
      'tokenizer_config.json',
      'config.json',
      'special_tokens_map.json',
    ],
  },
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
  'vectara/hallucination_evaluation_model': {
    onnxFile: 'onnx/model.onnx',
    quantizedFile: 'onnx/model_quantized.onnx',
    files: [
      'tokenizer.json',
      'tokenizer_config.json',
      'config.json',
    ],
  },
};

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

  // Fast path: already cached
  if (
    fs.existsSync(localOnnxPath) &&
    fs.existsSync(path.join(modelDir, 'config.json'))
  ) {
    return modelDir;
  }

  fs.mkdirSync(modelDir, { recursive: true });

  const repo = entry.repo ?? modelId;

  // Download ONNX model file (always saved as model.onnx locally)
  if (!fs.existsSync(localOnnxPath)) {
    await downloadHFFile(repo, onnxRemotePath, localOnnxPath);
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
 * Supports HF_TOKEN for gated/private models.
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

  const response = await fetch(url, { headers, redirect: 'follow' });

  if (!response.ok) {
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

  const buffer = await response.arrayBuffer();
  fs.mkdirSync(path.dirname(localPath), { recursive: true });
  fs.writeFileSync(localPath, Buffer.from(buffer));
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
