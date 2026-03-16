import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { validateOnnxFile, ensureModel, removeModel, listCachedModels, getRegisteredModels, MODEL_NAME_MAP } from './model-cache';

// ── validateOnnxFile ─────────────────────────────────────────────────────────

describe('validateOnnxFile', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'model-cache-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should return false for missing file', () => {
    expect(validateOnnxFile(path.join(tmpDir, 'missing.onnx'))).toBe(false);
  });

  it('should return false for file smaller than 1KB', () => {
    const file = path.join(tmpDir, 'tiny.onnx');
    fs.writeFileSync(file, Buffer.alloc(512, 0x08));
    expect(validateOnnxFile(file)).toBe(false);
  });

  it('should return false for file with wrong magic byte', () => {
    const file = path.join(tmpDir, 'bad.onnx');
    const buf = Buffer.alloc(2048, 0);
    buf[0] = 0xFF; // wrong magic byte
    fs.writeFileSync(file, buf);
    expect(validateOnnxFile(file)).toBe(false);
  });

  it('should return true for file >= 1KB with correct magic byte (0x08)', () => {
    const file = path.join(tmpDir, 'good.onnx');
    const buf = Buffer.alloc(2048, 0);
    buf[0] = 0x08; // ONNX protobuf ir_version field
    fs.writeFileSync(file, buf);
    expect(validateOnnxFile(file)).toBe(true);
  });

  it('should return false for empty file', () => {
    const file = path.join(tmpDir, 'empty.onnx');
    fs.writeFileSync(file, Buffer.alloc(0));
    expect(validateOnnxFile(file)).toBe(false);
  });
});

// ── ensureModel ──────────────────────────────────────────────────────────────

describe('ensureModel', () => {
  it('should throw for unknown model ID', async () => {
    await expect(ensureModel('unknown/model')).rejects.toThrow(/Unknown model/);
  });
});

// ── removeModel ──────────────────────────────────────────────────────────────

describe('removeModel', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'model-cache-rm-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should remove existing model directory', () => {
    const modelDir = path.join(tmpDir, 'org--model');
    fs.mkdirSync(modelDir, { recursive: true });
    fs.writeFileSync(path.join(modelDir, 'model.onnx'), 'data');
    removeModel('org/model', tmpDir);
    expect(fs.existsSync(modelDir)).toBe(false);
  });

  it('should not throw for non-existent model', () => {
    expect(() => removeModel('missing/model', tmpDir)).not.toThrow();
  });
});

// ── listCachedModels ─────────────────────────────────────────────────────────

describe('listCachedModels', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'model-cache-list-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should return empty array for empty cache dir', () => {
    expect(listCachedModels(tmpDir)).toEqual([]);
  });

  it('should list cached models with model.onnx', () => {
    const modelDir = path.join(tmpDir, 'org--model');
    fs.mkdirSync(modelDir, { recursive: true });
    fs.writeFileSync(path.join(modelDir, 'model.onnx'), 'data');
    expect(listCachedModels(tmpDir)).toEqual(['org/model']);
  });

  it('should skip directories without model.onnx', () => {
    const modelDir = path.join(tmpDir, 'org--incomplete');
    fs.mkdirSync(modelDir, { recursive: true });
    fs.writeFileSync(path.join(modelDir, 'config.json'), '{}');
    expect(listCachedModels(tmpDir)).toEqual([]);
  });

  it('should return empty for non-existent cache dir', () => {
    expect(listCachedModels(path.join(tmpDir, 'nope'))).toEqual([]);
  });
});

// ── getRegisteredModels ─────────────────────────────────────────────────────

describe('getRegisteredModels', () => {
  it('should include Xenova/toxic-bert', () => {
    expect(getRegisteredModels()).toContain('Xenova/toxic-bert');
  });

  it('should include protectai/deberta-v3-base-prompt-injection-v2', () => {
    expect(getRegisteredModels()).toContain('protectai/deberta-v3-base-prompt-injection-v2');
  });

  it('should include protectai/deberta-v3-small-prompt-injection-v2', () => {
    expect(getRegisteredModels()).toContain('protectai/deberta-v3-small-prompt-injection-v2');
  });

  it('should NOT include meta-llama/Prompt-Guard-86M (no ONNX weights)', () => {
    expect(getRegisteredModels()).not.toContain('meta-llama/Prompt-Guard-86M');
  });

  it('should NOT include vectara/hallucination_evaluation_model (no ONNX weights)', () => {
    expect(getRegisteredModels()).not.toContain('vectara/hallucination_evaluation_model');
  });
});

// ── MODEL_NAME_MAP ──────────────────────────────────────────────────────────

describe('MODEL_NAME_MAP', () => {
  it('should map toxicity to Xenova/toxic-bert', () => {
    expect(MODEL_NAME_MAP['toxicity']).toBe('Xenova/toxic-bert');
  });

  it('should map injection to protectai model', () => {
    expect(MODEL_NAME_MAP['injection']).toBe('protectai/deberta-v3-base-prompt-injection-v2');
  });

  it('should map injection-small to protectai small model', () => {
    expect(MODEL_NAME_MAP['injection-small']).toBe('protectai/deberta-v3-small-prompt-injection-v2');
  });

  it('should map ner to Xenova/bert-base-NER', () => {
    expect(MODEL_NAME_MAP['ner']).toBe('Xenova/bert-base-NER');
  });
});

// ── ensureModel with cacheDir ───────────────────────────────────────────────

describe('ensureModel with cacheDir', () => {
  it('should throw for unknown model even with cacheDir', async () => {
    await expect(ensureModel('unknown/model', { cacheDir: '/tmp/test' })).rejects.toThrow(/Unknown model/);
  });
});
