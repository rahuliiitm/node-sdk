#!/usr/bin/env node
/**
 * CLI for pre-downloading ML models.
 *
 * Usage:
 *   npx launchpromptly download-models
 *   npx launchpromptly download-models --models toxicity,injection
 *   npx launchpromptly download-models --cache-dir /app/.models
 */

import { ensureModel, MODEL_NAME_MAP, getRegisteredModels } from './model-cache';
import * as fs from 'fs';
import * as path from 'path';

/** Resolve a model specifier (friendly name or full HF ID) to a model ID. */
function resolveModelId(specifier: string): string {
  // Check friendly name map first
  if (MODEL_NAME_MAP[specifier]) return MODEL_NAME_MAP[specifier];
  // Check if it's already a registered model ID
  const registered = getRegisteredModels();
  if (registered.includes(specifier)) return specifier;
  throw new Error(
    `Unknown model: "${specifier}". ` +
    `Available names: ${Object.keys(MODEL_NAME_MAP).join(', ')}. ` +
    `Available IDs: ${registered.join(', ')}`,
  );
}

/** Get total size of a directory in bytes. */
function dirSize(dir: string): number {
  if (!fs.existsSync(dir)) return 0;
  let total = 0;
  for (const entry of fs.readdirSync(dir)) {
    const p = path.join(dir, entry);
    const stat = fs.statSync(p);
    total += stat.isDirectory() ? dirSize(p) : stat.size;
  }
  return total;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || (args.includes('--help') && !args[0]?.match(/^(download-models|eval)$/))) {
    console.log(`Usage: launchpromptly <command> [options]

Commands:
  download-models    Download ML models for enhanced detection
  eval               Run guardrail test suites

Run "launchpromptly <command> --help" for command-specific help.`);
    process.exit(0);
  }

  if (args[0] === 'download-models' && args.includes('--help')) {
    console.log(`Usage: launchpromptly download-models [options]

Options:
  --models <list>      Comma-separated model names (default: all)
                       Names: ${Object.keys(MODEL_NAME_MAP).join(', ')}
  --cache-dir <path>   Directory to store models (default: ~/.launchpromptly/models)
  --help               Show this help message

Examples:
  launchpromptly download-models
  launchpromptly download-models --models toxicity,injection
  launchpromptly download-models --cache-dir /app/.models`);
    process.exit(0);
  }

  const command = args[0];

  // Dispatch to eval command
  if (command === 'eval') {
    const { evalMain } = await import('../eval/cli');
    const code = await evalMain(args.slice(1));
    process.exit(code);
  }

  if (command && command !== 'download-models') {
    console.error(`Unknown command: ${command}. Use "download-models" or "eval".`);
    process.exit(1);
  }

  // Parse --models
  let modelIds: string[];
  const modelsIdx = args.indexOf('--models');
  if (modelsIdx !== -1 && args[modelsIdx + 1]) {
    const names = args[modelsIdx + 1].split(',').map((s) => s.trim());
    modelIds = names.map(resolveModelId);
  } else {
    // Default: download toxicity + injection (the models used in production)
    modelIds = [
      MODEL_NAME_MAP['toxicity'],
      MODEL_NAME_MAP['injection'],
    ];
  }

  // Parse --cache-dir
  const cacheDirIdx = args.indexOf('--cache-dir');
  const cacheDir = cacheDirIdx !== -1 && args[cacheDirIdx + 1]
    ? args[cacheDirIdx + 1]
    : undefined;

  console.log(`Downloading ${modelIds.length} model(s)...`);
  if (cacheDir) console.log(`Cache directory: ${cacheDir}`);

  let totalSize = 0;
  for (const modelId of modelIds) {
    const friendlyName = Object.entries(MODEL_NAME_MAP)
      .find(([, id]) => id === modelId)?.[0] ?? modelId;

    process.stdout.write(`  ${friendlyName} (${modelId})... `);

    try {
      // protectai models don't have quantized ONNX
      const quantized = !modelId.startsWith('protectai/');
      const modelDir = await ensureModel(modelId, { quantized, cacheDir });
      const size = dirSize(modelDir);
      totalSize += size;
      console.log(`OK (${formatBytes(size)})`);
    } catch (err) {
      console.log(`FAILED`);
      console.error(`    ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
  }

  console.log(`\nTotal: ${formatBytes(totalSize)}`);
  console.log('All models downloaded.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
