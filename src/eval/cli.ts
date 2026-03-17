#!/usr/bin/env node
/**
 * CLI for running guardrail evaluations.
 *
 * Usage:
 *   npx launchpromptly eval
 *   npx launchpromptly eval --filter injection,jailbreak
 *   npx launchpromptly eval --format json
 *   npx launchpromptly eval --threshold 0.95
 *   npx launchpromptly eval --config guardrails.yaml
 *
 * @internal
 */

import { loadCorpus } from './corpus';
import { runEval } from './runner';
import { formatJSON, formatCSV, formatMarkdown } from './formatters';
import type { GuardrailName, EvalConfig } from './types';

function parseArgs(argv: string[]): {
  filter?: string[];
  format: 'markdown' | 'json' | 'csv';
  threshold?: number;
  config?: string;
  help: boolean;
} {
  let filter: string[] | undefined;
  let format: 'markdown' | 'json' | 'csv' = 'markdown';
  let threshold: number | undefined;
  let config: string | undefined;
  let help = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      help = true;
    } else if (arg === '--filter' && argv[i + 1]) {
      filter = argv[++i].split(',').map((s) => s.trim());
    } else if (arg === '--format' && argv[i + 1]) {
      const fmt = argv[++i].toLowerCase();
      if (fmt === 'json' || fmt === 'csv' || fmt === 'markdown') {
        format = fmt;
      }
    } else if (arg === '--threshold' && argv[i + 1]) {
      threshold = parseFloat(argv[++i]);
    } else if (arg === '--config' && argv[i + 1]) {
      config = argv[++i];
    }
  }

  return { filter, format, threshold, config, help };
}

export async function evalMain(argv: string[]): Promise<number> {
  const args = parseArgs(argv);

  if (args.help) {
    console.log(`
launchpromptly eval — Run guardrail test suites

Usage:
  npx launchpromptly eval [options]

Options:
  --filter <guardrails>   Comma-separated guardrails (injection,jailbreak,pii,content,unicode,secrets,tool_guard)
  --format <format>       Output format: markdown (default), json, csv
  --threshold <number>    Minimum pass rate (0-1). Exit code 1 if below threshold
  --config <path>         Path to YAML/JSON config file
  -h, --help              Show this help
`);
    return 0;
  }

  // Load test suites
  const suites = loadCorpus(args.filter as GuardrailName[] | undefined);

  if (suites.length === 0) {
    console.error('No test suites found. Check --filter values.');
    return 1;
  }

  const config: EvalConfig = {
    name: 'LaunchPromptly Eval',
    suites,
    threshold: args.threshold,
  };

  // Run evaluation
  const report = runEval(config);

  // Output results
  switch (args.format) {
    case 'json':
      console.log(formatJSON(report));
      break;
    case 'csv':
      console.log(formatCSV(report));
      break;
    case 'markdown':
    default:
      console.log(formatMarkdown(report));
      break;
  }

  // Check threshold
  if (args.threshold != null && report.overall.passRate < args.threshold) {
    console.error(
      `\nFAILED: Pass rate ${(report.overall.passRate * 100).toFixed(1)}% below threshold ${(args.threshold * 100).toFixed(1)}%`,
    );
    return 1;
  }

  return 0;
}
