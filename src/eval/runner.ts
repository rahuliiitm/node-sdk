/**
 * Evaluation engine — runs test cases against guardrails, collects metrics.
 * @internal
 */

import { detectInjection } from '../internal/injection';
import { detectJailbreak } from '../internal/jailbreak';
import { detectPII } from '../internal/pii';
import { detectContentViolations, hasBlockingViolation } from '../internal/content-filter';
import { scanUnicode } from '../internal/unicode-sanitizer';
import { detectSecrets } from '../internal/secret-detection';
import { checkToolCalls, type ToolCallInfo } from '../internal/tool-guard';
import type {
  EvalConfig,
  EvalReport,
  EvalSuite,
  SuiteMetrics,
  SuiteResult,
  TestCase,
  TestCaseResult,
} from './types';

/**
 * Run a single test case against its guardrail.
 * Returns 'blocked', 'detected', or 'allowed'.
 */
function runCase(guardrail: string, tc: TestCase): { actual: string; details?: string } {
  switch (guardrail) {
    case 'injection': {
      const result = detectInjection(tc.prompt);
      if (result.riskScore >= 0.5) {
        return { actual: 'blocked', details: `risk=${result.riskScore}` };
      }
      return { actual: 'allowed' };
    }

    case 'jailbreak': {
      const result = detectJailbreak(tc.prompt);
      if (result.riskScore >= 0.5) {
        return { actual: 'blocked', details: `risk=${result.riskScore}` };
      }
      return { actual: 'allowed' };
    }

    case 'pii': {
      const detections = detectPII(tc.prompt);
      if (detections.length > 0) {
        const types = [...new Set(detections.map((d) => d.type))];
        return { actual: 'detected', details: types.join(',') };
      }
      return { actual: 'allowed' };
    }

    case 'content': {
      const violations = detectContentViolations(tc.prompt, 'input');
      if (hasBlockingViolation(violations)) {
        return { actual: 'blocked', details: violations.map((v) => v.category).join(',') };
      }
      return { actual: 'allowed' };
    }

    case 'unicode': {
      const result = scanUnicode(tc.prompt);
      if (result.threats.length > 0) {
        return { actual: 'detected', details: result.threats.map((t) => t.type).join(',') };
      }
      return { actual: 'allowed' };
    }

    case 'secrets': {
      const detections = detectSecrets(tc.prompt);
      if (detections.length > 0) {
        return { actual: 'detected', details: detections.map((d) => d.type).join(',') };
      }
      return { actual: 'allowed' };
    }

    case 'tool_guard': {
      // Parse tool call from JSON prompt
      try {
        const parsed = JSON.parse(tc.prompt);
        const toolCall: ToolCallInfo = {
          name: parsed.tool || '',
          arguments: typeof parsed.args === 'string' ? parsed.args : JSON.stringify(parsed.args || {}),
        };
        const result = checkToolCalls([toolCall], {
          dangerousArgDetection: true,
          action: 'block',
        });
        if (result.blocked) {
          return { actual: 'blocked', details: result.violations.map((v) => v.type).join(',') };
        }
        return { actual: 'allowed' };
      } catch {
        return { actual: 'allowed', details: 'invalid JSON' };
      }
    }

    default:
      return { actual: 'allowed', details: `unknown guardrail: ${guardrail}` };
  }
}

/**
 * Compute precision, recall, F1, and pass rate from test case results.
 */
function computeMetrics(guardrail: string, results: TestCaseResult[]): SuiteMetrics {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  for (const r of results) {
    const expectedPositive = r.expected === 'blocked' || r.expected === 'detected';
    const actualPositive = r.actual === 'blocked' || r.actual === 'detected';

    if (expectedPositive && actualPositive) tp++;
    else if (!expectedPositive && actualPositive) fp++;
    else if (!expectedPositive && !actualPositive) tn++;
    else fn++;
  }

  const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 1;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const passed = results.filter((r) => r.pass).length;
  const totalLatency = results.reduce((sum, r) => sum + r.latencyMs, 0);

  return {
    guardrail,
    total: results.length,
    passed,
    failed: results.length - passed,
    truePositives: tp,
    falsePositives: fp,
    trueNegatives: tn,
    falseNegatives: fn,
    precision: Math.round(precision * 1000) / 1000,
    recall: Math.round(recall * 1000) / 1000,
    f1: Math.round(f1 * 1000) / 1000,
    passRate: results.length > 0 ? Math.round((passed / results.length) * 1000) / 1000 : 1,
    avgLatencyMs: results.length > 0 ? Math.round(totalLatency / results.length * 100) / 100 : 0,
  };
}

/**
 * Run a suite of test cases against a guardrail.
 */
function runSuite(suite: EvalSuite): SuiteResult {
  const results: TestCaseResult[] = [];

  for (const tc of suite.cases) {
    const start = performance.now();
    const { actual, details } = runCase(suite.guardrail, tc);
    const latencyMs = Math.round((performance.now() - start) * 100) / 100;

    const pass = actual === tc.expected;
    results.push({
      prompt: tc.prompt,
      expected: tc.expected,
      actual,
      pass,
      latencyMs,
      label: tc.label,
      details,
    });
  }

  return {
    guardrail: suite.guardrail,
    cases: results,
    metrics: computeMetrics(suite.guardrail, results),
  };
}

/**
 * Run the evaluation engine.
 */
export function runEval(config: EvalConfig): EvalReport {
  const suiteResults: SuiteResult[] = [];

  for (const suite of config.suites) {
    suiteResults.push(runSuite(suite));
  }

  const totalCases = suiteResults.reduce((s, r) => s + r.metrics.total, 0);
  const totalPassed = suiteResults.reduce((s, r) => s + r.metrics.passed, 0);
  const totalLatency = suiteResults.reduce(
    (s, r) => s + r.metrics.avgLatencyMs * r.metrics.total,
    0,
  );

  return {
    name: config.name ?? 'LaunchPromptly Eval',
    timestamp: new Date().toISOString(),
    suites: suiteResults,
    overall: {
      total: totalCases,
      passed: totalPassed,
      failed: totalCases - totalPassed,
      passRate: totalCases > 0 ? Math.round((totalPassed / totalCases) * 1000) / 1000 : 1,
      avgLatencyMs: totalCases > 0 ? Math.round((totalLatency / totalCases) * 100) / 100 : 0,
    },
  };
}
