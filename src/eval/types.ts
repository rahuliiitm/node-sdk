/**
 * Types for the eval CLI.
 * @internal
 */

export interface EvalConfig {
  name?: string;
  threshold?: number;
  security?: Record<string, unknown>;
  suites: EvalSuite[];
}

export interface EvalSuite {
  guardrail: GuardrailName;
  cases: TestCase[];
}

export type GuardrailName =
  | 'injection'
  | 'jailbreak'
  | 'pii'
  | 'content'
  | 'unicode'
  | 'secrets'
  | 'tool_guard';

export interface TestCase {
  prompt: string;
  expected: 'blocked' | 'allowed' | 'detected';
  /** For PII tests: expected PII types to find. */
  piiTypes?: string[];
  /** Optional label for this test case. */
  label?: string;
}

export interface TestCaseResult {
  prompt: string;
  expected: string;
  actual: string;
  pass: boolean;
  latencyMs: number;
  label?: string;
  details?: string;
}

export interface SuiteMetrics {
  guardrail: string;
  total: number;
  passed: number;
  failed: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1: number;
  passRate: number;
  avgLatencyMs: number;
}

export interface SuiteResult {
  guardrail: string;
  cases: TestCaseResult[];
  metrics: SuiteMetrics;
}

export interface EvalReport {
  name: string;
  timestamp: string;
  suites: SuiteResult[];
  overall: {
    total: number;
    passed: number;
    failed: number;
    passRate: number;
    avgLatencyMs: number;
  };
}
