/**
 * Output formatters for eval results.
 * @internal
 */

import type { EvalReport } from './types';

/**
 * Format report as JSON string.
 */
export function formatJSON(report: EvalReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Format report as CSV.
 */
export function formatCSV(report: EvalReport): string {
  const lines: string[] = ['guardrail,prompt,expected,actual,pass,latency_ms,label'];

  for (const suite of report.suites) {
    for (const c of suite.cases) {
      const prompt = c.prompt.replace(/"/g, '""');
      lines.push(
        `${suite.guardrail},"${prompt}",${c.expected},${c.actual},${c.pass},${c.latencyMs},${c.label ?? ''}`,
      );
    }
  }

  return lines.join('\n');
}

/**
 * Format report as markdown table.
 */
export function formatMarkdown(report: EvalReport): string {
  const lines: string[] = [];

  lines.push(`# ${report.name}`);
  lines.push(`_${report.timestamp}_\n`);

  // Overall summary
  lines.push(`## Summary`);
  lines.push(`- **Total:** ${report.overall.total}`);
  lines.push(`- **Passed:** ${report.overall.passed}`);
  lines.push(`- **Failed:** ${report.overall.failed}`);
  lines.push(`- **Pass Rate:** ${(report.overall.passRate * 100).toFixed(1)}%`);
  lines.push(`- **Avg Latency:** ${report.overall.avgLatencyMs}ms\n`);

  // Per-suite metrics
  lines.push(`## Guardrail Metrics\n`);
  lines.push('| Guardrail | Total | Pass | Fail | Precision | Recall | F1 | Pass Rate |');
  lines.push('|-----------|-------|------|------|-----------|--------|----|-----------|');

  for (const suite of report.suites) {
    const m = suite.metrics;
    lines.push(
      `| ${m.guardrail} | ${m.total} | ${m.passed} | ${m.failed} | ${m.precision} | ${m.recall} | ${m.f1} | ${(m.passRate * 100).toFixed(1)}% |`,
    );
  }

  lines.push('');

  // Failed cases
  const failedCases = report.suites.flatMap((s) =>
    s.cases.filter((c) => !c.pass).map((c) => ({ guardrail: s.guardrail, ...c })),
  );

  if (failedCases.length > 0) {
    lines.push(`## Failed Cases (${failedCases.length})\n`);
    lines.push('| Guardrail | Label | Expected | Actual | Prompt (truncated) |');
    lines.push('|-----------|-------|----------|--------|-------------------|');

    for (const f of failedCases) {
      const prompt = f.prompt.length > 50 ? f.prompt.slice(0, 50) + '...' : f.prompt;
      lines.push(
        `| ${f.guardrail} | ${f.label ?? '-'} | ${f.expected} | ${f.actual} | ${prompt} |`,
      );
    }
  } else {
    lines.push('All tests passed!');
  }

  return lines.join('\n');
}
