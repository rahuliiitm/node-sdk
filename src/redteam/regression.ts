/**
 * Red Team Regression Tracking — Compare reports over time to detect security regressions.
 * @module
 */

import type { AttackCategory, RedTeamReport, CategoryScore } from './types';

// ── Types ────────────────────────────────────────────────────────────────────

export interface RedTeamBaseline {
  /** ISO timestamp of the baseline. */
  timestamp: string;
  /** Overall security score. */
  securityScore: number;
  /** Per-category scores. */
  categoryScores: Record<string, number>;
  /** Total attacks executed. */
  attackCount: number;
  /** Hash of the system prompt (for change detection). */
  promptHash: string;
}

export interface CategoryRegression {
  category: string;
  previousScore: number;
  currentScore: number;
  change: number;
}

export interface RegressionReport {
  /** Change in overall security score (positive = improvement). */
  scoreChange: number;
  /** Categories that got worse. */
  regressions: CategoryRegression[];
  /** Categories that got better. */
  improvements: CategoryRegression[];
  /** Vulnerability IDs not in the baseline. */
  newVulnerabilities: string[];
  /** Vulnerability IDs resolved since baseline. */
  resolvedVulnerabilities: string[];
  /** Overall recommendation. */
  recommendation: 'PASS' | 'WARN' | 'FAIL';
  /** Current report snapshot. */
  currentScore: number;
  /** Baseline score. */
  baselineScore: number;
}

// ── Functions ────────────────────────────────────────────────────────────────

/**
 * Create a baseline from a red team report for future comparison.
 */
export function createBaseline(report: RedTeamReport, promptHash?: string): RedTeamBaseline {
  const categoryScores: Record<string, number> = {};
  for (const cat of report.categories) {
    categoryScores[cat.category] = cat.score;
  }

  return {
    timestamp: new Date().toISOString(),
    securityScore: report.securityScore,
    categoryScores,
    attackCount: report.totalAttacks,
    promptHash: promptHash ?? '',
  };
}

/**
 * Compare a current red team report against a baseline to detect regressions.
 */
export function compareReports(current: RedTeamReport, baseline: RedTeamBaseline): RegressionReport {
  const scoreChange = current.securityScore - baseline.securityScore;

  // Per-category comparison
  const regressions: CategoryRegression[] = [];
  const improvements: CategoryRegression[] = [];

  const currentCategoryMap: Record<string, number> = {};
  for (const cat of current.categories) {
    currentCategoryMap[cat.category] = cat.score;
  }

  // Check categories from baseline
  const allCategories = new Set([
    ...Object.keys(baseline.categoryScores),
    ...Object.keys(currentCategoryMap),
  ]);

  for (const category of allCategories) {
    const prev = baseline.categoryScores[category] ?? 100; // New category defaults to 100 (untested)
    const curr = currentCategoryMap[category] ?? 100;
    const change = curr - prev;

    if (change < -5) {
      regressions.push({ category, previousScore: prev, currentScore: curr, change });
    } else if (change > 5) {
      improvements.push({ category, previousScore: prev, currentScore: curr, change });
    }
  }

  // Sort regressions by severity (biggest drop first)
  regressions.sort((a, b) => a.change - b.change);
  improvements.sort((a, b) => b.change - a.change);

  // Vulnerability diff
  const currentVulnIds = new Set(current.vulnerabilities.map((v) => v.attackId));
  const baselineVulnIds = new Set<string>(); // We don't store full vuln list in baseline — just IDs

  const newVulnerabilities = current.vulnerabilities
    .filter((v) => !baselineVulnIds.has(v.attackId))
    .map((v) => v.attackId);

  // Recommendation
  let recommendation: 'PASS' | 'WARN' | 'FAIL';
  if (scoreChange < -10 || regressions.some((r) => r.change < -15)) {
    recommendation = 'FAIL';
  } else if (scoreChange < -5 || regressions.length > 0) {
    recommendation = 'WARN';
  } else {
    recommendation = 'PASS';
  }

  return {
    scoreChange,
    regressions,
    improvements,
    newVulnerabilities,
    resolvedVulnerabilities: [], // Cannot determine without full vuln list in baseline
    recommendation,
    currentScore: current.securityScore,
    baselineScore: baseline.securityScore,
  };
}
