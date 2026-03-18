import { createBaseline, compareReports, type RedTeamBaseline } from './regression';
import type { RedTeamReport, CategoryScore, Vulnerability } from './types';

function makeReport(overrides: Partial<RedTeamReport> = {}): RedTeamReport {
  return {
    securityScore: 80,
    categories: [
      { category: 'injection', score: 85, total: 10, blocked: 8, refused: 1, bypassed: 1, errors: 0, inconclusive: 0 },
      { category: 'jailbreak', score: 75, total: 10, blocked: 7, refused: 1, bypassed: 2, errors: 0, inconclusive: 0 },
    ],
    attacks: [],
    vulnerabilities: [],
    totalAttacks: 20,
    totalDurationMs: 5000,
    estimatedCostUsd: 0.10,
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function makeVuln(id: string, category = 'injection'): Vulnerability {
  return {
    severity: 'high',
    category: category as any,
    attackName: `attack-${id}`,
    attackId: id,
    description: 'Test vulnerability',
    remediation: 'Fix it',
  };
}

describe('createBaseline', () => {
  it('creates baseline from report', () => {
    const report = makeReport();
    const baseline = createBaseline(report, 'abc123');

    expect(baseline.securityScore).toBe(80);
    expect(baseline.categoryScores['injection']).toBe(85);
    expect(baseline.categoryScores['jailbreak']).toBe(75);
    expect(baseline.attackCount).toBe(20);
    expect(baseline.promptHash).toBe('abc123');
    expect(baseline.timestamp).toBeTruthy();
  });

  it('defaults promptHash to empty string', () => {
    const baseline = createBaseline(makeReport());
    expect(baseline.promptHash).toBe('');
  });
});

describe('compareReports', () => {
  it('detects score improvement', () => {
    const baseline: RedTeamBaseline = {
      timestamp: new Date().toISOString(),
      securityScore: 70,
      categoryScores: { injection: 65, jailbreak: 75 },
      attackCount: 20,
      promptHash: '',
    };
    const current = makeReport({ securityScore: 85 });
    const result = compareReports(current, baseline);

    expect(result.scoreChange).toBe(15);
    expect(result.recommendation).toBe('PASS');
    expect(result.currentScore).toBe(85);
    expect(result.baselineScore).toBe(70);
  });

  it('detects score regression', () => {
    const baseline: RedTeamBaseline = {
      timestamp: new Date().toISOString(),
      securityScore: 90,
      categoryScores: { injection: 95, jailbreak: 85 },
      attackCount: 20,
      promptHash: '',
    };
    const current = makeReport({
      securityScore: 60,
      categories: [
        { category: 'injection', score: 50, total: 10, blocked: 5, refused: 0, bypassed: 5, errors: 0, inconclusive: 0 },
        { category: 'jailbreak', score: 70, total: 10, blocked: 7, refused: 0, bypassed: 3, errors: 0, inconclusive: 0 },
      ],
    });
    const result = compareReports(current, baseline);

    expect(result.scoreChange).toBe(-30);
    expect(result.recommendation).toBe('FAIL');
    expect(result.regressions.length).toBeGreaterThan(0);
    expect(result.regressions[0].category).toBe('injection');
    expect(result.regressions[0].change).toBe(-45);
  });

  it('detects category improvements', () => {
    const baseline: RedTeamBaseline = {
      timestamp: new Date().toISOString(),
      securityScore: 70,
      categoryScores: { injection: 50 },
      attackCount: 10,
      promptHash: '',
    };
    const current = makeReport({
      securityScore: 85,
      categories: [
        { category: 'injection', score: 90, total: 10, blocked: 9, refused: 1, bypassed: 0, errors: 0, inconclusive: 0 },
      ],
    });
    const result = compareReports(current, baseline);

    expect(result.improvements.length).toBe(1);
    expect(result.improvements[0].category).toBe('injection');
    expect(result.improvements[0].change).toBe(40);
  });

  it('lists new vulnerabilities', () => {
    const baseline: RedTeamBaseline = {
      timestamp: new Date().toISOString(),
      securityScore: 80,
      categoryScores: {},
      attackCount: 10,
      promptHash: '',
    };
    const current = makeReport({
      vulnerabilities: [makeVuln('vuln-1'), makeVuln('vuln-2')],
    });
    const result = compareReports(current, baseline);

    expect(result.newVulnerabilities).toContain('vuln-1');
    expect(result.newVulnerabilities).toContain('vuln-2');
  });

  it('returns WARN for moderate regression', () => {
    const baseline: RedTeamBaseline = {
      timestamp: new Date().toISOString(),
      securityScore: 85,
      categoryScores: { injection: 85 },
      attackCount: 10,
      promptHash: '',
    };
    const current = makeReport({
      securityScore: 78,
      categories: [
        { category: 'injection', score: 78, total: 10, blocked: 7, refused: 1, bypassed: 2, errors: 0, inconclusive: 0 },
      ],
    });
    const result = compareReports(current, baseline);

    expect(result.recommendation).toBe('WARN');
  });

  it('returns PASS when scores are stable', () => {
    const baseline: RedTeamBaseline = {
      timestamp: new Date().toISOString(),
      securityScore: 80,
      categoryScores: { injection: 85, jailbreak: 75 },
      attackCount: 20,
      promptHash: '',
    };
    const result = compareReports(makeReport(), baseline);

    expect(result.recommendation).toBe('PASS');
    expect(result.regressions.length).toBe(0);
  });

  it('sorts regressions by severity', () => {
    const baseline: RedTeamBaseline = {
      timestamp: new Date().toISOString(),
      securityScore: 90,
      categoryScores: { injection: 90, jailbreak: 90, content_bypass: 90 },
      attackCount: 30,
      promptHash: '',
    };
    const current = makeReport({
      securityScore: 50,
      categories: [
        { category: 'injection', score: 70, total: 10, blocked: 7, refused: 0, bypassed: 3, errors: 0, inconclusive: 0 },
        { category: 'jailbreak', score: 50, total: 10, blocked: 5, refused: 0, bypassed: 5, errors: 0, inconclusive: 0 },
        { category: 'content_bypass', score: 60, total: 10, blocked: 6, refused: 0, bypassed: 4, errors: 0, inconclusive: 0 },
      ],
    });
    const result = compareReports(current, baseline);

    expect(result.regressions.length).toBe(3);
    // Sorted by change ascending (most negative first)
    expect(result.regressions[0].category).toBe('jailbreak');
    expect(result.regressions[0].change).toBe(-40);
  });
});
