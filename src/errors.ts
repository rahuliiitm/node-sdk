/**
 * Security-related error types.
 */

import type { BudgetViolation } from './internal/cost-guard';
import type { InjectionAnalysis } from './internal/injection';
import type { ContentViolation } from './internal/content-filter';
import type { ComplianceViolation } from './internal/compliance';

export class PromptInjectionError extends Error {
  readonly analysis: InjectionAnalysis;

  constructor(analysis: InjectionAnalysis) {
    super(
      `Prompt injection detected (risk: ${analysis.riskScore}, categories: ${analysis.triggered.join(', ')})`,
    );
    this.name = 'PromptInjectionError';
    this.analysis = analysis;
  }
}

export class CostLimitError extends Error {
  readonly violation: BudgetViolation;

  constructor(violation: BudgetViolation) {
    super(
      `Cost limit exceeded: ${violation.type} — current: $${violation.currentSpend.toFixed(4)}, limit: $${violation.limit.toFixed(4)}`,
    );
    this.name = 'CostLimitError';
    this.violation = violation;
  }
}

export class ContentViolationError extends Error {
  readonly violations: ContentViolation[];

  constructor(violations: ContentViolation[]) {
    const categories = [...new Set(violations.map((v) => v.category))].join(', ');
    super(`Content policy violation: ${categories}`);
    this.name = 'ContentViolationError';
    this.violations = violations;
  }
}

export class ComplianceError extends Error {
  readonly violations: ComplianceViolation[];

  constructor(violations: ComplianceViolation[]) {
    const messages = violations.map((v) => v.message).join('; ');
    super(`Compliance check failed: ${messages}`);
    this.name = 'ComplianceError';
    this.violations = violations;
  }
}
