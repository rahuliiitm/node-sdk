/**
 * Security-related error types.
 */

import type { BudgetViolation } from './internal/cost-guard';
import type { InjectionAnalysis } from './internal/injection';
import type { JailbreakAnalysis } from './internal/jailbreak';
import type { ContentViolation } from './internal/content-filter';
import type { ModelPolicyViolation } from './internal/model-policy';
import type { TopicViolation } from './internal/topic-guard';
import type { StreamViolation } from './types';
import type { ToolGuardViolation } from './internal/tool-guard';
import type { ChainOfThoughtViolation } from './internal/cot-guard';
import type { ConversationGuardViolation } from './internal/conversation-guard';
import type { ResponseJudgment } from './internal/response-judge';
import type { SchemaValidationError as SchemaError } from './internal/schema-validator';

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

export class ModelPolicyError extends Error {
  readonly violation: ModelPolicyViolation;

  constructor(violation: ModelPolicyViolation) {
    super(`Model policy violation: ${violation.message}`);
    this.name = 'ModelPolicyError';
    this.violation = violation;
  }
}

export class OutputSchemaError extends Error {
  readonly validationErrors: SchemaError[];
  readonly responseText: string;

  constructor(validationErrors: SchemaError[], responseText: string) {
    const summary = validationErrors.slice(0, 3).map((e) => e.message).join('; ');
    super(`Output schema validation failed: ${summary}`);
    this.name = 'OutputSchemaError';
    this.validationErrors = validationErrors;
    this.responseText = responseText;
  }
}

export class JailbreakError extends Error {
  readonly analysis: JailbreakAnalysis;

  constructor(analysis: JailbreakAnalysis) {
    super(
      `Jailbreak detected (risk: ${analysis.riskScore}, categories: ${analysis.triggered.join(', ')})`,
    );
    this.name = 'JailbreakError';
    this.analysis = analysis;
  }
}

export class TopicViolationError extends Error {
  readonly violation: TopicViolation;

  constructor(violation: TopicViolation) {
    super(
      `Topic violation: ${violation.type}${violation.topic ? ` — ${violation.topic}` : ''}`,
    );
    this.name = 'TopicViolationError';
    this.violation = violation;
  }
}

export class StreamAbortError extends Error {
  readonly violation: StreamViolation;
  readonly partialResponse: string;
  readonly approximateTokens: number;

  constructor(violation: StreamViolation, partialResponse: string) {
    super(`Stream aborted: ${violation.type} violation detected at offset ${violation.offset}`);
    this.name = 'StreamAbortError';
    this.violation = violation;
    this.partialResponse = partialResponse;
    this.approximateTokens = Math.ceil(partialResponse.length / 4);
  }
}

export class ToolGuardError extends Error {
  readonly violations: ToolGuardViolation[];

  constructor(violations: ToolGuardViolation[]) {
    const summary = violations.map((v) => `${v.type}: ${v.toolName}`).join(', ');
    super(`Tool guard violation: ${summary}`);
    this.name = 'ToolGuardError';
    this.violations = violations;
  }
}

export class ChainOfThoughtError extends Error {
  readonly violations: ChainOfThoughtViolation[];

  constructor(violations: ChainOfThoughtViolation[]) {
    const summary = violations.map((v) => v.type).join(', ');
    super(`Chain-of-thought violation: ${summary}`);
    this.name = 'ChainOfThoughtError';
    this.violations = violations;
  }
}

export class ConversationGuardError extends Error {
  readonly violation: ConversationGuardViolation;

  constructor(violation: ConversationGuardViolation) {
    super(`Conversation guard: ${violation.type} at turn ${violation.currentTurn} — ${violation.details}`);
    this.name = 'ConversationGuardError';
    this.violation = violation;
  }
}

export class ResponseBoundaryError extends Error {
  readonly judgment: ResponseJudgment;

  constructor(judgment: ResponseJudgment) {
    const types = [...new Set(judgment.violations.map((v) => v.type))].join(', ');
    super(
      `Response boundary violation: ${types} (compliance: ${judgment.complianceScore.toFixed(2)}, severity: ${judgment.severity})`,
    );
    this.name = 'ResponseBoundaryError';
    this.judgment = judgment;
  }
}
