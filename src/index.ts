export { LaunchPromptly, PromptNotFoundError } from './launch-promptly';
export { interpolate, extractVariables } from './template';
export type {
  LaunchPromptlyOptions,
  PromptOptions,
  WrapOptions,
  CustomerContext,
  RequestContext,
  SecurityOptions,
  PIISecurityOptions,
  InjectionSecurityOptions,
} from './types';

// Security errors
export {
  PromptInjectionError,
  CostLimitError,
  ContentViolationError,
  ComplianceError,
} from './errors';

// Security modules — public API
export { detectPII, mergeDetections, RegexPIIDetector, createCustomDetector } from './internal/pii';
export type {
  PIIType,
  PIIDetection,
  PIIDetectOptions,
  PIIDetectorProvider,
  CustomPIIPattern,
} from './internal/pii';

export { redactPII, deRedact } from './internal/redaction';
export type { RedactionStrategy, RedactionOptions, RedactionResult, MaskingOptions } from './internal/redaction';

export { detectInjection, mergeInjectionAnalyses, RuleInjectionDetector } from './internal/injection';
export type {
  InjectionAnalysis,
  InjectionOptions,
  InjectionDetectorProvider,
} from './internal/injection';

export { CostGuard } from './internal/cost-guard';
export type { CostGuardOptions, BudgetViolation } from './internal/cost-guard';

export { detectContentViolations, hasBlockingViolation, RuleContentFilter } from './internal/content-filter';
export type {
  ContentCategory,
  ContentFilterOptions,
  CustomPattern,
  ContentViolation,
  ContentFilterProvider,
} from './internal/content-filter';

export { checkCompliance, buildComplianceEventData } from './internal/compliance';
export type {
  ComplianceOptions,
  ComplianceCheckResult,
  ComplianceViolation,
  ComplianceEventData,
} from './internal/compliance';

export { createSecurityStream } from './internal/streaming';
export type {
  SecurityStreamOptions,
  SecurityStreamResult,
  StreamSecurityReport,
} from './internal/streaming';

// Backward-compatible alias
export { LaunchPromptly as PlanForge } from './launch-promptly';
export type { LaunchPromptlyOptions as PlanForgeOptions } from './types';
