export { LaunchPromptly } from './launch-promptly';
export type {
  LaunchPromptlyOptions,
  WrapOptions,
  CustomerContext,
  RequestContext,
  SecurityOptions,
  PIISecurityOptions,
  InjectionSecurityOptions,
  JailbreakSecurityOptions,
  CascadeThresholds,
  UnicodeSanitizerSecurityOptions,
  SecretDetectionSecurityOptions,
  TopicGuardSecurityOptions,
  OutputSafetySecurityOptions,
  PromptLeakageSecurityOptions,
  StreamGuardOptions,
  MaxResponseLength,
  StreamViolation,
  GuardrailEventType,
  GuardrailEvent,
  GuardrailEventHandlers,
} from './types';

// Security errors
export {
  PromptInjectionError,
  CostLimitError,
  ContentViolationError,
  ModelPolicyError,
  OutputSchemaError,
  StreamAbortError,
  JailbreakError,
  TopicViolationError,
  ToolGuardError,
  ChainOfThoughtError,
  ConversationGuardError,
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

export { checkModelPolicy } from './internal/model-policy';
export type { ModelPolicyOptions, ModelPolicyViolation } from './internal/model-policy';

export { validateSchema, validateOutputSchema } from './internal/schema-validator';
export type {
  JsonSchema,
  OutputSchemaOptions,
  SchemaValidationError as SchemaError,
} from './internal/schema-validator';

export { detectJailbreak, mergeJailbreakAnalyses, RuleJailbreakDetector } from './internal/jailbreak';
export type {
  JailbreakAnalysis,
  JailbreakOptions,
  JailbreakDetectorProvider,
} from './internal/jailbreak';

export { detectPromptLeakage } from './internal/prompt-leakage';
export type { PromptLeakageOptions, PromptLeakageResult } from './internal/prompt-leakage';

export { scanUnicode } from './internal/unicode-sanitizer';
export type {
  UnicodeSanitizeOptions,
  UnicodeScanResult,
  UnicodeThreat,
} from './internal/unicode-sanitizer';

export { detectSecrets } from './internal/secret-detection';
export type {
  SecretDetectionOptions,
  CustomSecretPattern,
  SecretDetection,
} from './internal/secret-detection';

export { checkTopicGuard } from './internal/topic-guard';
export type {
  TopicGuardOptions,
  TopicDefinition,
  TopicViolation,
} from './internal/topic-guard';

export { scanOutputSafety } from './internal/output-safety';
export type {
  OutputSafetyOptions,
  OutputSafetyCategory,
  OutputSafetyThreat,
} from './internal/output-safety';

// Tool guard
export { checkToolCalls, detectDangerousArgs, scanToolResult } from './internal/tool-guard';
export type {
  ToolGuardOptions,
  ToolGuardViolation,
  ToolGuardCheckResult,
  ToolCallInfo,
  ToolResultScanReport,
  ToolResultThreat,
} from './internal/tool-guard';

// Chain-of-thought guard
export { scanChainOfThought, extractReasoningText } from './internal/cot-guard';
export type {
  ChainOfThoughtGuardOptions,
  ChainOfThoughtViolation,
  ChainOfThoughtScanResult,
} from './internal/cot-guard';

// Conversation guard
export { ConversationGuard } from './internal/conversation-guard';
export type {
  ConversationGuardOptions,
  ConversationGuardViolation,
  ConversationSummary,
} from './internal/conversation-guard';

// Topic templates (pre-built topic definitions)
export {
  COMPETITOR_ENDORSEMENT,
  POLITICAL_BIAS,
  MEDICAL_ADVICE,
  LEGAL_ADVICE,
  FINANCIAL_ADVICE,
} from './internal/topic-templates';

// Industry compliance templates
export {
  HEALTHCARE_COMPLIANCE,
  FINANCE_COMPLIANCE,
  ECOMMERCE_COMPLIANCE,
  INSURANCE_COMPLIANCE,
} from './internal/compliance';
export type { ComplianceTemplate } from './internal/compliance';

export { createSecurityStream } from './internal/streaming';
export type {
  SecurityStreamOptions,
  SecurityStreamResult,
  StreamSecurityReport,
} from './internal/streaming';

// Provider adapters
export {
  wrapAnthropicClient,
  extractAnthropicMessageTexts,
  extractAnthropicResponseText,
  extractAnthropicToolCalls,
  extractAnthropicStreamChunk,
  extractContentBlockText,
} from './providers/anthropic';
export type {
  AnthropicContentBlock,
  AnthropicMessage,
  AnthropicCreateParams,
  AnthropicUsage,
  AnthropicResponse,
} from './providers/anthropic';

export {
  wrapGeminiClient,
  extractGeminiMessageTexts,
  extractGeminiResponseText,
  extractGeminiFunctionCalls,
  extractGeminiStreamChunk,
  extractGeminiContentText,
} from './providers/gemini';
export type {
  GeminiPart,
  GeminiContent,
  GeminiGenerateContentParams,
  GeminiUsageMetadata,
  GeminiCandidate,
  GeminiResponse,
} from './providers/gemini';

// Backward-compatible alias
export { LaunchPromptly as PlanForge } from './launch-promptly';
export type { LaunchPromptlyOptions as PlanForgeOptions, MLGuardrailType } from './types';
export type { SensitivityPreset } from './internal/presets';
