export interface CustomerContext {
  id: string;
  feature?: string;
}

export interface LaunchPromptlyOptions {
  apiKey?: string;
  endpoint?: string;
  flushAt?: number;
  flushInterval?: number;
  /** Guardrail event handlers. Called when security checks trigger. */
  on?: GuardrailEventHandlers;
}

export interface WrapOptions {
  customer?: () => CustomerContext | Promise<CustomerContext>;
  feature?: string;
  traceId?: string;
  spanName?: string;
  security?: SecurityOptions;
}

/** Security configuration for the wrap() pipeline. */
export interface SecurityOptions {
  pii?: PIISecurityOptions;
  injection?: InjectionSecurityOptions;
  jailbreak?: JailbreakSecurityOptions;
  costGuard?: import('./internal/cost-guard').CostGuardOptions;
  contentFilter?: import('./internal/content-filter').ContentFilterOptions;
  modelPolicy?: import('./internal/model-policy').ModelPolicyOptions;
  streamGuard?: StreamGuardOptions;
  outputSchema?: import('./internal/schema-validator').OutputSchemaOptions;
  unicodeSanitizer?: UnicodeSanitizerSecurityOptions;
  secretDetection?: SecretDetectionSecurityOptions;
  topicGuard?: TopicGuardSecurityOptions;
  outputSafety?: OutputSafetySecurityOptions;
  promptLeakage?: PromptLeakageSecurityOptions;
  audit?: {
    logLevel?: 'none' | 'summary' | 'detailed';
  };
}

export interface JailbreakSecurityOptions {
  enabled?: boolean;
  blockThreshold?: number;
  warnThreshold?: number;
  blockOnDetection?: boolean;
  providers?: import('./internal/jailbreak').JailbreakDetectorProvider[];
  onDetect?: (analysis: import('./internal/jailbreak').JailbreakAnalysis) => void;
}

export interface UnicodeSanitizerSecurityOptions {
  enabled?: boolean;
  action?: 'strip' | 'warn' | 'block';
  detectHomoglyphs?: boolean;
  onDetect?: (result: import('./internal/unicode-sanitizer').UnicodeScanResult) => void;
}

export interface SecretDetectionSecurityOptions {
  enabled?: boolean;
  builtInPatterns?: boolean;
  customPatterns?: import('./internal/secret-detection').CustomSecretPattern[];
  scanResponse?: boolean;
  action?: 'warn' | 'block' | 'redact';
  onDetect?: (secrets: import('./internal/secret-detection').SecretDetection[]) => void;
}

export interface TopicGuardSecurityOptions {
  enabled?: boolean;
  allowedTopics?: import('./internal/topic-guard').TopicDefinition[];
  blockedTopics?: import('./internal/topic-guard').TopicDefinition[];
  action?: 'warn' | 'block';
  onViolation?: (violation: import('./internal/topic-guard').TopicViolation) => void;
}

export interface OutputSafetySecurityOptions {
  enabled?: boolean;
  categories?: import('./internal/output-safety').OutputSafetyCategory[];
  action?: 'warn' | 'block';
  onDetect?: (threats: import('./internal/output-safety').OutputSafetyThreat[]) => void;
}

export interface PromptLeakageSecurityOptions {
  enabled?: boolean;
  systemPrompt: string;
  threshold?: number;
  blockOnLeak?: boolean;
  onDetect?: (result: import('./internal/prompt-leakage').PromptLeakageResult) => void;
}

/** Configuration for real-time streaming guard. */
export interface StreamGuardOptions {
  /** Enable mid-stream PII scanning. Default: true when security.pii is configured. */
  piiScan?: boolean;
  /** Enable mid-stream injection scanning. Default: true when security.injection is configured. */
  injectionScan?: boolean;
  /** Response length limits. */
  maxResponseLength?: MaxResponseLength;
  /** Characters between periodic scans. Default: 500. */
  scanInterval?: number;
  /** Overlap characters when the rolling window advances. Default: 200. */
  windowOverlap?: number;
  /** Action on violation: 'abort' stops stream, 'warn' fires callback, 'flag' adds to report. Default: 'flag'. */
  onViolation?: 'abort' | 'warn' | 'flag';
  /** Called when a mid-stream violation is detected. */
  onStreamViolation?: (violation: StreamViolation) => void;
  /** Run full-text scan after stream completes. Default: true. */
  finalScan?: boolean;
  /** Enable approximate token counting (chars/4). Default: true. */
  trackTokens?: boolean;
}

/** Response length limits for streaming guard. */
export interface MaxResponseLength {
  /** Maximum characters allowed. */
  maxChars?: number;
  /** Maximum words allowed. */
  maxWords?: number;
}

/** A violation detected during streaming. */
export interface StreamViolation {
  type: 'pii' | 'injection' | 'length';
  /** Character offset in the accumulated response. */
  offset: number;
  /** Details vary by type. */
  details: unknown;
  /** Timestamp of detection (ms). */
  timestamp: number;
}

export interface PIISecurityOptions {
  enabled?: boolean;
  redaction?: import('./internal/redaction').RedactionStrategy;
  types?: import('./internal/pii').PIIType[];
  scanResponse?: boolean;
  providers?: import('./internal/pii').PIIDetectorProvider[];
  onDetect?: (detections: import('./internal/pii').PIIDetection[]) => void;
}

export interface InjectionSecurityOptions {
  enabled?: boolean;
  blockThreshold?: number;
  blockOnHighRisk?: boolean;
  providers?: import('./internal/injection').InjectionDetectorProvider[];
  onDetect?: (analysis: import('./internal/injection').InjectionAnalysis) => void;
}

/** Context propagated via AsyncLocalStorage through withContext() */
export interface RequestContext {
  traceId?: string;
  spanName?: string;
  customerId?: string;
  feature?: string;
  metadata?: Record<string, string>;
}

// ── Guardrail Events ─────────────────────────────────────────────────────────

/** All guardrail event types emitted by the SDK. */
export type GuardrailEventType =
  | 'pii.detected'
  | 'pii.redacted'
  | 'injection.detected'
  | 'injection.blocked'
  | 'jailbreak.detected'
  | 'jailbreak.blocked'
  | 'cost.exceeded'
  | 'content.violated'
  | 'schema.invalid'
  | 'model.blocked'
  | 'unicode.suspicious'
  | 'secret.detected'
  | 'topic.violated'
  | 'output.unsafe'
  | 'prompt.leaked';

/** Payload emitted when a guardrail event fires. */
export interface GuardrailEvent {
  type: GuardrailEventType;
  timestamp: number;
  data: Record<string, unknown>;
}

/** Map of event type → handler callback. */
export type GuardrailEventHandlers = Partial<Record<GuardrailEventType, (event: GuardrailEvent) => void>>;

export interface ChatMessage {
  role: string;
  content: string;
}

export interface ChatCompletionCreateParams {
  model: string;
  messages: ChatMessage[];
  [key: string]: unknown;
}

export interface ChatCompletionUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface ChatCompletion {
  usage?: ChatCompletionUsage;
  [key: string]: unknown;
}
