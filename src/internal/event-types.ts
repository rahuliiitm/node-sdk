/**
 * Payload shape for a single LLM event sent to the LaunchPromptly API.
 * @internal
 */
export interface IngestEventPayload {
  provider: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  costUsd: number;
  latencyMs: number;
  customerId?: string;
  feature?: string;
  systemHash?: string;
  fullHash?: string;
  promptPreview?: string;
  statusCode?: number;
  traceId?: string;
  spanName?: string;
  environmentId?: string;
  metadata?: Record<string, string>;

  // Security metadata
  piiDetections?: {
    inputCount: number;
    outputCount: number;
    types: string[];
    redactionApplied: boolean;
    detectorUsed: 'regex' | 'ml' | 'both';
  };
  injectionRisk?: {
    score: number;
    triggered: string[];
    action: 'allow' | 'warn' | 'block';
    detectorUsed: 'rules' | 'ml' | 'both';
  };
  costGuard?: {
    estimatedCost: number;
    budgetRemaining: number;
    limitTriggered?: string;
  };
  contentViolations?: {
    inputViolations: Array<{ category: string; matched: string; severity: string }>;
    outputViolations: Array<{ category: string; matched: string; severity: string }>;
  };
  streamGuard?: {
    aborted: boolean;
    violationCount: number;
    violationTypes: string[];
    approximateOutputTokens: number;
    responseLength: number;
  };
  jailbreakRisk?: {
    score: number;
    triggered: string[];
    action: 'allow' | 'warn' | 'block';
    decodedPayloads?: string[];
  };
  unicodeThreats?: {
    found: boolean;
    threatCount: number;
    threatTypes: string[];
    action: 'strip' | 'warn' | 'block';
  };
  secretDetections?: {
    inputCount: number;
    outputCount: number;
    types: string[];
  };
  topicViolation?: {
    type: 'off_topic' | 'blocked_topic';
    topic?: string;
    matchedKeywords: string[];
    score: number;
  };
  outputSafety?: {
    threatCount: number;
    categories: string[];
    threats: Array<{ category: string; matched: string; severity: string }>;
  };
  promptLeakage?: {
    leaked: boolean;
    similarity: number;
    metaResponseDetected: boolean;
  };
}

/**
 * Batch payload for the /v1/events/batch endpoint.
 * @internal
 */
export interface IngestBatchPayload {
  events: IngestEventPayload[];
}
