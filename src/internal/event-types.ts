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
  managedPromptId?: string;
  promptVersionId?: string;
  traceId?: string;
  spanName?: string;
  environmentId?: string;
  metadata?: Record<string, string>;
}

/**
 * Batch payload for the /v1/events/batch endpoint.
 * @internal
 */
export interface IngestBatchPayload {
  events: IngestEventPayload[];
}
