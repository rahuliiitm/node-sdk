export interface CustomerContext {
  id: string;
  feature?: string;
}

export interface LaunchPromptlyOptions {
  apiKey?: string;
  endpoint?: string;
  flushAt?: number;
  flushInterval?: number;
  promptCacheTtl?: number;
  /** Maximum number of prompt entries to cache in memory (LRU eviction). Default: 1000 */
  maxCacheSize?: number;
}

export interface PromptOptions {
  customerId?: string;
  variables?: Record<string, string>;
}

export interface WrapOptions {
  customer?: () => CustomerContext | Promise<CustomerContext>;
  feature?: string;
  traceId?: string;
  spanName?: string;
}

/** Context propagated via AsyncLocalStorage through withContext() */
export interface RequestContext {
  traceId?: string;
  spanName?: string;
  customerId?: string;
  feature?: string;
  metadata?: Record<string, string>;
}

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
