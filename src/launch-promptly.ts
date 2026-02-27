import { AsyncLocalStorage } from 'node:async_hooks';
import { EventBatcher } from './batcher';
import { PromptCache } from './prompt-cache';
import { interpolate } from './template';
import { calculateEventCost } from './internal/cost';
import { fingerprintMessages } from './internal/fingerprint';
import type {
  LaunchPromptlyOptions,
  PromptOptions,
  WrapOptions,
  RequestContext,
  ChatCompletionCreateParams,
  ChatCompletion,
} from './types';
import type { IngestEventPayload } from './internal/event-types';

const DEFAULT_ENDPOINT = 'https://api.launchpromptly.dev';
const DEFAULT_PROMPT_CACHE_TTL = 60000; // 60 seconds

type CreateFn = (params: ChatCompletionCreateParams) => Promise<ChatCompletion>;

export class PromptNotFoundError extends Error {
  constructor(slug: string) {
    super(`Prompt "${slug}" not found`);
    this.name = 'PromptNotFoundError';
  }
}

export class LaunchPromptly {
  // ── Singleton ───────────────────────────────────────────────────────────────
  private static _instance: LaunchPromptly | null = null;

  /**
   * Initialize the global singleton instance.
   * Subsequent calls return the existing instance (logs a warning).
   */
  static init(options: LaunchPromptlyOptions): LaunchPromptly {
    if (LaunchPromptly._instance) {
      return LaunchPromptly._instance;
    }
    LaunchPromptly._instance = new LaunchPromptly(options);
    return LaunchPromptly._instance;
  }

  /** Access the global singleton. Throws if init() hasn't been called. */
  static get shared(): LaunchPromptly {
    if (!LaunchPromptly._instance) {
      throw new Error(
        'LaunchPromptly has not been initialized. Call LaunchPromptly.init({ apiKey }) first.',
      );
    }
    return LaunchPromptly._instance;
  }

  /** Reset the singleton (primarily for testing). */
  static reset(): void {
    if (LaunchPromptly._instance) {
      LaunchPromptly._instance.destroy();
      LaunchPromptly._instance = null;
    }
  }

  // ── AsyncLocalStorage for context propagation ───────────────────────────────
  private readonly als = new AsyncLocalStorage<RequestContext>();

  // ── Instance fields ─────────────────────────────────────────────────────────
  private readonly batcher: EventBatcher;
  private readonly promptCache: PromptCache;
  private readonly apiKey: string;
  private readonly endpoint: string;
  private readonly promptCacheTtl: number;
  private _destroyed = false;

  /** Maps interpolated content → { managedPromptId, promptVersionId } for event metadata injection */
  private readonly resolvedPrompts = new Map<
    string,
    { managedPromptId: string; promptVersionId: string }
  >();

  constructor(options: LaunchPromptlyOptions = {}) {
    const resolvedKey = options.apiKey
      || (typeof process !== 'undefined' && process.env?.LAUNCHPROMPTLY_API_KEY)
      || (typeof process !== 'undefined' && process.env?.LP_API_KEY)
      || '';

    if (!resolvedKey) {
      throw new Error(
        'LaunchPromptly API key not found. Either:\n' +
        '  1. Pass it directly: new LaunchPromptly({ apiKey: "lp_live_..." })\n' +
        '  2. Set LAUNCHPROMPTLY_API_KEY environment variable\n' +
        '  3. Set LP_API_KEY environment variable\n' +
        'Get your key from Settings → Environments in the LaunchPromptly dashboard.',
      );
    }

    this.apiKey = resolvedKey;
    this.endpoint = options.endpoint ?? DEFAULT_ENDPOINT;
    this.promptCacheTtl = options.promptCacheTtl ?? DEFAULT_PROMPT_CACHE_TTL;
    this.promptCache = new PromptCache(options.maxCacheSize);
    this.batcher = new EventBatcher(
      resolvedKey,
      this.endpoint,
      options.flushAt ?? 10,
      options.flushInterval ?? 5000,
    );
  }

  /**
   * Run a callback with request-scoped context that automatically propagates
   * traceId, customerId, feature, and spanName to all SDK calls within.
   *
   * Context flows across async/await boundaries via AsyncLocalStorage.
   *
   * @example
   * ```ts
   * await lp.withContext({ traceId: req.id, customerId: user.id }, async () => {
   *   const prompt = await lp.prompt('greeting');
   *   await wrapped.chat.completions.create({ ... });
   * });
   * ```
   */
  withContext<T>(context: RequestContext, fn: () => T): T {
    return this.als.run(context, fn);
  }

  /** Get the current AsyncLocalStorage context (or undefined if none). */
  getContext(): RequestContext | undefined {
    return this.als.getStore();
  }

  async prompt(slug: string, options?: PromptOptions): Promise<string> {
    const alsCtx = this.als.getStore();
    const effectiveCustomerId = options?.customerId ?? alsCtx?.customerId;

    // Check cache first
    const cached = this.promptCache.get(slug);
    if (cached) {
      const content = options?.variables
        ? interpolate(cached.content, options.variables)
        : cached.content;

      // Store interpolated content for event metadata
      this.resolvedPrompts.set(content, {
        managedPromptId: cached.managedPromptId,
        promptVersionId: cached.promptVersionId,
      });

      return content;
    }

    // Fetch from API
    const queryParams = effectiveCustomerId
      ? `?customerId=${encodeURIComponent(effectiveCustomerId)}`
      : '';
    const url = `${this.endpoint}/v1/prompts/resolve/${encodeURIComponent(slug)}${queryParams}`;

    try {
      const response = await fetch(url, {
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
        },
      });

      if (response.status === 404) {
        // 404 is authoritative — no stale fallback
        throw new PromptNotFoundError(slug);
      }

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = (await response.json()) as {
        content: string;
        managedPromptId: string;
        promptVersionId: string;
        version: number;
      };

      // Cache the raw template (before interpolation)
      this.promptCache.set(slug, data, this.promptCacheTtl);

      // Interpolate variables if provided
      const content = options?.variables
        ? interpolate(data.content, options.variables)
        : data.content;

      // Store interpolated content for event metadata injection
      this.resolvedPrompts.set(content, {
        managedPromptId: data.managedPromptId,
        promptVersionId: data.promptVersionId,
      });

      return content;
    } catch (error) {
      // On PromptNotFoundError, always throw
      if (error instanceof PromptNotFoundError) {
        throw error;
      }

      // On network error, try stale cache
      const stale = this.promptCache.getStale(slug);
      if (stale) {
        const content = options?.variables
          ? interpolate(stale.content, options.variables)
          : stale.content;
        return content;
      }

      throw error;
    }
  }

  wrap<T extends object>(client: T, options: WrapOptions = {}): T {
    const batcher = this.batcher;
    const customerFn = options.customer;
    const featureTag = options.feature;
    const traceIdTag = options.traceId;
    const spanNameTag = options.spanName;
    const resolvedPrompts = this.resolvedPrompts;
    const als = this.als;

    return new Proxy(client, {
      get(target, prop) {
        const value = Reflect.get(target, prop);

        if (prop === 'chat') {
          return new Proxy(value as object, {
            get(_chatTarget, chatProp) {
              const chatValue = Reflect.get(value as object, chatProp);
              if (chatProp === 'completions') {
                return new Proxy(chatValue as object, {
                  get(_compTarget, compProp) {
                    const compValue = Reflect.get(chatValue as object, compProp);
                    if (compProp === 'create') {
                      return async (
                        params: ChatCompletionCreateParams,
                      ): Promise<ChatCompletion> => {
                        const startMs = Date.now();
                        const result = await (compValue as CreateFn).call(
                          chatValue,
                          params,
                        );
                        const latencyMs = Date.now() - startMs;

                        // Capture ALS context at call time (not at wrap time)
                        const alsCtx = als.getStore();

                        void (async () => {
                          try {
                            const usage = result.usage;
                            if (!usage) return;

                            const inputTokens = usage.prompt_tokens;
                            const outputTokens = usage.completion_tokens;
                            const totalTokens = usage.total_tokens;
                            const costUsd = calculateEventCost(
                              'openai',
                              params.model,
                              inputTokens,
                              outputTokens,
                            );

                            const systemMsg = params.messages.find(
                              (m) => m.role === 'system',
                            );
                            const nonSystem = params.messages.filter(
                              (m) => m.role !== 'system',
                            );
                            const fingerprint = fingerprintMessages(
                              nonSystem,
                              systemMsg?.content,
                            );

                            // Resolve customer: ALS context > WrapOptions.customer() > undefined
                            let customerId: string | undefined = alsCtx?.customerId;
                            let feature: string | undefined = alsCtx?.feature ?? featureTag;

                            if (!customerId && customerFn) {
                              const ctx = await customerFn();
                              customerId = ctx.id;
                              feature = ctx.feature ?? feature;
                            }

                            // Resolve trace: ALS context > WrapOptions > undefined
                            const traceId = alsCtx?.traceId ?? traceIdTag;
                            const spanName = alsCtx?.spanName ?? spanNameTag;

                            // Check if system message matches a resolved managed prompt
                            const promptMeta = systemMsg?.content
                              ? resolvedPrompts.get(systemMsg.content)
                              : undefined;

                            const event: IngestEventPayload = {
                              provider: 'openai',
                              model: params.model,
                              inputTokens,
                              outputTokens,
                              totalTokens,
                              costUsd,
                              latencyMs,
                              customerId,
                              feature,
                              systemHash: fingerprint.systemHash ?? undefined,
                              fullHash: fingerprint.fullHash,
                              promptPreview: fingerprint.promptPreview,
                              statusCode: 200,
                              managedPromptId: promptMeta?.managedPromptId,
                              promptVersionId: promptMeta?.promptVersionId,
                              traceId,
                              spanName,
                              metadata: alsCtx?.metadata,
                            };

                            batcher.enqueue(event);
                          } catch {
                            // SDK must never throw
                          }
                        })();

                        return result;
                      };
                    }
                    return typeof compValue === 'function'
                      ? (compValue as Function).bind(chatValue)
                      : compValue;
                  },
                });
              }
              return typeof chatValue === 'function'
                ? (chatValue as Function).bind(value)
                : chatValue;
            },
          });
        }

        return typeof value === 'function'
          ? (value as Function).bind(target)
          : value;
      },
    }) as T;
  }

  /** Flush all pending events to the API. */
  async flush(): Promise<void> {
    await this.batcher.flush();
  }

  /** Stop timers and release resources. Safe to call multiple times. */
  destroy(): void {
    if (this._destroyed) return;
    this._destroyed = true;
    this.batcher.destroy();
  }

  /**
   * Graceful shutdown: flush pending events, then destroy.
   * Use this in server shutdown hooks (SIGTERM, process.on('beforeExit')).
   */
  async shutdown(): Promise<void> {
    await this.flush();
    this.destroy();
  }

  /** Whether this instance has been destroyed. */
  get isDestroyed(): boolean {
    return this._destroyed;
  }
}
