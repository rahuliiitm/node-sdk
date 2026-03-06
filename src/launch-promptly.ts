import { AsyncLocalStorage } from 'node:async_hooks';
import { EventBatcher } from './batcher';
import { calculateEventCost } from './internal/cost';
import { fingerprintMessages } from './internal/fingerprint';
import { detectPII, mergeDetections, type PIIDetection } from './internal/pii';
import { redactPII, deRedact, type RedactionStrategy } from './internal/redaction';
import { detectInjection, mergeInjectionAnalyses, type InjectionAnalysis } from './internal/injection';
import { CostGuard, type BudgetViolation } from './internal/cost-guard';
import { detectContentViolations, hasBlockingViolation, type ContentViolation } from './internal/content-filter';
import { createSecurityStream, StreamGuardEngine, extractChunkContent } from './internal/streaming';
import type { StreamSecurityReport } from './internal/streaming';
import { checkModelPolicy } from './internal/model-policy';
import { validateOutputSchema } from './internal/schema-validator';
import { PromptInjectionError, CostLimitError, ContentViolationError, ModelPolicyError, OutputSchemaError, StreamAbortError } from './errors';
import { wrapAnthropicClient } from './providers/anthropic';
import { wrapGeminiClient } from './providers/gemini';
import type {
  LaunchPromptlyOptions,
  WrapOptions,
  RequestContext,
  SecurityOptions,
  ChatCompletionCreateParams,
  ChatCompletion,
  GuardrailEventType,
  GuardrailEvent,
  GuardrailEventHandlers,
} from './types';
import type { IngestEventPayload } from './internal/event-types';

const DEFAULT_ENDPOINT = 'https://launchpromptly-api-950530830180.us-west1.run.app';

type CreateFn = (params: ChatCompletionCreateParams) => Promise<ChatCompletion>;

// ── Tool scanning helpers ───────────────────────────────────────────────────

/**
 * Scan tool definitions for PII in parameter descriptions and schemas.
 * @internal
 */
async function scanToolDefinitions(
  tools: any[],
  piiTypes?: import('./internal/pii').PIIType[],
  providers?: import('./internal/pii').PIIDetectorProvider[],
): Promise<PIIDetection[]> {
  const textsToScan: string[] = [];

  for (const tool of tools) {
    const fn = tool?.function;
    if (!fn) continue;

    // Scan function description
    if (typeof fn.description === 'string') {
      textsToScan.push(fn.description);
    }

    // Scan parameter definitions
    if (fn.parameters) {
      if (typeof fn.parameters === 'string') {
        textsToScan.push(fn.parameters);
      } else if (typeof fn.parameters === 'object') {
        // Walk the parameters object to find description strings
        collectDescriptions(fn.parameters, textsToScan);
      }
    }
  }

  if (textsToScan.length === 0) return [];

  const combinedText = textsToScan.join('\n');
  let detections = detectPII(combinedText, { types: piiTypes });

  if (providers?.length) {
    const providerDets = await Promise.all(providers.map(async (p) => {
      try { return await Promise.resolve(p.detect(combinedText, { types: piiTypes })); }
      catch { return [] as PIIDetection[]; }
    }));
    detections = mergeDetections(detections, ...providerDets);
  }

  return detections;
}

/**
 * Recursively collect string values from object (e.g., parameter descriptions).
 * @internal
 */
function collectDescriptions(obj: any, result: string[]): void {
  if (typeof obj !== 'object' || obj === null) return;
  for (const key of Object.keys(obj)) {
    if (key === 'description' && typeof obj[key] === 'string') {
      result.push(obj[key]);
    } else if (typeof obj[key] === 'object') {
      collectDescriptions(obj[key], result);
    }
  }
}

/**
 * Scan tool call arguments in the response for PII.
 * @internal
 */
async function scanToolCallArguments(
  toolCalls: any[],
  piiTypes?: import('./internal/pii').PIIType[],
  providers?: import('./internal/pii').PIIDetectorProvider[],
): Promise<PIIDetection[]> {
  const textsToScan: string[] = [];

  for (const tc of toolCalls) {
    if (tc?.function?.arguments && typeof tc.function.arguments === 'string') {
      textsToScan.push(tc.function.arguments);
    }
  }

  if (textsToScan.length === 0) return [];

  const combinedText = textsToScan.join('\n');
  let detections = detectPII(combinedText, { types: piiTypes });

  if (providers?.length) {
    const providerDets = await Promise.all(providers.map(async (p) => {
      try { return await Promise.resolve(p.detect(combinedText, { types: piiTypes })); }
      catch { return [] as PIIDetection[]; }
    }));
    detections = mergeDetections(detections, ...providerDets);
  }

  return detections;
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
  private readonly apiKey: string;
  private readonly endpoint: string;
  private readonly _eventHandlers: GuardrailEventHandlers;
  private _destroyed = false;

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

    // Validate endpoint URL to prevent SSRF
    try {
      const url = new URL(this.endpoint);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        throw new Error(`Endpoint must use HTTPS or HTTP protocol, got: ${url.protocol}`);
      }
    } catch (e) {
      if (e instanceof TypeError) {
        throw new Error(`Invalid endpoint URL: ${this.endpoint}`);
      }
      throw e;
    }
    this._eventHandlers = options.on ?? {};
    this.batcher = new EventBatcher(
      resolvedKey,
      this.endpoint,
      options.flushAt ?? 10,
      options.flushInterval ?? 5000,
    );
  }

  /**
   * Emit a guardrail event. Calls the registered handler (if any) for the event type.
   * Never throws — handler errors are silently caught.
   * @internal
   */
  _emit(type: GuardrailEventType, data: Record<string, unknown>): void {
    const handler = this._eventHandlers[type];
    if (!handler) return;
    try {
      handler({ type, timestamp: Date.now(), data });
    } catch {
      // Event handlers must never break the pipeline
    }
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

  wrap<T extends object>(client: T, options: WrapOptions = {}): T {
    const batcher = this.batcher;
    const emit = this._emit.bind(this);
    const customerFn = options.customer;
    const featureTag = options.feature;
    const traceIdTag = options.traceId;
    const spanNameTag = options.spanName;
    const als = this.als;
    const security = options.security;

    // Initialize cost guard if configured
    const costGuard = security?.costGuard
      ? new CostGuard(security.costGuard)
      : null;

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
                        // Capture ALS context at call time (not at wrap time)
                        const alsCtx = als.getStore();

                        // ── PRE-CALL SECURITY PIPELINE ──────────────────────

                        // Collect security metadata for the event
                        let inputPiiDetections: PIIDetection[] = [];
                        let outputPiiDetections: PIIDetection[] = [];
                        let injectionResult: InjectionAnalysis | null = null;
                        let costViolation: BudgetViolation | null = null;
                        let inputContentViolations: ContentViolation[] = [];
                        let outputContentViolations: ContentViolation[] = [];
                        const redactionMapping = new Map<string, string>();
                        let redactionApplied = false;

                        // Build a mutable copy of params for potential message redaction
                        let effectiveParams = params;

                        if (security) {
                          // 0. Model policy enforcement (first check)
                          if (security.modelPolicy) {
                            const violation = checkModelPolicy(params, security.modelPolicy);
                            if (violation) {
                              emit('model.blocked', { violation });
                              security.modelPolicy.onViolation?.(violation);
                              throw new ModelPolicyError(violation);
                            }
                          }

                          // 1. Cost guard pre-check
                          if (costGuard) {
                            let customerId = alsCtx?.customerId;
                            if (!customerId && customerFn) {
                              try { customerId = (await customerFn()).id; } catch { /* ignore */ }
                            }

                            costViolation = costGuard.checkPreCall({
                              model: params.model,
                              maxTokens: params.max_tokens as number | undefined,
                              customerId,
                            });

                            if (costViolation && costGuard.shouldBlock) {
                              emit('cost.exceeded', { violation: costViolation });
                              security.costGuard?.onBudgetExceeded?.(costViolation);
                              throw new CostLimitError(costViolation);
                            }
                          }

                          // 3. PII detection + redaction
                          if (security.pii?.enabled !== false) {
                            // Scan tool definitions for PII (parameter descriptions, etc.)
                            if (params.tools && Array.isArray(params.tools)) {
                              const toolDefDetections = await scanToolDefinitions(
                                params.tools,
                                security.pii?.types,
                                security.pii?.providers,
                              );
                              if (toolDefDetections.length > 0) {
                                inputPiiDetections.push(...toolDefDetections);
                              }
                            }

                            const allMessageText = params.messages
                              .map((m) => m.content)
                              .join('\n');

                            // Detect PII in message text
                            const messagePiiDetections = detectPII(allMessageText, {
                              types: security.pii?.types,
                            });
                            inputPiiDetections.push(...messagePiiDetections);

                            // Merge with ML provider detections if any
                            if (security.pii?.providers?.length) {
                              const providerDets = await Promise.all(security.pii.providers.map(async (p) => {
                                try { return await Promise.resolve(p.detect(allMessageText, { types: security.pii?.types })); }
                                catch { return [] as PIIDetection[]; }
                              }));
                              inputPiiDetections = mergeDetections(inputPiiDetections, ...providerDets);
                            }

                            // Fire callback + guardrail event
                            if (inputPiiDetections.length > 0) {
                              emit('pii.detected', { detections: inputPiiDetections, direction: 'input' });
                              security.pii?.onDetect?.(inputPiiDetections);
                            }

                            // Redact messages if configured
                            const redactionStrategy: RedactionStrategy = security.pii?.redaction ?? 'placeholder';
                            if (inputPiiDetections.length > 0 && redactionStrategy !== 'none') {
                              redactionApplied = true;
                              // Shared counters across all messages prevent placeholder collisions
                              // (e.g., two messages both having [EMAIL_1] for different emails)
                              const sharedCounters: Record<string, number> = {};
                              const redactedMessages: typeof params.messages = [];
                              for (const msg of params.messages) {
                                const result = await redactPII(msg.content, {
                                  strategy: redactionStrategy,
                                  types: security.pii?.types,
                                  providers: security.pii?.providers,
                                }, sharedCounters);
                                // Accumulate all mappings for de-redaction
                                for (const [k, v] of result.mapping) {
                                  redactionMapping.set(k, v);
                                }
                                redactedMessages.push({ ...msg, content: result.redactedText });
                              }
                              effectiveParams = { ...params, messages: redactedMessages };
                              emit('pii.redacted', { strategy: redactionStrategy, count: inputPiiDetections.length });
                            }
                          }

                          // 4. Injection detection
                          if (security.injection?.enabled !== false) {
                            // Scan user messages AND tool/function results (untrusted external input)
                            const userMessages = params.messages
                              .filter((m) => m.role === 'user' || m.role === 'tool' || m.role === 'function')
                              .map((m) => m.content)
                              .join('\n');

                            if (userMessages) {
                              injectionResult = detectInjection(userMessages, {
                                blockThreshold: security.injection?.blockThreshold,
                              });

                              // Merge with ML providers
                              if (security.injection?.providers?.length) {
                                const providerResults = await Promise.all(security.injection.providers.map(async (p) => {
                                  try { return await Promise.resolve(p.detect(userMessages)); }
                                  catch { return { riskScore: 0, triggered: [] as string[], action: 'allow' as const }; }
                                }));
                                injectionResult = mergeInjectionAnalyses(
                                  [injectionResult, ...providerResults],
                                  { blockThreshold: security.injection?.blockThreshold },
                                );
                              }

                              // Fire callback + guardrail event
                              if (injectionResult.riskScore > 0) {
                                emit('injection.detected', { analysis: injectionResult });
                              }
                              security.injection?.onDetect?.(injectionResult);

                              // Block if configured
                              if (
                                security.injection?.blockOnHighRisk &&
                                injectionResult.action === 'block'
                              ) {
                                emit('injection.blocked', { analysis: injectionResult });
                                throw new PromptInjectionError(injectionResult);
                              }
                            }
                          }

                          // 5. Content filter
                          if (security.contentFilter?.enabled !== false && security.contentFilter) {
                            const allInput = params.messages.map((m) => m.content).join('\n');
                            inputContentViolations = detectContentViolations(
                              allInput,
                              'input',
                              security.contentFilter,
                            );

                            if (inputContentViolations.length > 0) {
                              emit('content.violated', { violations: inputContentViolations, direction: 'input' });
                            }

                            if (hasBlockingViolation(inputContentViolations, security.contentFilter)) {
                              security.contentFilter.onViolation?.(inputContentViolations[0]);
                              throw new ContentViolationError(inputContentViolations);
                            }

                            // Fire callback for warnings
                            if (inputContentViolations.length > 0) {
                              for (const v of inputContentViolations) {
                                security.contentFilter.onViolation?.(v);
                              }
                            }
                          }
                        }

                        // ── STREAMING PATH ────────────────────────────────────
                        if (params.stream === true) {
                          const startMs = Date.now();
                          const streamResult = await (compValue as Function).call(
                            chatValue,
                            effectiveParams,
                          );
                          const latencyMs = Date.now() - startMs;

                          // Choose between StreamGuardEngine (real-time) and legacy createSecurityStream (post-hoc)
                          let outputStream: AsyncIterable<any>;
                          let getStreamReport: () => StreamSecurityReport;

                          if (security?.streamGuard) {
                            const engine = new StreamGuardEngine({
                              streamGuard: security.streamGuard,
                              pii: security.pii ? {
                                types: security.pii.types,
                                providers: security.pii.providers,
                              } : undefined,
                              injection: security.injection ? {
                                blockThreshold: security.injection.blockThreshold,
                              } : undefined,
                              extractText: extractChunkContent,
                            });
                            const guarded = engine.wrap(streamResult as AsyncIterable<any>);
                            outputStream = guarded;
                            getStreamReport = () => guarded.getReport();
                          } else {
                            const { stream: securedStream, getReport } = createSecurityStream(
                              streamResult as AsyncIterable<any>,
                              {
                                pii: security ? {
                                  enabled: security.pii?.enabled !== false,
                                  types: security.pii?.types,
                                  providers: security.pii?.providers,
                                } : undefined,
                                injection: security ? {
                                  enabled: security.injection?.enabled !== false,
                                  blockThreshold: security.injection?.blockThreshold,
                                } : undefined,
                              },
                            );
                            outputStream = securedStream;
                            getStreamReport = getReport;
                          }

                          // Create a wrapper that captures the event after consumption
                          const wrappedStream = (async function* () {
                            yield* outputStream;

                            // Stream complete — capture event with security data
                            void (async () => {
                              try {
                                const report = getStreamReport();

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

                                let customerId: string | undefined = alsCtx?.customerId;
                                let feature: string | undefined = alsCtx?.feature ?? featureTag;

                                if (!customerId && customerFn) {
                                  const ctx = await customerFn();
                                  customerId = ctx.id;
                                  feature = ctx.feature ?? feature;
                                }

                                const traceId = alsCtx?.traceId ?? traceIdTag;
                                const spanName = alsCtx?.spanName ?? spanNameTag;

                                const event: IngestEventPayload = {
                                  provider: 'openai',
                                  model: params.model,
                                  inputTokens: 0,
                                  outputTokens: 0,
                                  totalTokens: 0,
                                  costUsd: 0,
                                  latencyMs,
                                  customerId,
                                  feature,
                                  systemHash: fingerprint.systemHash ?? undefined,
                                  fullHash: fingerprint.fullHash,
                                  promptPreview: security ? undefined : fingerprint.promptPreview,
                                  statusCode: 200,
                                  traceId,
                                  spanName,
                                  metadata: alsCtx?.metadata,
                                };

                                // Enrich with streaming security data
                                if (security) {
                                  const streamPiiDetections = report.piiDetections;
                                  const allPii = [...inputPiiDetections, ...streamPiiDetections];
                                  const hasMlPiiProviders = (security.pii?.providers?.length ?? 0) > 0;
                                  const hasMlInjProviders = (security.injection?.providers?.length ?? 0) > 0;

                                  if (allPii.length > 0) {
                                    event.piiDetections = {
                                      inputCount: inputPiiDetections.length,
                                      outputCount: streamPiiDetections.length,
                                      types: [...new Set(allPii.map((d) => d.type))],
                                      redactionApplied,
                                      detectorUsed: hasMlPiiProviders ? 'both' : 'regex',
                                    };
                                  }

                                  const injResult = report.injectionRisk ?? injectionResult;
                                  if (injResult) {
                                    event.injectionRisk = {
                                      score: injResult.riskScore,
                                      triggered: injResult.triggered,
                                      action: injResult.action,
                                      detectorUsed: hasMlInjProviders ? 'both' : 'rules',
                                    };
                                  }

                                  // Add stream guard metadata
                                  if (security.streamGuard && report.streamViolations.length > 0) {
                                    event.streamGuard = {
                                      aborted: report.aborted,
                                      violationCount: report.streamViolations.length,
                                      violationTypes: [...new Set(report.streamViolations.map((v) => v.type))],
                                      approximateOutputTokens: report.approximateTokens,
                                      responseLength: report.responseLength,
                                    };
                                  }
                                }

                                batcher.enqueue(event);
                              } catch {
                                // SDK must never throw
                              }
                            })();
                          })();

                          return wrappedStream as any;
                        }

                        // ── NON-STREAMING PATH ────────────────────────────────
                        // ── CALL ORIGINAL API ───────────────────────────────
                        const startMs = Date.now();
                        const result = await (compValue as CreateFn).call(
                          chatValue,
                          effectiveParams,
                        );
                        const latencyMs = Date.now() - startMs;

                        // ── POST-CALL SECURITY PIPELINE ─────────────────────

                        // Extract response text for post-call scanning
                        let responseForCaller = result;

                        if (security) {
                          const responseText = (result as any).choices?.[0]?.message?.content as string | undefined;

                          // Post-call: scan response for PII
                          if (security.pii?.scanResponse && responseText) {
                            outputPiiDetections = detectPII(responseText, {
                              types: security.pii?.types,
                            });
                          }

                          // Post-call: scan tool call arguments for PII
                          const responseToolCalls = (result as any).choices?.[0]?.message?.tool_calls;
                          if (security.pii?.enabled !== false && responseToolCalls && Array.isArray(responseToolCalls)) {
                            const toolCallDetections = await scanToolCallArguments(
                              responseToolCalls,
                              security.pii?.types,
                              security.pii?.providers,
                            );
                            if (toolCallDetections.length > 0) {
                              outputPiiDetections.push(...toolCallDetections);
                            }
                          }

                          if (outputPiiDetections.length > 0) {
                            emit('pii.detected', { detections: outputPiiDetections, direction: 'output' });
                          }

                          // Post-call: scan response for content violations
                          if (security.contentFilter?.enabled !== false && security.contentFilter && responseText) {
                            outputContentViolations = detectContentViolations(
                              responseText,
                              'output',
                              security.contentFilter,
                            );
                            if (outputContentViolations.length > 0) {
                              emit('content.violated', { violations: outputContentViolations, direction: 'output' });
                            }
                          }

                          // Post-call: output schema validation
                          if (security.outputSchema && responseText) {
                            const validation = validateOutputSchema(responseText, security.outputSchema);
                            if (!validation.valid) {
                              emit('schema.invalid', { errors: validation.errors, responseText });
                              if (security.outputSchema.blockOnInvalid) {
                                throw new OutputSchemaError(validation.errors, responseText);
                              }
                            }
                          }

                          // Post-call: de-redact response if we have a mapping
                          if (redactionMapping.size > 0 && responseText) {
                            const deRedactedText = deRedact(responseText, redactionMapping);
                            if (deRedactedText !== responseText) {
                              // Create a shallow clone with de-redacted response
                              const choices = [...((result as any).choices ?? [])];
                              if (choices[0]?.message) {
                                choices[0] = {
                                  ...choices[0],
                                  message: { ...choices[0].message, content: deRedactedText },
                                };
                              }
                              responseForCaller = { ...result, choices } as typeof result;
                            }
                          }

                          // Post-call: update cost guard
                          if (costGuard && result.usage) {
                            const actualCost = calculateEventCost(
                              'openai',
                              params.model,
                              result.usage.prompt_tokens,
                              result.usage.completion_tokens,
                            );
                            let customerId = alsCtx?.customerId;
                            if (!customerId && customerFn) {
                              try { customerId = (await customerFn()).id; } catch { /* ignore */ }
                            }
                            costGuard.recordCost(actualCost, customerId);
                          }
                        }

                        // ── CAPTURE EVENT ───────────────────────────────────
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
                              promptPreview: security ? undefined : fingerprint.promptPreview,
                              statusCode: 200,
                              traceId,
                              spanName,
                              metadata: alsCtx?.metadata,
                            };

                            // Enrich with security metadata
                            if (security) {
                              const hasMlPiiProviders = (security.pii?.providers?.length ?? 0) > 0;
                              const hasMlInjProviders = (security.injection?.providers?.length ?? 0) > 0;

                              if (inputPiiDetections.length > 0 || outputPiiDetections.length > 0) {
                                event.piiDetections = {
                                  inputCount: inputPiiDetections.length,
                                  outputCount: outputPiiDetections.length,
                                  types: [...new Set([
                                    ...inputPiiDetections.map((d) => d.type),
                                    ...outputPiiDetections.map((d) => d.type),
                                  ])],
                                  redactionApplied,
                                  detectorUsed: hasMlPiiProviders ? 'both' : 'regex',
                                };
                              }

                              if (injectionResult) {
                                event.injectionRisk = {
                                  score: injectionResult.riskScore,
                                  triggered: injectionResult.triggered,
                                  action: injectionResult.action,
                                  detectorUsed: hasMlInjProviders ? 'both' : 'rules',
                                };
                              }

                              if (inputContentViolations.length > 0 || outputContentViolations.length > 0) {
                                event.contentViolations = {
                                  inputViolations: inputContentViolations.map((v) => ({
                                    category: v.category,
                                    matched: v.matched,
                                    severity: v.severity,
                                  })),
                                  outputViolations: outputContentViolations.map((v) => ({
                                    category: v.category,
                                    matched: v.matched,
                                    severity: v.severity,
                                  })),
                                };
                              }

                              if (costGuard) {
                                event.costGuard = {
                                  estimatedCost: costUsd,
                                  budgetRemaining: Math.max(
                                    0,
                                    (security.costGuard?.maxCostPerHour ?? Infinity) -
                                      costGuard.getCurrentHourSpend(),
                                  ),
                                  limitTriggered: costViolation?.type,
                                };
                              }
                            }

                            batcher.enqueue(event);
                          } catch {
                            // SDK must never throw
                          }
                        })();

                        return responseForCaller;
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

  /**
   * Wrap an Anthropic client with security pipeline interception.
   *
   * Intercepts `client.messages.create()` to run PII redaction, injection
   * detection, cost controls, content filtering, and compliance checks.
   *
   * @example
   * ```ts
   * import Anthropic from '@anthropic-ai/sdk';
   * const client = new Anthropic({ apiKey: '...' });
   * const wrapped = lp.wrapAnthropic(client, {
   *   security: { pii: { redaction: 'placeholder' } },
   * });
   * const result = await wrapped.messages.create({
   *   model: 'claude-sonnet-4-20250514',
   *   max_tokens: 1024,
   *   messages: [{ role: 'user', content: 'Hello' }],
   * });
   * ```
   */
  wrapAnthropic<T extends object>(client: T, options: WrapOptions = {}): T {
    return wrapAnthropicClient(client, {
      batcher: this.batcher,
      als: this.als,
      emit: this._emit.bind(this),
    }, options);
  }

  /**
   * Wrap a Google Gemini client with security pipeline interception.
   *
   * Intercepts `client.models.generateContent()` and
   * `client.models.generateContentStream()` to run PII redaction, injection
   * detection, cost controls, content filtering, and compliance checks.
   *
   * @example
   * ```ts
   * import { GoogleGenAI } from '@google/genai';
   * const client = new GoogleGenAI({ apiKey: '...' });
   * const wrapped = lp.wrapGemini(client, {
   *   security: { pii: { redaction: 'placeholder' } },
   * });
   * const result = await wrapped.models.generateContent({
   *   model: 'gemini-2.0-flash',
   *   contents: [{ role: 'user', parts: [{ text: 'Hello' }] }],
   * });
   * ```
   */
  wrapGemini<T extends object>(client: T, options: WrapOptions = {}): T {
    return wrapGeminiClient(client, {
      batcher: this.batcher,
      als: this.als,
      emit: this._emit.bind(this),
    }, options);
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
