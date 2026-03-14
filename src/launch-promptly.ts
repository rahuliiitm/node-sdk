import { AsyncLocalStorage } from 'node:async_hooks';
import { EventBatcher } from './batcher';
import { calculateEventCost } from './internal/cost';
import { fingerprintMessages } from './internal/fingerprint';
import { detectPII, mergeDetections, applySuppressiveContext, filterAllowList, filterByConfidence, type PIIDetection } from './internal/pii';
import { redactPII, deRedact, type RedactionStrategy } from './internal/redaction';
import { detectInjection, mergeInjectionAnalyses, type InjectionAnalysis } from './internal/injection';
import { CostGuard, type BudgetViolation } from './internal/cost-guard';
import { detectContentViolations, hasBlockingViolation, type ContentViolation } from './internal/content-filter';
import { createSecurityStream, StreamGuardEngine, extractChunkContent } from './internal/streaming';
import type { StreamSecurityReport } from './internal/streaming';
import { checkModelPolicy } from './internal/model-policy';
import { validateOutputSchema } from './internal/schema-validator';
import { scanUnicode, type UnicodeScanResult } from './internal/unicode-sanitizer';
import { detectSecrets, mergeSecretDetections, type SecretDetection } from './internal/secret-detection';
import { detectJailbreak, mergeJailbreakAnalyses, type JailbreakAnalysis } from './internal/jailbreak';
import { checkTopicGuard, type TopicViolation } from './internal/topic-guard';
import { scanOutputSafety, type OutputSafetyThreat } from './internal/output-safety';
import { detectPromptLeakage, type PromptLeakageResult } from './internal/prompt-leakage';
import { resolveSecurityOptions } from './internal/presets';
import { PromptInjectionError, CostLimitError, ContentViolationError, ModelPolicyError, OutputSchemaError, StreamAbortError, JailbreakError, TopicViolationError } from './errors';
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

const DEFAULT_ENDPOINT = 'https://api.launchpromptly.dev';

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
    let security = options.security ? resolveSecurityOptions(options.security) : undefined;

    // Lazy ML provider state — loaded once on first call, cached for subsequent calls
    let mlInitDone = false;
    let mlInitPromise: Promise<void> | null = null;

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

                        // Lazy ML provider initialization (runs once on first call)
                        if (security?.useML && !mlInitDone) {
                          if (!mlInitPromise) {
                            mlInitPromise = (async () => {
                              const { createMLProviders, mergeMLProviders } = await import('./internal/ml-resolver');
                              const mlProviders = await createMLProviders(security!.useML!);
                              security = mergeMLProviders(security!, mlProviders);
                              mlInitDone = true;
                            })();
                          }
                          await mlInitPromise;
                        }

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
                        let jailbreakResult: JailbreakAnalysis | null = null;
                        let unicodeScanResult: UnicodeScanResult | null = null;
                        let inputSecretDetections: SecretDetection[] = [];
                        let outputSecretDetections: SecretDetection[] = [];
                        let topicViolationResult: TopicViolation | null = null;
                        let outputSafetyThreats: OutputSafetyThreat[] = [];
                        let promptLeakageResult: PromptLeakageResult | null = null;
                        let hallucinationResult: import('./internal/hallucination').HallucinationResult | null = null;

                        // Build a mutable copy of params for potential message redaction
                        let effectiveParams = params;

                        const isShadow = security?.mode === 'shadow';

                        if (security) {

                          // 0a. Unicode sanitizer (must run first — clean input for all downstream)
                          if (security.unicodeSanitizer?.enabled !== false && security.unicodeSanitizer) {
                            const allInput = effectiveParams.messages.map((m) => m.content).join('\n');
                            unicodeScanResult = scanUnicode(allInput, {
                              action: security.unicodeSanitizer.action,
                              detectHomoglyphs: security.unicodeSanitizer.detectHomoglyphs,
                            });

                            if (unicodeScanResult.found) {
                              emit('unicode.suspicious', { result: unicodeScanResult });
                              security.unicodeSanitizer.onDetect?.(unicodeScanResult);

                              if (!isShadow && security.unicodeSanitizer.action === 'block') {
                                throw new Error(
                                  `Unicode threat detected: ${unicodeScanResult.threats.length} suspicious characters found`,
                                );
                              }

                              // If action is 'strip', replace message content with sanitized text
                              if (!isShadow && security.unicodeSanitizer.action === 'strip' && unicodeScanResult.sanitizedText != null) {
                                // Re-scan each message individually to get per-message sanitized text
                                const sanitizedMessages: typeof effectiveParams.messages = [];
                                for (const msg of effectiveParams.messages) {
                                  const msgScan = scanUnicode(msg.content, {
                                    action: 'strip',
                                    detectHomoglyphs: security.unicodeSanitizer.detectHomoglyphs,
                                  });
                                  sanitizedMessages.push({
                                    ...msg,
                                    content: msgScan.sanitizedText ?? msg.content,
                                  });
                                }
                                effectiveParams = { ...effectiveParams, messages: sanitizedMessages };
                              }
                            }
                          }

                          // 0b. Model policy enforcement
                          if (security.modelPolicy) {
                            const violation = checkModelPolicy(params, security.modelPolicy);
                            if (violation) {
                              emit('model.blocked', { violation, mode: isShadow ? 'shadow' : 'enforce' });
                              security.modelPolicy.onViolation?.(violation);
                              if (!isShadow) throw new ModelPolicyError(violation);
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
                              emit('cost.exceeded', { violation: costViolation, mode: isShadow ? 'shadow' : 'enforce' });
                              security.costGuard?.onBudgetExceeded?.(costViolation);
                              if (!isShadow) throw new CostLimitError(costViolation);
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
                              const piiOpts = security.pii;
                              const providerDets = await Promise.all(piiOpts.providers!.map(async (p) => {
                                try { return await Promise.resolve(p.detect(allMessageText, { types: piiOpts.types })); }
                                catch { return [] as PIIDetection[]; }
                              }));
                              inputPiiDetections = mergeDetections(inputPiiDetections, ...providerDets);
                            }

                            // Apply suppressive context, allow list, and confidence thresholds
                            const allMsgText = allMessageText;
                            inputPiiDetections = inputPiiDetections.map((d) => applySuppressiveContext(d, allMsgText));
                            if (security.pii?.allowList?.length) {
                              inputPiiDetections = filterAllowList(inputPiiDetections, security.pii.allowList);
                            }
                            if (security.pii?.confidenceThresholds) {
                              inputPiiDetections = filterByConfidence(inputPiiDetections, security.pii.confidenceThresholds);
                            }

                            // Fire callback + guardrail event
                            if (inputPiiDetections.length > 0) {
                              emit('pii.detected', { detections: inputPiiDetections, direction: 'input' });
                              security.pii?.onDetect?.(inputPiiDetections);
                            }

                            // Redact messages if configured
                            const redactionStrategy: RedactionStrategy = security.pii?.redaction ?? 'placeholder';
                            if (!isShadow && inputPiiDetections.length > 0 && redactionStrategy !== 'none') {
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

                          // 3b. Secret detection (input)
                          if (security.secretDetection?.enabled !== false && security.secretDetection) {
                            const allInput = effectiveParams.messages.map((m) => m.content).join('\n');
                            inputSecretDetections = detectSecrets(allInput, {
                              builtInPatterns: security.secretDetection.builtInPatterns,
                              customPatterns: security.secretDetection.customPatterns,
                            });

                            // Merge with provider detections
                            if (security.secretDetection.providers?.length) {
                              const providerDets = await Promise.all(security.secretDetection.providers.map(async (p) => {
                                try { return await Promise.resolve(p.detect(allInput)); }
                                catch { return [] as SecretDetection[]; }
                              }));
                              inputSecretDetections = mergeSecretDetections(inputSecretDetections, ...providerDets);
                            }

                            if (inputSecretDetections.length > 0) {
                              emit('secret.detected', { detections: inputSecretDetections, direction: 'input' });
                              security.secretDetection.onDetect?.(inputSecretDetections);

                              if (!isShadow && security.secretDetection.action === 'block') {
                                throw new Error(
                                  `Secrets detected in input: ${inputSecretDetections.map((d) => d.type).join(', ')}`,
                                );
                              }
                            }
                          }

                          // Extract system prompt for injection/jailbreak awareness
                          const systemPromptText = params.messages
                            .filter((m) => m.role === 'system')
                            .map((m) => m.content)
                            .join('\n');

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
                                systemPrompt: systemPromptText || undefined,
                              });

                              // Merge with ML providers
                              if (security.injection?.providers?.length) {
                                const providerResults = await Promise.all(security.injection.providers.map(async (p) => {
                                  try { return await Promise.resolve(p.detect(userMessages)); }
                                  catch { return { riskScore: 0, triggered: [] as string[], action: 'allow' as const }; }
                                }));
                                injectionResult = mergeInjectionAnalyses(
                                  [injectionResult, ...providerResults],
                                  { blockThreshold: security.injection?.blockThreshold, mergeStrategy: security.injection?.mergeStrategy },
                                );
                              }

                              // Fire callback + guardrail event
                              if (injectionResult.riskScore > 0) {
                                emit('injection.detected', { analysis: injectionResult });
                              }
                              security.injection?.onDetect?.(injectionResult);

                              // Block if configured
                              if (
                                !isShadow &&
                                security.injection?.blockOnHighRisk &&
                                injectionResult.action === 'block'
                              ) {
                                emit('injection.blocked', { analysis: injectionResult });
                                throw new PromptInjectionError(injectionResult);
                              }
                            }
                          }

                          // 4b. Jailbreak detection
                          if (security.jailbreak?.enabled !== false && security.jailbreak) {
                            const userMessages = params.messages
                              .filter((m) => m.role === 'user' || m.role === 'tool' || m.role === 'function')
                              .map((m) => m.content)
                              .join('\n');

                            if (userMessages) {
                              jailbreakResult = detectJailbreak(userMessages, {
                                blockThreshold: security.jailbreak.blockThreshold,
                                warnThreshold: security.jailbreak.warnThreshold,
                                systemPrompt: systemPromptText || undefined,
                              });

                              // Merge with ML providers
                              if (security.jailbreak.providers?.length) {
                                const providerResults = await Promise.all(security.jailbreak.providers.map(async (p) => {
                                  try { return await Promise.resolve(p.detect(userMessages)); }
                                  catch { return { riskScore: 0, triggered: [] as string[], action: 'allow' as const }; }
                                }));
                                jailbreakResult = mergeJailbreakAnalyses(
                                  [jailbreakResult, ...providerResults],
                                  { blockThreshold: security.jailbreak.blockThreshold, mergeStrategy: security.jailbreak.mergeStrategy },
                                );
                              }

                              if (jailbreakResult.riskScore > 0) {
                                emit('jailbreak.detected', { analysis: jailbreakResult });
                                security.jailbreak.onDetect?.(jailbreakResult);
                              }

                              if (
                                !isShadow &&
                                security.jailbreak.blockOnDetection !== false &&
                                jailbreakResult.action === 'block'
                              ) {
                                emit('jailbreak.blocked', { analysis: jailbreakResult });
                                throw new JailbreakError(jailbreakResult);
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

                            // Run pluggable content filter providers (e.g., ML toxicity)
                            if (security.contentFilter.providers?.length) {
                              const providerResults = await Promise.all(
                                security.contentFilter.providers.map(async (p) => {
                                  try {
                                    return await Promise.resolve(p.detect(allInput, 'input'));
                                  } catch {
                                    return [] as ContentViolation[];
                                  }
                                }),
                              );
                              for (const pv of providerResults) {
                                inputContentViolations.push(...pv);
                              }
                            }

                            if (inputContentViolations.length > 0) {
                              emit('content.violated', { violations: inputContentViolations, direction: 'input' });
                            }

                            if (!isShadow && hasBlockingViolation(inputContentViolations, security.contentFilter)) {
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

                          // 6. Topic guard
                          if (security.topicGuard?.enabled !== false && security.topicGuard) {
                            const allInput = effectiveParams.messages.map((m) => m.content).join('\n');
                            topicViolationResult = checkTopicGuard(allInput, {
                              allowedTopics: security.topicGuard.allowedTopics,
                              blockedTopics: security.topicGuard.blockedTopics,
                            });

                            if (topicViolationResult) {
                              emit('topic.violated', { violation: topicViolationResult });
                              security.topicGuard.onViolation?.(topicViolationResult);

                              if (!isShadow && security.topicGuard.action !== 'warn') {
                                throw new TopicViolationError(topicViolationResult);
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
                              streamGuard: isShadow
                                ? { ...security.streamGuard, onViolation: 'flag' as const }
                                : security.streamGuard,
                              pii: security.pii ? {
                                types: security.pii.types,
                                providers: security.pii.providers,
                              } : undefined,
                              injection: security.injection ? {
                                blockThreshold: security.injection.blockThreshold,
                              } : undefined,
                              secretDetection: security.secretDetection?.enabled !== false && security.secretDetection ? {
                                builtInPatterns: security.secretDetection.builtInPatterns,
                                customPatterns: security.secretDetection.customPatterns,
                              } : undefined,
                              outputSafety: security.outputSafety?.enabled !== false && security.outputSafety ? {
                                categories: security.outputSafety.categories,
                              } : undefined,
                              promptLeakage: security.promptLeakage?.enabled !== false && security.promptLeakage ? {
                                systemPrompt: security.promptLeakage.systemPrompt,
                                threshold: security.promptLeakage.threshold,
                              } : undefined,
                              extractText: extractChunkContent,
                              emit,
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

                                // Approximate cost from stream report
                                const approxOutputTokens = report.approximateTokens ?? 0;
                                const streamCost = approxOutputTokens > 0
                                  ? calculateEventCost('openai', params.model, 0, approxOutputTokens)
                                  : 0;

                                if (costGuard && streamCost > 0) {
                                  costGuard.recordCost(streamCost, customerId);
                                }

                                const event: IngestEventPayload = {
                                  provider: 'openai',
                                  model: params.model,
                                  inputTokens: 0,
                                  outputTokens: approxOutputTokens,
                                  totalTokens: approxOutputTokens,
                                  costUsd: streamCost,
                                  latencyMs,
                                  customerId,
                                  feature,
                                  systemHash: fingerprint.systemHash ?? undefined,
                                  fullHash: fingerprint.fullHash,
                                  promptPreview: fingerprint.promptPreview,
                                  responseText: report.responseText ?? undefined,
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
                                      inputDetails: inputPiiDetections.map((d) => ({ type: d.type, start: d.start, end: d.end, confidence: d.confidence })),
                                      outputDetails: streamPiiDetections.map((d) => ({ type: d.type, start: d.start, end: d.end, confidence: d.confidence })),
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

                                  // Pre-call metadata from new guardrails
                                  if (jailbreakResult && jailbreakResult.riskScore > 0) {
                                    event.jailbreakRisk = {
                                      score: jailbreakResult.riskScore,
                                      triggered: jailbreakResult.triggered,
                                      action: jailbreakResult.action,
                                      decodedPayloads: jailbreakResult.decodedPayloads,
                                    };
                                  }

                                  if (unicodeScanResult?.found) {
                                    event.unicodeThreats = {
                                      found: true,
                                      threatCount: unicodeScanResult.threats.length,
                                      threatTypes: [...new Set(unicodeScanResult.threats.map((t) => t.type))],
                                      action: security.unicodeSanitizer?.action ?? 'strip',
                                    };
                                  }

                                  const streamSecrets = report.secretDetections ?? [];
                                  if (inputSecretDetections.length > 0 || streamSecrets.length > 0) {
                                    event.secretDetections = {
                                      inputCount: inputSecretDetections.length,
                                      outputCount: streamSecrets.length,
                                      types: [...new Set([
                                        ...inputSecretDetections.map((d) => d.type),
                                        ...streamSecrets.map((d) => d.type),
                                      ])],
                                    };
                                  }

                                  if (topicViolationResult) {
                                    event.topicViolation = {
                                      type: topicViolationResult.type,
                                      topic: topicViolationResult.topic,
                                      matchedKeywords: topicViolationResult.matchedKeywords,
                                      score: topicViolationResult.score,
                                    };
                                  }

                                  const streamSafetyThreats = report.outputSafetyThreats ?? [];
                                  if (streamSafetyThreats.length > 0) {
                                    event.outputSafety = {
                                      threatCount: streamSafetyThreats.length,
                                      categories: [...new Set(streamSafetyThreats.map((t) => t.category))],
                                      threats: streamSafetyThreats.map((t) => ({
                                        category: t.category,
                                        matched: t.matched,
                                        severity: t.severity,
                                      })),
                                    };
                                  }

                                  if (report.promptLeakageResult?.leaked) {
                                    event.promptLeakage = {
                                      leaked: true,
                                      similarity: report.promptLeakageResult.similarity,
                                      metaResponseDetected: report.promptLeakageResult.metaResponseDetected,
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
                        const responseText = (result as any).choices?.[0]?.message?.content as string | undefined;

                        if (security) {

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

                            // Run pluggable content filter providers on output
                            if (security.contentFilter.providers?.length) {
                              const providerResults = await Promise.all(
                                security.contentFilter.providers.map(async (p) => {
                                  try {
                                    return await Promise.resolve(p.detect(responseText, 'output'));
                                  } catch {
                                    return [] as ContentViolation[];
                                  }
                                }),
                              );
                              for (const pv of providerResults) {
                                outputContentViolations.push(...pv);
                              }
                            }

                            if (outputContentViolations.length > 0) {
                              emit('content.violated', { violations: outputContentViolations, direction: 'output' });
                            }
                          }

                          // Post-call: output safety scan
                          if (security.outputSafety?.enabled !== false && security.outputSafety && responseText) {
                            outputSafetyThreats = scanOutputSafety(responseText, {
                              categories: security.outputSafety.categories,
                            });

                            if (outputSafetyThreats.length > 0) {
                              emit('output.unsafe', { threats: outputSafetyThreats });
                              security.outputSafety.onDetect?.(outputSafetyThreats);

                              if (!isShadow && security.outputSafety.action === 'block') {
                                throw new Error(
                                  `Unsafe output detected: ${outputSafetyThreats.map((t) => t.category).join(', ')}`,
                                );
                              }
                            }
                          }

                          // Post-call: prompt leakage detection
                          if (security.promptLeakage?.enabled !== false && security.promptLeakage && responseText) {
                            promptLeakageResult = detectPromptLeakage(responseText, {
                              systemPrompt: security.promptLeakage.systemPrompt,
                              threshold: security.promptLeakage.threshold,
                            });

                            if (promptLeakageResult.leaked) {
                              emit('prompt.leaked', { result: promptLeakageResult });
                              security.promptLeakage.onDetect?.(promptLeakageResult);

                              if (!isShadow && security.promptLeakage.blockOnLeak) {
                                throw new Error(
                                  `System prompt leakage detected (similarity: ${promptLeakageResult.similarity.toFixed(2)})`,
                                );
                              }
                            }
                          }

                          // Post-call: hallucination detection
                          if (security.hallucination?.enabled !== false && security.hallucination && responseText) {
                            // Determine source text: explicit > system prompt
                            let sourceText = security.hallucination.sourceText;
                            if (!sourceText && security.hallucination.extractFromSystemPrompt !== false) {
                              const sysMsg = params.messages.find((m) => m.role === 'system');
                              if (sysMsg && typeof sysMsg.content === 'string') {
                                sourceText = sysMsg.content;
                              }
                            }

                            if (sourceText) {
                              const { detectHallucination, mergeHallucinationResults } = await import('./internal/hallucination');
                              hallucinationResult = detectHallucination(responseText, sourceText, {
                                threshold: security.hallucination.threshold,
                              });

                              // Run ML providers if available
                              if (security.hallucination.providers?.length) {
                                const providerResults = await Promise.all(
                                  security.hallucination.providers.map(async (p) => {
                                    try {
                                      return await Promise.resolve(p.detect(responseText, sourceText!));
                                    } catch {
                                      return null;
                                    }
                                  }),
                                );
                                const validResults = providerResults.filter(Boolean) as import('./internal/hallucination').HallucinationResult[];
                                if (validResults.length > 0) {
                                  hallucinationResult = mergeHallucinationResults([hallucinationResult!, ...validResults]);
                                }
                              }

                              if (hallucinationResult!.hallucinated) {
                                emit('hallucination.detected', { result: hallucinationResult });
                                security.hallucination.onDetect?.(hallucinationResult!);

                                if (!isShadow && security.hallucination.blockOnDetection) {
                                  emit('hallucination.blocked', { result: hallucinationResult });
                                  throw new Error(
                                    `Hallucination detected (faithfulness: ${hallucinationResult!.faithfulnessScore.toFixed(2)})`,
                                  );
                                }
                              }
                            }
                          }

                          // Post-call: secret detection (output)
                          if (security.secretDetection?.enabled !== false && security.secretDetection?.scanResponse !== false && security.secretDetection && responseText) {
                            outputSecretDetections = detectSecrets(responseText, {
                              builtInPatterns: security.secretDetection.builtInPatterns,
                              customPatterns: security.secretDetection.customPatterns,
                            });

                            if (security.secretDetection.providers?.length) {
                              const providerDets = await Promise.all(security.secretDetection.providers.map(async (p) => {
                                try { return await Promise.resolve(p.detect(responseText!)); }
                                catch { return [] as SecretDetection[]; }
                              }));
                              outputSecretDetections = mergeSecretDetections(outputSecretDetections, ...providerDets);
                            }

                            if (outputSecretDetections.length > 0) {
                              emit('secret.detected', { detections: outputSecretDetections, direction: 'output' });
                              security.secretDetection.onDetect?.(outputSecretDetections);
                            }
                          }

                          // Post-call: output schema validation
                          if (security.outputSchema && responseText) {
                            const validation = validateOutputSchema(responseText, security.outputSchema);
                            if (!validation.valid) {
                              emit('schema.invalid', { errors: validation.errors, responseText });
                              if (!isShadow && security.outputSchema.blockOnInvalid) {
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
                              promptPreview: fingerprint.promptPreview,
                              responseText: responseText ?? undefined,
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
                                  inputDetails: inputPiiDetections.map((d) => ({ type: d.type, start: d.start, end: d.end, confidence: d.confidence })),
                                  outputDetails: outputPiiDetections.map((d) => ({ type: d.type, start: d.start, end: d.end, confidence: d.confidence })),
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

                              if (jailbreakResult && jailbreakResult.riskScore > 0) {
                                event.jailbreakRisk = {
                                  score: jailbreakResult.riskScore,
                                  triggered: jailbreakResult.triggered,
                                  action: jailbreakResult.action,
                                  decodedPayloads: jailbreakResult.decodedPayloads,
                                };
                              }

                              if (unicodeScanResult?.found) {
                                event.unicodeThreats = {
                                  found: true,
                                  threatCount: unicodeScanResult.threats.length,
                                  threatTypes: [...new Set(unicodeScanResult.threats.map((t) => t.type))],
                                  action: security.unicodeSanitizer?.action ?? 'strip',
                                };
                              }

                              if (inputSecretDetections.length > 0 || outputSecretDetections.length > 0) {
                                event.secretDetections = {
                                  inputCount: inputSecretDetections.length,
                                  outputCount: outputSecretDetections.length,
                                  types: [...new Set([
                                    ...inputSecretDetections.map((d) => d.type),
                                    ...outputSecretDetections.map((d) => d.type),
                                  ])],
                                };
                              }

                              if (topicViolationResult) {
                                event.topicViolation = {
                                  type: topicViolationResult.type,
                                  topic: topicViolationResult.topic,
                                  matchedKeywords: topicViolationResult.matchedKeywords,
                                  score: topicViolationResult.score,
                                };
                              }

                              if (outputSafetyThreats.length > 0) {
                                event.outputSafety = {
                                  threatCount: outputSafetyThreats.length,
                                  categories: [...new Set(outputSafetyThreats.map((t) => t.category))],
                                  threats: outputSafetyThreats.map((t) => ({
                                    category: t.category,
                                    matched: t.matched,
                                    severity: t.severity,
                                  })),
                                };
                              }

                              if (promptLeakageResult?.leaked) {
                                event.promptLeakage = {
                                  leaked: true,
                                  similarity: promptLeakageResult.similarity,
                                  metaResponseDetected: promptLeakageResult.metaResponseDetected,
                                };
                              }

                              if (hallucinationResult?.hallucinated) {
                                event.hallucination = {
                                  detected: true,
                                  faithfulness_score: hallucinationResult.faithfulnessScore,
                                  severity: hallucinationResult.severity,
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

  /**
   * Report feedback on a guardrail detection to improve future accuracy.
   *
   * @param eventId - The event ID returned by the dashboard or event payload.
   * @param options - Feedback details: guardrailType, originalAction, feedback.
   */
  async reportFeedback(
    eventId: string,
    options: {
      guardrailType: 'injection' | 'jailbreak' | 'pii' | 'content';
      originalAction: 'allow' | 'warn' | 'block';
      feedback: 'correct' | 'false_positive' | 'false_negative';
      notes?: string;
    },
  ): Promise<void> {
    try {
      const res = await fetch(`${this.endpoint}/v1/security/feedback/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({ eventId, ...options }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) {
        // Log but don't throw — feedback is non-critical
        // eslint-disable-next-line no-console
        console.warn(`[launchpromptly] feedback report failed: ${res.status}`);
      }
    } catch {
      // Swallow — feedback is fire-and-forget
    }
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
