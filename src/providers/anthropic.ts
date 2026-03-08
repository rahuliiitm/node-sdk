/**
 * Anthropic Claude provider adapter.
 *
 * Wraps Anthropic client's `client.messages.create()` with the full
 * security pipeline (PII, injection, content filter, cost guard).
 *
 * @module
 */

import type { AsyncLocalStorage } from 'node:async_hooks';
import type { EventBatcher } from '../batcher';
import type { RequestContext, WrapOptions, SecurityOptions } from '../types';
import type { IngestEventPayload } from '../internal/event-types';
import { calculateEventCost } from '../internal/cost';
import { fingerprintMessages } from '../internal/fingerprint';
import { detectPII, mergeDetections, type PIIDetection } from '../internal/pii';
import { redactPII, deRedact } from '../internal/redaction';
import { detectInjection, mergeInjectionAnalyses, type InjectionAnalysis } from '../internal/injection';
import { CostGuard, type BudgetViolation } from '../internal/cost-guard';
import { detectContentViolations, hasBlockingViolation, type ContentViolation } from '../internal/content-filter';
import { StreamGuardEngine, type StreamSecurityReport } from '../internal/streaming';
import { checkModelPolicy } from '../internal/model-policy';
import { validateOutputSchema } from '../internal/schema-validator';
import { PromptInjectionError, CostLimitError, ContentViolationError, ModelPolicyError, OutputSchemaError } from '../errors';

// ── Anthropic Types ──────────────────────────────────────────────────────────

export interface AnthropicContentBlock {
  type: string;
  text?: string;
  id?: string;
  name?: string;
  input?: any;
  tool_use_id?: string;
  content?: string | AnthropicContentBlock[];
}

export interface AnthropicMessage {
  role: 'user' | 'assistant';
  content: string | AnthropicContentBlock[];
}

export interface AnthropicCreateParams {
  model: string;
  messages: AnthropicMessage[];
  max_tokens: number;
  system?: string | AnthropicContentBlock[];
  temperature?: number;
  tools?: any[];
  stream?: boolean;
  [key: string]: unknown;
}

export interface AnthropicUsage {
  input_tokens: number;
  output_tokens: number;
}

export interface AnthropicResponse {
  id: string;
  type: string;
  role: string;
  content: AnthropicContentBlock[];
  model: string;
  stop_reason: string;
  usage: AnthropicUsage;
  [key: string]: unknown;
}

// ── Message Extraction Helpers ───────────────────────────────────────────────

/**
 * Extract text content from an Anthropic content block or string.
 */
export function extractContentBlockText(content: string | AnthropicContentBlock[]): string {
  if (typeof content === 'string') return content;
  return content
    .filter((b) => b.type === 'text' && typeof b.text === 'string')
    .map((b) => b.text!)
    .join('\n');
}

/**
 * Extract all message text from Anthropic params for security scanning.
 * Includes system prompt and all messages.
 */
export function extractAnthropicMessageTexts(params: AnthropicCreateParams): {
  allText: string;
  userText: string;
  systemText: string;
} {
  const parts: string[] = [];
  const userParts: string[] = [];

  // System prompt
  let systemText = '';
  if (params.system) {
    systemText = typeof params.system === 'string'
      ? params.system
      : extractContentBlockText(params.system);
    parts.push(systemText);
  }

  // Messages
  for (const msg of params.messages) {
    const text = extractContentBlockText(msg.content);
    parts.push(text);
    // Include user messages and tool_result blocks (untrusted external input)
    if (msg.role === 'user') {
      userParts.push(text);
    }
  }

  return {
    allText: parts.join('\n'),
    userText: userParts.join('\n'),
    systemText,
  };
}

/**
 * Apply redaction to Anthropic message content.
 * Returns new content with PII replaced.
 */
async function redactContent(
  content: string | AnthropicContentBlock[],
  strategy: import('../internal/redaction').RedactionStrategy,
  types?: import('../internal/pii').PIIType[],
  providers?: import('../internal/pii').PIIDetectorProvider[],
  mapping?: Map<string, string>,
): Promise<string | AnthropicContentBlock[]> {
  if (typeof content === 'string') {
    const result = await redactPII(content, { strategy, types, providers });
    if (mapping) {
      for (const [k, v] of result.mapping) mapping.set(k, v);
    }
    return result.redactedText;
  }

  return Promise.all(content.map(async (block) => {
    if (block.type === 'text' && typeof block.text === 'string') {
      const result = await redactPII(block.text, { strategy, types, providers });
      if (mapping) {
        for (const [k, v] of result.mapping) mapping.set(k, v);
      }
      return { ...block, text: result.redactedText };
    }
    return block;
  }));
}

/**
 * Extract response text from Anthropic response.
 */
export function extractAnthropicResponseText(result: AnthropicResponse): string | undefined {
  if (!result.content) return undefined;
  return extractContentBlockText(result.content);
}

/**
 * Extract tool use blocks from Anthropic response.
 */
export function extractAnthropicToolCalls(result: AnthropicResponse): AnthropicContentBlock[] {
  if (!result.content) return [];
  return result.content.filter((b) => b.type === 'tool_use');
}

/**
 * Extract text from Anthropic streaming chunk.
 */
export function extractAnthropicStreamChunk(chunk: any): string | null {
  // content_block_delta with text_delta
  if (chunk?.type === 'content_block_delta' && chunk?.delta?.type === 'text_delta') {
    return chunk.delta.text ?? null;
  }
  // Simple text delta
  if (chunk?.delta?.text) {
    return chunk.delta.text;
  }
  return null;
}

// ── Dependencies Interface ───────────────────────────────────────────────────

export interface WrapDependencies {
  batcher: EventBatcher;
  als: AsyncLocalStorage<RequestContext>;
  emit?: (type: import('../types').GuardrailEventType, data: Record<string, unknown>) => void;
}

// ── Main Wrapper ─────────────────────────────────────────────────────────────

/**
 * Wrap an Anthropic client with the full LaunchPromptly security pipeline.
 *
 * Intercepts `client.messages.create()` calls to run PII redaction,
 * injection detection, cost controls, and content filtering
 * before and after the API call.
 *
 * @example
 * ```ts
 * import Anthropic from '@anthropic-ai/sdk';
 *
 * const client = new Anthropic({ apiKey: '...' });
 * const wrapped = lp.wrapAnthropic(client, {
 *   security: { pii: { redaction: 'placeholder' } },
 * });
 *
 * const result = await wrapped.messages.create({
 *   model: 'claude-sonnet-4-20250514',
 *   max_tokens: 1024,
 *   messages: [{ role: 'user', content: 'Hello' }],
 * });
 * ```
 */
export function wrapAnthropicClient<T extends object>(
  client: T,
  deps: WrapDependencies,
  options: WrapOptions = {},
): T {
  const { batcher, als, emit } = deps;
  const customerFn = options.customer;
  const featureTag = options.feature;
  const traceIdTag = options.traceId;
  const spanNameTag = options.spanName;
  const security = options.security;

  const costGuard = security?.costGuard ? new CostGuard(security.costGuard) : null;

  return new Proxy(client, {
    get(target, prop) {
      const value = Reflect.get(target, prop);

      if (prop === 'messages') {
        return new Proxy(value as object, {
          get(msgTarget, msgProp) {
            const msgValue = Reflect.get(value as object, msgProp);

            if (msgProp === 'create') {
              return async (params: AnthropicCreateParams): Promise<AnthropicResponse> => {
                const alsCtx = als.getStore();

                // ── PRE-CALL SECURITY ────────────────────────────
                let inputPiiDetections: PIIDetection[] = [];
                let outputPiiDetections: PIIDetection[] = [];
                let injectionResult: InjectionAnalysis | null = null;
                let costViolation: BudgetViolation | null = null;
                let inputContentViolations: ContentViolation[] = [];
                let outputContentViolations: ContentViolation[] = [];
                const redactionMapping = new Map<string, string>();
                let redactionApplied = false;
                let effectiveParams = params;

                if (security) {
                  // 0. Model policy enforcement (first check)
                  if (security.modelPolicy) {
                    const violation = checkModelPolicy(params, security.modelPolicy);
                    if (violation) {
                      security.modelPolicy.onViolation?.(violation);
                      emit?.('model.blocked', { violation });
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
                      maxTokens: params.max_tokens,
                      customerId,
                    });
                    if (costViolation && costGuard.shouldBlock) {
                      security.costGuard?.onBudgetExceeded?.(costViolation);
                      emit?.('cost.exceeded', { violation: costViolation });
                      throw new CostLimitError(costViolation);
                    }
                  }

                  // 3. PII detection + redaction
                  if (security.pii?.enabled !== false) {
                    const { allText } = extractAnthropicMessageTexts(params);

                    let detections = detectPII(allText, { types: security.pii?.types });
                    if (security.pii?.providers?.length) {
                      const providerDets = await Promise.all(security.pii.providers.map(async (p) => {
                        try { return await Promise.resolve(p.detect(allText, { types: security.pii?.types })); }
                        catch { return [] as PIIDetection[]; }
                      }));
                      detections = mergeDetections(detections, ...providerDets);
                    }
                    inputPiiDetections = detections;

                    if (inputPiiDetections.length > 0) {
                      security.pii?.onDetect?.(inputPiiDetections);
                      emit?.('pii.detected', { detections: inputPiiDetections, direction: 'input' });
                    }

                    const strategy = security.pii?.redaction ?? 'placeholder';
                    if (inputPiiDetections.length > 0 && strategy !== 'none') {
                      redactionApplied = true;
                      emit?.('pii.redacted', { strategy, count: inputPiiDetections.length });
                      const redactedMessages = await Promise.all(params.messages.map(async (msg) => ({
                        ...msg,
                        content: await redactContent(msg.content, strategy, security.pii?.types, security.pii?.providers, redactionMapping),
                      })));

                      let redactedSystem = params.system;
                      if (params.system) {
                        redactedSystem = typeof params.system === 'string'
                          ? await redactContent(params.system, strategy, security.pii?.types, security.pii?.providers, redactionMapping) as string
                          : await redactContent(params.system, strategy, security.pii?.types, security.pii?.providers, redactionMapping) as AnthropicContentBlock[];
                      }

                      effectiveParams = {
                        ...params,
                        messages: redactedMessages,
                        ...(redactedSystem !== undefined && { system: redactedSystem }),
                      };
                    }
                  }

                  // 4. Injection detection
                  if (security.injection?.enabled !== false) {
                    const { userText } = extractAnthropicMessageTexts(params);
                    if (userText) {
                      injectionResult = detectInjection(userText, {
                        blockThreshold: security.injection?.blockThreshold,
                      });
                      if (security.injection?.providers?.length) {
                        const providerResults = await Promise.all(security.injection.providers.map(async (p) => {
                          try { return await Promise.resolve(p.detect(userText)); }
                          catch { return { riskScore: 0, triggered: [] as string[], action: 'allow' as const }; }
                        }));
                        injectionResult = mergeInjectionAnalyses(
                          [injectionResult, ...providerResults],
                          { blockThreshold: security.injection?.blockThreshold },
                        );
                      }
                      security.injection?.onDetect?.(injectionResult);
                      if (injectionResult.riskScore > 0) {
                        emit?.('injection.detected', { analysis: injectionResult });
                      }
                      if (security.injection?.blockOnHighRisk && injectionResult.action === 'block') {
                        emit?.('injection.blocked', { analysis: injectionResult });
                        throw new PromptInjectionError(injectionResult);
                      }
                    }
                  }

                  // 5. Content filter
                  if (security.contentFilter?.enabled !== false && security.contentFilter) {
                    const { allText } = extractAnthropicMessageTexts(params);
                    inputContentViolations = detectContentViolations(allText, 'input', security.contentFilter);
                    if (inputContentViolations.length > 0) {
                      emit?.('content.violated', { violations: inputContentViolations, direction: 'input' });
                    }
                    if (hasBlockingViolation(inputContentViolations, security.contentFilter)) {
                      security.contentFilter.onViolation?.(inputContentViolations[0]);
                      throw new ContentViolationError(inputContentViolations);
                    }
                    for (const v of inputContentViolations) {
                      security.contentFilter.onViolation?.(v);
                    }
                  }
                }

                // ── STREAMING ────────────────────────────────────
                if (params.stream === true) {
                  const startMs = Date.now();
                  const streamResult = await (msgValue as Function).call(value, effectiveParams);
                  const latencyMs = Date.now() - startMs;

                  // Choose between StreamGuardEngine (real-time) and legacy buffering (post-hoc)
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
                      extractText: extractAnthropicStreamChunk,
                    });
                    const guarded = engine.wrap(streamResult as AsyncIterable<any>);
                    outputStream = guarded;
                    getStreamReport = () => guarded.getReport();
                  } else {
                    // Legacy: buffer and scan post-hoc
                    const contentParts: string[] = [];
                    let streamPiiDetections: PIIDetection[] = [];
                    const legacyStream = (async function* () {
                      for await (const chunk of streamResult as AsyncIterable<any>) {
                        const text = extractAnthropicStreamChunk(chunk);
                        if (text) contentParts.push(text);
                        yield chunk;
                      }
                      const responseText = contentParts.join('');
                      if (security?.pii?.enabled !== false && responseText) {
                        streamPiiDetections = detectPII(responseText, { types: security?.pii?.types });
                      }
                    })();
                    outputStream = legacyStream;
                    getStreamReport = () => ({
                      piiDetections: streamPiiDetections,
                      injectionRisk: undefined,
                      secretDetections: [],
                      outputSafetyThreats: [],
                      responseText: contentParts.join(''),
                      streamViolations: [],
                      aborted: false,
                      approximateTokens: 0,
                      responseLength: contentParts.join('').length,
                      responseWordCount: 0,
                    });
                  }

                  const wrappedStream = (async function* () {
                    yield* outputStream;

                    // Stream complete — capture event
                    void (async () => {
                      try {
                        const report = getStreamReport();

                        const { systemText } = extractAnthropicMessageTexts(params);
                        const normalizedMsgs = params.messages.map((m) => ({
                          role: m.role,
                          content: extractContentBlockText(m.content),
                        }));
                        const fingerprint = fingerprintMessages(
                          normalizedMsgs,
                          systemText || undefined,
                        );

                        let customerId = alsCtx?.customerId;
                        let feature = alsCtx?.feature ?? featureTag;
                        if (!customerId && customerFn) {
                          const ctx = await customerFn();
                          customerId = ctx.id;
                          feature = ctx.feature ?? feature;
                        }

                        const event: IngestEventPayload = {
                          provider: 'anthropic',
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
                          traceId: alsCtx?.traceId ?? traceIdTag,
                          spanName: alsCtx?.spanName ?? spanNameTag,
                          metadata: alsCtx?.metadata,
                        };

                        if (security) {
                          const streamPiiDetections = report.piiDetections;
                          const allPii = [...inputPiiDetections, ...streamPiiDetections];
                          if (allPii.length > 0) {
                            event.piiDetections = {
                              inputCount: inputPiiDetections.length,
                              outputCount: streamPiiDetections.length,
                              types: [...new Set(allPii.map((d) => d.type))],
                              redactionApplied,
                              detectorUsed: (security.pii?.providers?.length ?? 0) > 0 ? 'both' : 'regex',
                            };
                          }
                          const injResult = report.injectionRisk ?? injectionResult;
                          if (injResult) {
                            event.injectionRisk = {
                              score: injResult.riskScore,
                              triggered: injResult.triggered,
                              action: injResult.action,
                              detectorUsed: (security.injection?.providers?.length ?? 0) > 0 ? 'both' : 'rules',
                            };
                          }
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
                      } catch { /* SDK must never throw */ }
                    })();
                  })();

                  return wrappedStream as any;
                }

                // ── NON-STREAMING ────────────────────────────────
                const startMs = Date.now();
                const result = await (msgValue as Function).call(value, effectiveParams) as AnthropicResponse;
                const latencyMs = Date.now() - startMs;

                let responseForCaller: AnthropicResponse = result;

                if (security) {
                  const responseText = extractAnthropicResponseText(result);

                  // Post-call: PII scan response
                  if (security.pii?.scanResponse && responseText) {
                    outputPiiDetections = detectPII(responseText, { types: security.pii?.types });
                  }

                  // Post-call: scan tool use inputs for PII
                  const toolUseBlocks = extractAnthropicToolCalls(result);
                  if (security.pii?.enabled !== false && toolUseBlocks.length > 0) {
                    const toolTexts = toolUseBlocks
                      .map((b) => typeof b.input === 'string' ? b.input : JSON.stringify(b.input ?? ''))
                      .join('\n');
                    const toolDetections = detectPII(toolTexts, { types: security.pii?.types });
                    outputPiiDetections.push(...toolDetections);
                  }

                  // Post-call: emit output PII event
                  if (outputPiiDetections.length > 0) {
                    emit?.('pii.detected', { detections: outputPiiDetections, direction: 'output' });
                  }

                  // Post-call: content filter
                  if (security.contentFilter?.enabled !== false && security.contentFilter && responseText) {
                    outputContentViolations = detectContentViolations(responseText, 'output', security.contentFilter);
                    if (outputContentViolations.length > 0) {
                      emit?.('content.violated', { violations: outputContentViolations, direction: 'output' });
                    }
                  }

                  // Post-call: output schema validation
                  if (security.outputSchema && responseText) {
                    const validation = validateOutputSchema(responseText, security.outputSchema);
                    if (!validation.valid && security.outputSchema.blockOnInvalid) {
                      emit?.('schema.invalid', { errors: validation.errors, responseText });
                      throw new OutputSchemaError(validation.errors, responseText);
                    }
                  }

                  // Post-call: de-redact
                  if (redactionMapping.size > 0 && responseText) {
                    const deRedactedText = deRedact(responseText, redactionMapping);
                    if (deRedactedText !== responseText) {
                      const newContent = result.content.map((block) => {
                        if (block.type === 'text' && typeof block.text === 'string') {
                          return { ...block, text: deRedact(block.text, redactionMapping) };
                        }
                        return block;
                      });
                      responseForCaller = { ...result, content: newContent };
                    }
                  }

                  // Post-call: cost guard update
                  if (costGuard && result.usage) {
                    const actualCost = calculateEventCost(
                      'anthropic', params.model,
                      result.usage.input_tokens, result.usage.output_tokens,
                    );
                    let customerId = alsCtx?.customerId;
                    if (!customerId && customerFn) {
                      try { customerId = (await customerFn()).id; } catch { /* ignore */ }
                    }
                    costGuard.recordCost(actualCost, customerId);
                  }
                }

                // ── CAPTURE EVENT ────────────────────────────────
                void (async () => {
                  try {
                    const usage = result.usage;
                    if (!usage) return;

                    const inputTokens = usage.input_tokens;
                    const outputTokens = usage.output_tokens;
                    const totalTokens = inputTokens + outputTokens;
                    const costUsd = calculateEventCost('anthropic', params.model, inputTokens, outputTokens);

                    const { systemText } = extractAnthropicMessageTexts(params);
                    const normalizedMsgs = params.messages.map((m) => ({
                      role: m.role,
                      content: extractContentBlockText(m.content),
                    }));
                    const fingerprint = fingerprintMessages(
                      normalizedMsgs,
                      systemText || undefined,
                    );

                    let customerId = alsCtx?.customerId;
                    let feature = alsCtx?.feature ?? featureTag;
                    if (!customerId && customerFn) {
                      const ctx = await customerFn();
                      customerId = ctx.id;
                      feature = ctx.feature ?? feature;
                    }

                    const event: IngestEventPayload = {
                      provider: 'anthropic',
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
                      traceId: alsCtx?.traceId ?? traceIdTag,
                      spanName: alsCtx?.spanName ?? spanNameTag,
                      metadata: alsCtx?.metadata,
                    };

                    // Enrich with security metadata
                    if (security) {
                      const hasMlPii = (security.pii?.providers?.length ?? 0) > 0;
                      const hasMlInj = (security.injection?.providers?.length ?? 0) > 0;

                      if (inputPiiDetections.length > 0 || outputPiiDetections.length > 0) {
                        event.piiDetections = {
                          inputCount: inputPiiDetections.length,
                          outputCount: outputPiiDetections.length,
                          types: [...new Set([
                            ...inputPiiDetections.map((d) => d.type),
                            ...outputPiiDetections.map((d) => d.type),
                          ])],
                          redactionApplied,
                          detectorUsed: hasMlPii ? 'both' : 'regex',
                        };
                      }

                      if (injectionResult) {
                        event.injectionRisk = {
                          score: injectionResult.riskScore,
                          triggered: injectionResult.triggered,
                          action: injectionResult.action,
                          detectorUsed: hasMlInj ? 'both' : 'rules',
                        };
                      }

                      if (inputContentViolations.length > 0 || outputContentViolations.length > 0) {
                        event.contentViolations = {
                          inputViolations: inputContentViolations.map((v) => ({
                            category: v.category, matched: v.matched, severity: v.severity,
                          })),
                          outputViolations: outputContentViolations.map((v) => ({
                            category: v.category, matched: v.matched, severity: v.severity,
                          })),
                        };
                      }

                      if (costGuard) {
                        event.costGuard = {
                          estimatedCost: costUsd,
                          budgetRemaining: Math.max(0,
                            (security.costGuard?.maxCostPerHour ?? Infinity) - costGuard.getCurrentHourSpend(),
                          ),
                          limitTriggered: costViolation?.type,
                        };
                      }
                    }

                    batcher.enqueue(event);
                  } catch { /* SDK must never throw */ }
                })();

                return responseForCaller;
              };
            }

            return typeof msgValue === 'function'
              ? (msgValue as Function).bind(value)
              : msgValue;
          },
        });
      }

      return typeof value === 'function'
        ? (value as Function).bind(target)
        : value;
    },
  }) as T;
}
