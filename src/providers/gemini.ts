/**
 * Google Gemini provider adapter.
 *
 * Wraps Gemini client's `client.models.generateContent()` with the full
 * security pipeline (PII, injection, content filter, cost guard).
 *
 * Supports both the new `@google/genai` SDK format.
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
import { PromptInjectionError, CostLimitError, ContentViolationError, ModelPolicyError, OutputSchemaError, ResponseBoundaryError } from '../errors';
import { resolveSecurityOptions } from '../internal/presets';
import { extractContext, extractContextWithProviders, type ContextProfile } from '../internal/context-engine';
import { judgeResponse, mergeJudgments, type ResponseJudgment } from '../internal/response-judge';

// ── Gemini Types ─────────────────────────────────────────────────────────────

export interface GeminiPart {
  text?: string;
  functionCall?: { name: string; args: any };
  functionResponse?: { name: string; response: any };
  inlineData?: { mimeType: string; data: string };
  [key: string]: unknown;
}

export interface GeminiContent {
  role?: 'user' | 'model' | 'tool';
  parts: GeminiPart[];
}

export interface GeminiGenerateContentParams {
  model: string;
  contents: GeminiContent[] | string;
  config?: {
    systemInstruction?: string | GeminiContent;
    temperature?: number;
    maxOutputTokens?: number;
    tools?: any[];
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface GeminiUsageMetadata {
  promptTokenCount: number;
  candidatesTokenCount: number;
  totalTokenCount: number;
}

export interface GeminiCandidate {
  content: GeminiContent;
  finishReason?: string;
  [key: string]: unknown;
}

export interface GeminiResponse {
  candidates?: GeminiCandidate[];
  usageMetadata?: GeminiUsageMetadata;
  text?: string;
  [key: string]: unknown;
}

// ── Message Extraction Helpers ───────────────────────────────────────────────

/**
 * Extract text from a Gemini part.
 */
function extractPartText(part: GeminiPart): string | null {
  if (typeof part.text === 'string') return part.text;
  if (part.functionCall) return JSON.stringify(part.functionCall.args ?? {});
  if (part.functionResponse) return JSON.stringify(part.functionResponse.response ?? {});
  return null;
}

/**
 * Extract text from Gemini content (array of parts).
 */
export function extractGeminiContentText(content: GeminiContent): string {
  return content.parts
    .map(extractPartText)
    .filter(Boolean)
    .join('\n');
}

/**
 * Normalize Gemini contents to a string. Handles both string and Content[] formats.
 */
function normalizeContents(contents: GeminiContent[] | string): GeminiContent[] {
  if (typeof contents === 'string') {
    return [{ role: 'user', parts: [{ text: contents }] }];
  }
  return contents;
}

/**
 * Extract all message texts from Gemini params for security scanning.
 */
export function extractGeminiMessageTexts(params: GeminiGenerateContentParams): {
  allText: string;
  userText: string;
  systemText: string;
} {
  const parts: string[] = [];
  const userParts: string[] = [];

  // System instruction
  let systemText = '';
  if (params.config?.systemInstruction) {
    if (typeof params.config.systemInstruction === 'string') {
      systemText = params.config.systemInstruction;
    } else {
      systemText = extractGeminiContentText(params.config.systemInstruction);
    }
    parts.push(systemText);
  }

  // Contents
  const contents = normalizeContents(params.contents);
  for (const content of contents) {
    const text = extractGeminiContentText(content);
    parts.push(text);
    // Include user messages and tool results (untrusted external input)
    if (content.role === 'user' || content.role === 'tool') {
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
 * Apply redaction to Gemini content parts.
 */
async function redactGeminiContent(
  content: GeminiContent,
  strategy: import('../internal/redaction').RedactionStrategy,
  types?: import('../internal/pii').PIIType[],
  providers?: import('../internal/pii').PIIDetectorProvider[],
  mapping?: Map<string, string>,
): Promise<GeminiContent> {
  const redactedParts = await Promise.all(content.parts.map(async (part) => {
    if (typeof part.text === 'string') {
      const result = await redactPII(part.text, { strategy, types, providers });
      if (mapping) {
        for (const [k, v] of result.mapping) mapping.set(k, v);
      }
      return { ...part, text: result.redactedText };
    }
    return part;
  }));
  return { ...content, parts: redactedParts };
}

/**
 * Extract response text from Gemini response.
 */
export function extractGeminiResponseText(result: GeminiResponse): string | undefined {
  // Direct text accessor (some SDK versions)
  if (typeof result.text === 'string') return result.text;

  // Standard candidates path
  if (result.candidates?.[0]?.content?.parts) {
    return result.candidates[0].content.parts
      .filter((p: GeminiPart) => typeof p.text === 'string')
      .map((p: GeminiPart) => p.text!)
      .join('');
  }

  return undefined;
}

/**
 * Extract function calls from Gemini response.
 */
export function extractGeminiFunctionCalls(result: GeminiResponse): GeminiPart[] {
  const parts = result.candidates?.[0]?.content?.parts ?? [];
  return parts.filter((p: GeminiPart) => p.functionCall != null);
}

/**
 * Extract text from Gemini streaming chunk.
 */
export function extractGeminiStreamChunk(chunk: any): string | null {
  // Standard format
  if (chunk?.candidates?.[0]?.content?.parts?.[0]?.text) {
    return chunk.candidates[0].content.parts[0].text;
  }
  // Direct text
  if (typeof chunk?.text === 'string') {
    return chunk.text;
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
 * Wrap a Google Gemini client with the full LaunchPromptly security pipeline.
 *
 * Intercepts `client.models.generateContent()` and
 * `client.models.generateContentStream()` calls to run PII redaction,
 * injection detection, cost controls, and content filtering
 * before and after the API call.
 *
 * @example
 * ```ts
 * import { GoogleGenAI } from '@google/genai';
 *
 * const client = new GoogleGenAI({ apiKey: '...' });
 * const wrapped = lp.wrapGemini(client, {
 *   security: { pii: { redaction: 'placeholder' } },
 * });
 *
 * const result = await wrapped.models.generateContent({
 *   model: 'gemini-2.0-flash',
 *   contents: [{ role: 'user', parts: [{ text: 'Hello' }] }],
 * });
 * ```
 */
export function wrapGeminiClient<T extends object>(
  client: T,
  deps: WrapDependencies,
  options: WrapOptions = {},
): T {
  const { batcher, als, emit } = deps;
  const customerFn = options.customer;
  const featureTag = options.feature;
  const traceIdTag = options.traceId;
  const spanNameTag = options.spanName;
  const security = options.security ? resolveSecurityOptions(options.security) : undefined;

  const costGuard = security?.costGuard ? new CostGuard(security.costGuard) : null;

  return new Proxy(client, {
    get(target, prop) {
      const value = Reflect.get(target, prop);

      if (prop === 'models') {
        return new Proxy(value as object, {
          get(modelsTarget, modelsProp) {
            const modelsValue = Reflect.get(value as object, modelsProp);

            if (modelsProp === 'generateContent' || modelsProp === 'generateContentStream') {
              const isStreaming = modelsProp === 'generateContentStream';

              return async (params: GeminiGenerateContentParams): Promise<GeminiResponse> => {
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
                let contextProfile: ContextProfile | null = null;
                let responseJudgmentResult: ResponseJudgment | null = null;
                let effectiveParams = params;
                const isShadow = security?.mode === 'shadow';

                if (security) {
                  // 0. Model policy enforcement (first check)
                  if (security.modelPolicy) {
                    // Normalize Gemini params to the model-policy interface
                    const policyParams = {
                      model: params.model,
                      max_tokens: params.config?.maxOutputTokens,
                      temperature: params.config?.temperature,
                      system: params.config?.systemInstruction,
                    };
                    const violation = checkModelPolicy(policyParams, security.modelPolicy);
                    if (violation) {
                      emit?.('model.blocked', { violation });
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
                      maxTokens: params.config?.maxOutputTokens,
                      customerId,
                    });
                    if (costViolation && costGuard.shouldBlock) {
                      emit?.('cost.exceeded', { violation: costViolation });
                      security.costGuard?.onBudgetExceeded?.(costViolation);
                      if (!isShadow) throw new CostLimitError(costViolation);
                    }
                  }

                  // 3. PII detection + redaction
                  if (security.pii?.enabled !== false) {
                    const { allText } = extractGeminiMessageTexts(params);

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
                      emit?.('pii.detected', { detections: inputPiiDetections, direction: 'input' });
                      security.pii?.onDetect?.(inputPiiDetections);
                    }

                    const redactionStrategy = security.pii?.redaction ?? 'placeholder';
                    if (!isShadow && inputPiiDetections.length > 0 && redactionStrategy !== 'none') {
                      redactionApplied = true;
                      const contents = normalizeContents(params.contents);
                      const redactedContents = await Promise.all(contents.map((c) =>
                        redactGeminiContent(c, redactionStrategy, security.pii?.types, security.pii?.providers, redactionMapping),
                      ));

                      let redactedConfig = params.config;
                      if (params.config?.systemInstruction) {
                        if (typeof params.config.systemInstruction === 'string') {
                          const result = await redactPII(params.config.systemInstruction, {
                            strategy: redactionStrategy, types: security.pii?.types, providers: security.pii?.providers,
                          });
                          for (const [k, v] of result.mapping) redactionMapping.set(k, v);
                          redactedConfig = { ...params.config, systemInstruction: result.redactedText };
                        } else {
                          const redacted = await redactGeminiContent(
                            params.config.systemInstruction, redactionStrategy,
                            security.pii?.types, security.pii?.providers, redactionMapping,
                          );
                          redactedConfig = { ...params.config, systemInstruction: redacted };
                        }
                      }

                      effectiveParams = {
                        ...params,
                        contents: redactedContents,
                        ...(redactedConfig && { config: redactedConfig }),
                      };
                      emit?.('pii.redacted', { strategy: redactionStrategy, count: inputPiiDetections.length });
                    }
                  }

                  // Extract system prompt for injection awareness
                  const { systemText: geminiSystemPrompt } = extractGeminiMessageTexts(params);

                  // Context Engine (L3) — extract constraints from system prompt
                  if (security.contextEngine?.enabled !== false && security.contextEngine) {
                    const prompt = security.contextEngine.systemPrompt ?? geminiSystemPrompt;
                    if (prompt) {
                      const cacheOpts = { cache: security.contextEngine.cacheProfiles !== false };
                      if (security.contextEngine.providers?.length) {
                        contextProfile = await extractContextWithProviders(
                          prompt, security.contextEngine.providers, cacheOpts,
                        );
                      } else {
                        contextProfile = extractContext(prompt, cacheOpts);
                      }
                      emit?.('context.extracted', { profile: contextProfile });
                    }
                  }

                  // 4. Injection detection
                  if (security.injection?.enabled !== false) {
                    const { userText } = extractGeminiMessageTexts(params);
                    if (userText) {
                      injectionResult = detectInjection(userText, {
                        blockThreshold: security.injection?.blockThreshold,
                        systemPrompt: geminiSystemPrompt || undefined,
                      });
                      if (security.injection?.providers?.length) {
                        const cascade = security.injection.cascade ?? true;
                        const skipAbove = security.injection.cascadeThresholds?.skipAbove ?? 0.85;
                        const skipBelow = security.injection.cascadeThresholds?.skipBelow ?? 0.10;
                        const regexScore = injectionResult.riskScore;
                        const skipML = cascade && (regexScore >= skipAbove || regexScore <= skipBelow);

                        if (!skipML) {
                          const providerResults = await Promise.all(security.injection.providers.map(async (p) => {
                            try { return await Promise.resolve(p.detect(userText)); }
                            catch { return { riskScore: 0, triggered: [] as string[], action: 'allow' as const }; }
                          }));
                          injectionResult = mergeInjectionAnalyses(
                            [injectionResult, ...providerResults],
                            { blockThreshold: security.injection?.blockThreshold, mergeStrategy: security.injection?.mergeStrategy },
                          );
                        }
                      }
                      if (injectionResult.riskScore > 0) {
                        emit?.('injection.detected', { analysis: injectionResult });
                      }
                      security.injection?.onDetect?.(injectionResult);
                      if (!isShadow && security.injection?.blockOnHighRisk && injectionResult.action === 'block') {
                        emit?.('injection.blocked', { analysis: injectionResult });
                        throw new PromptInjectionError(injectionResult);
                      }
                    }
                  }

                  // 5. Content filter
                  if (security.contentFilter?.enabled !== false && security.contentFilter) {
                    const { allText } = extractGeminiMessageTexts(params);
                    inputContentViolations = detectContentViolations(allText, 'input', security.contentFilter);

                    // Run pluggable content filter providers (e.g., ML toxicity)
                    if (security.contentFilter.providers?.length) {
                      const providerResults = await Promise.all(
                        security.contentFilter.providers.map(async (p) => {
                          try {
                            return await Promise.resolve(p.detect(allText, 'input'));
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
                      emit?.('content.violated', { violations: inputContentViolations, direction: 'input' });
                    }
                    if (!isShadow && hasBlockingViolation(inputContentViolations, security.contentFilter)) {
                      security.contentFilter.onViolation?.(inputContentViolations[0]);
                      throw new ContentViolationError(inputContentViolations);
                    }
                    for (const v of inputContentViolations) {
                      security.contentFilter.onViolation?.(v);
                    }
                  }
                }

                // ── STREAMING ────────────────────────────────────
                if (isStreaming) {
                  const startMs = Date.now();
                  const streamResult = await (modelsValue as Function).call(value, effectiveParams);
                  const latencyMs = Date.now() - startMs;

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
                      extractText: extractGeminiStreamChunk,
                    });
                    const guarded = engine.wrap(streamResult as AsyncIterable<any>);
                    outputStream = guarded;
                    getStreamReport = () => guarded.getReport();
                  } else {
                    const contentParts: string[] = [];
                    let streamPiiDetections: PIIDetection[] = [];
                    const legacyStream = (async function* () {
                      for await (const chunk of streamResult as AsyncIterable<any>) {
                        const text = extractGeminiStreamChunk(chunk);
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

                    void (async () => {
                      try {
                        const report = getStreamReport();

                        const { systemText } = extractGeminiMessageTexts(params);
                        const contents = normalizeContents(params.contents);
                        const normalizedMsgs = contents.map((c) => ({
                          role: c.role === 'model' ? 'assistant' : (c.role ?? 'user'),
                          content: extractGeminiContentText(c),
                        }));
                        const fingerprint = fingerprintMessages(normalizedMsgs, systemText || undefined);

                        let customerId = alsCtx?.customerId;
                        let feature = alsCtx?.feature ?? featureTag;
                        if (!customerId && customerFn) {
                          const ctx = await customerFn();
                          customerId = ctx.id;
                          feature = ctx.feature ?? feature;
                        }

                        const event: IngestEventPayload = {
                          provider: 'gemini',
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
                          promptPreview: fingerprint.promptPreview,
                          responseText: report.responseText ?? undefined,
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
                          if (contextProfile) {
                            event.contextEngine = {
                              constraintCount: contextProfile.constraints.length,
                              role: contextProfile.role,
                              allowedTopicCount: contextProfile.allowedTopics.length,
                              restrictedTopicCount: contextProfile.restrictedTopics.length,
                              forbiddenActionCount: contextProfile.forbiddenActions.length,
                              groundingMode: contextProfile.groundingMode,
                            };
                          }
                          // Run response judge on streaming final text
                          if (security.responseJudge?.enabled !== false && security.responseJudge && report.responseText && contextProfile) {
                            const streamJudgment = judgeResponse(report.responseText, contextProfile, {
                              threshold: security.responseJudge.threshold,
                            });
                            if (streamJudgment.violated) {
                              emit?.('context.violation', { judgment: streamJudgment });
                              security.responseJudge.onViolation?.(streamJudgment);
                            }
                            event.responseJudge = {
                              violated: streamJudgment.violated,
                              complianceScore: streamJudgment.complianceScore,
                              violationCount: streamJudgment.violations.length,
                              violationTypes: [...new Set(streamJudgment.violations.map((v: import('../internal/response-judge').BoundaryViolation) => v.type))],
                              severity: streamJudgment.severity,
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
                const result = await (modelsValue as Function).call(value, effectiveParams) as GeminiResponse;
                const latencyMs = Date.now() - startMs;

                let responseForCaller: GeminiResponse = result;
                const responseText = extractGeminiResponseText(result);

                if (security) {

                  // Post-call: PII scan response
                  if (security.pii?.scanResponse && responseText) {
                    outputPiiDetections = detectPII(responseText, { types: security.pii?.types });
                  }

                  // Post-call: scan function call args for PII
                  const fnCalls = extractGeminiFunctionCalls(result);
                  if (security.pii?.enabled !== false && fnCalls.length > 0) {
                    const fnTexts = fnCalls
                      .map((p) => JSON.stringify(p.functionCall?.args ?? {}))
                      .join('\n');
                    const fnDetections = detectPII(fnTexts, { types: security.pii?.types });
                    outputPiiDetections.push(...fnDetections);
                  }

                  if (outputPiiDetections.length > 0) {
                    emit?.('pii.detected', { detections: outputPiiDetections, direction: 'output' });
                  }

                  // Post-call: content filter
                  if (security.contentFilter?.enabled !== false && security.contentFilter && responseText) {
                    outputContentViolations = detectContentViolations(responseText, 'output', security.contentFilter);

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
                      emit?.('content.violated', { violations: outputContentViolations, direction: 'output' });
                    }
                  }

                  // Post-call: response judge (L4)
                  if (security.responseJudge?.enabled !== false && security.responseJudge && responseText && contextProfile) {
                    responseJudgmentResult = judgeResponse(responseText, contextProfile, {
                      threshold: security.responseJudge.threshold,
                    });

                    if (security.responseJudge.providers?.length) {
                      const providerResults = await Promise.all(
                        security.responseJudge.providers.map(async (p) => {
                          try {
                            return await Promise.resolve(p.judge(responseText!, contextProfile!));
                          } catch {
                            return null;
                          }
                        }),
                      );
                      const validResults = providerResults.filter(Boolean) as ResponseJudgment[];
                      if (validResults.length > 0) {
                        responseJudgmentResult = mergeJudgments([responseJudgmentResult!, ...validResults]);
                      }
                    }

                    if (responseJudgmentResult!.violated) {
                      emit?.('context.violation', { judgment: responseJudgmentResult });
                      security.responseJudge.onViolation?.(responseJudgmentResult!);

                      if (!isShadow && security.responseJudge.blockOnViolation) {
                        emit?.('response.boundary_violation', { judgment: responseJudgmentResult });
                        throw new ResponseBoundaryError(responseJudgmentResult!);
                      }
                    }
                  }

                  // Post-call: output schema validation
                  if (security.outputSchema && responseText) {
                    const validation = validateOutputSchema(responseText, security.outputSchema);
                    if (!validation.valid) {
                      emit?.('schema.invalid', { errors: validation.errors, responseText });
                      if (!isShadow && security.outputSchema.blockOnInvalid) {
                        throw new OutputSchemaError(validation.errors, responseText);
                      }
                    }
                  }

                  // Post-call: de-redact
                  if (redactionMapping.size > 0 && responseText) {
                    const deRedactedText = deRedact(responseText, redactionMapping);
                    if (deRedactedText !== responseText && result.candidates?.[0]?.content?.parts) {
                      const newParts = result.candidates[0].content.parts.map((p: GeminiPart) => {
                        if (typeof p.text === 'string') {
                          return { ...p, text: deRedact(p.text, redactionMapping) };
                        }
                        return p;
                      });
                      responseForCaller = {
                        ...result,
                        candidates: [{
                          ...result.candidates[0],
                          content: { ...result.candidates[0].content, parts: newParts },
                        }],
                      };
                    }
                  }

                  // Post-call: cost guard update
                  if (costGuard && result.usageMetadata) {
                    const actualCost = calculateEventCost(
                      'gemini', params.model,
                      result.usageMetadata.promptTokenCount,
                      result.usageMetadata.candidatesTokenCount,
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
                    const usage = result.usageMetadata;
                    if (!usage) return;

                    const inputTokens = usage.promptTokenCount;
                    const outputTokens = usage.candidatesTokenCount;
                    const totalTokens = usage.totalTokenCount;
                    const costUsd = calculateEventCost('gemini', params.model, inputTokens, outputTokens);

                    const { systemText } = extractGeminiMessageTexts(params);
                    const contents = normalizeContents(params.contents);
                    const normalizedMsgs = contents.map((c) => ({
                      role: c.role === 'model' ? 'assistant' : (c.role ?? 'user'),
                      content: extractGeminiContentText(c),
                    }));
                    const fingerprint = fingerprintMessages(normalizedMsgs, systemText || undefined);

                    let customerId = alsCtx?.customerId;
                    let feature = alsCtx?.feature ?? featureTag;
                    if (!customerId && customerFn) {
                      const ctx = await customerFn();
                      customerId = ctx.id;
                      feature = ctx.feature ?? feature;
                    }

                    const event: IngestEventPayload = {
                      provider: 'gemini',
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
                      traceId: alsCtx?.traceId ?? traceIdTag,
                      spanName: alsCtx?.spanName ?? spanNameTag,
                      metadata: alsCtx?.metadata,
                    };

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
                          inputDetails: inputPiiDetections.map((d) => ({ type: d.type, start: d.start, end: d.end, confidence: d.confidence })),
                          outputDetails: outputPiiDetections.map((d) => ({ type: d.type, start: d.start, end: d.end, confidence: d.confidence })),
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

                      if (contextProfile) {
                        event.contextEngine = {
                          constraintCount: contextProfile.constraints.length,
                          role: contextProfile.role,
                          allowedTopicCount: contextProfile.allowedTopics.length,
                          restrictedTopicCount: contextProfile.restrictedTopics.length,
                          forbiddenActionCount: contextProfile.forbiddenActions.length,
                          groundingMode: contextProfile.groundingMode,
                        };
                      }
                      if (responseJudgmentResult) {
                        event.responseJudge = {
                          violated: responseJudgmentResult.violated,
                          complianceScore: responseJudgmentResult.complianceScore,
                          violationCount: responseJudgmentResult.violations.length,
                          violationTypes: [...new Set(responseJudgmentResult.violations.map((v) => v.type))],
                          severity: responseJudgmentResult.severity,
                        };
                      }
                    }

                    batcher.enqueue(event);
                  } catch { /* SDK must never throw */ }
                })();

                return responseForCaller;
              };
            }

            return typeof modelsValue === 'function'
              ? (modelsValue as Function).bind(value)
              : modelsValue;
          },
        });
      }

      return typeof value === 'function'
        ? (value as Function).bind(target)
        : value;
    },
  }) as T;
}
