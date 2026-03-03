/**
 * Streaming support — wraps async iterable responses with security scanning.
 * Buffers chunks, runs PII detection and injection analysis after stream ends.
 * @internal
 */

import { detectPII, mergeDetections, type PIIDetection, type PIIDetectOptions, type PIIDetectorProvider } from './pii';
import { detectInjection, type InjectionAnalysis } from './injection';
import type { StreamGuardOptions, StreamViolation } from '../types';

export interface StreamSecurityReport {
  piiDetections: PIIDetection[];
  injectionRisk?: InjectionAnalysis;
  responseText: string;
  /** Violations detected during mid-stream scanning. */
  streamViolations: StreamViolation[];
  /** Whether the stream was aborted due to a violation. */
  aborted: boolean;
  /** Approximate output tokens (chars/4). */
  approximateTokens: number;
  /** Character count of the response. */
  responseLength: number;
  /** Word count of the response. */
  responseWordCount: number;
}

export interface SecurityStreamOptions {
  pii?: {
    enabled?: boolean;
    types?: PIIDetectOptions['types'];
    providers?: PIIDetectorProvider[];
  };
  injection?: {
    enabled?: boolean;
    blockThreshold?: number;
  };
}

export interface SecurityStreamResult<T> {
  stream: AsyncIterable<T>;
  getReport: () => StreamSecurityReport;
}

/**
 * Wrap an async iterable (streaming response) with security scanning.
 *
 * Buffers all content chunks as they are yielded, then after the stream
 * completes, runs PII detection and injection analysis on the full
 * buffered content. Individual chunks are re-yielded unchanged since
 * we can only detect/report PII post-hoc in streaming mode.
 *
 * Usage:
 *   const { stream, getReport } = createSecurityStream(originalStream, options);
 *   for await (const chunk of stream) { ... }
 *   const report = getReport();
 */
export function createSecurityStream<T>(
  source: AsyncIterable<T>,
  options?: SecurityStreamOptions,
): SecurityStreamResult<T> {
  let report: StreamSecurityReport = {
    piiDetections: [],
    responseText: '',
    streamViolations: [],
    aborted: false,
    approximateTokens: 0,
    responseLength: 0,
    responseWordCount: 0,
  };
  let streamComplete = false;

  async function* wrappedStream(): AsyncGenerator<T> {
    const contentParts: string[] = [];

    for await (const chunk of source) {
      // Extract text content from the chunk
      // OpenAI streaming chunks have choices[0].delta.content
      const content = extractChunkContent(chunk);
      if (content) {
        contentParts.push(content);
      }
      yield chunk;
    }

    // Stream is complete — run security analysis on buffered content
    const fullText = contentParts.join('');
    report.responseText = fullText;

    if (fullText) {
      // PII detection
      if (options?.pii?.enabled !== false) {
        let piiDetections = detectPII(fullText, {
          types: options?.pii?.types,
        });

        if (options?.pii?.providers?.length) {
          const providerDets = options.pii.providers.map((p) => {
            try { return p.detect(fullText, { types: options?.pii?.types }); }
            catch { return []; }
          });
          piiDetections = mergeDetections(piiDetections, ...providerDets);
        }

        report.piiDetections = piiDetections;
      }

      // Injection detection
      if (options?.injection?.enabled !== false) {
        report.injectionRisk = detectInjection(fullText, {
          blockThreshold: options?.injection?.blockThreshold,
        });
      }
    }

    streamComplete = true;
  }

  return {
    stream: wrappedStream(),
    getReport(): StreamSecurityReport {
      if (!streamComplete) {
        // Return partial report if stream hasn't completed
        return {
          piiDetections: [],
          responseText: '',
          streamViolations: [],
          aborted: false,
          approximateTokens: 0,
          responseLength: 0,
          responseWordCount: 0,
        };
      }
      return report;
    },
  };
}

// ── StreamGuardEngine ────────────────────────────────────────────────
// Real-time streaming guard with rolling window buffer, periodic scanning,
// response length enforcement, and mid-stream abort.

export interface StreamGuardEngineConfig<T> {
  streamGuard: StreamGuardOptions;
  pii?: {
    types?: PIIDetectOptions['types'];
    providers?: PIIDetectorProvider[];
  };
  injection?: {
    blockThreshold?: number;
  };
  extractText: (chunk: T) => string | null;
}

/**
 * Core streaming guard engine. Wraps a provider's async iterable stream,
 * applies periodic PII + injection scanning on a rolling window, enforces
 * response length limits, and can abort mid-stream on violations.
 */
export class StreamGuardEngine<T> {
  private readonly scanInterval: number;
  private readonly windowOverlap: number;
  private readonly onViolation: 'abort' | 'warn' | 'flag';
  private readonly onStreamViolation?: (violation: StreamViolation) => void;
  private readonly doPiiScan: boolean;
  private readonly doInjectionScan: boolean;
  private readonly doFinalScan: boolean;
  private readonly trackTokens: boolean;
  private readonly maxResponseLength?: { maxChars?: number; maxWords?: number };
  private readonly piiConfig?: { types?: PIIDetectOptions['types']; providers?: PIIDetectorProvider[] };
  private readonly injectionConfig?: { blockThreshold?: number };
  private readonly extractText: (chunk: T) => string | null;

  // State
  private buffer = '';
  private windowStart = 0;
  private charsSinceLastScan = 0;
  private wordCount = 0;
  private aborted = false;
  private violations: StreamViolation[] = [];
  private report: StreamSecurityReport | null = null;

  constructor(config: StreamGuardEngineConfig<T>) {
    const sg = config.streamGuard;
    this.scanInterval = sg.scanInterval ?? 500;
    this.windowOverlap = sg.windowOverlap ?? 200;
    this.onViolation = sg.onViolation ?? 'flag';
    this.onStreamViolation = sg.onStreamViolation;
    this.doPiiScan = sg.piiScan !== false;
    this.doInjectionScan = sg.injectionScan !== false;
    this.doFinalScan = sg.finalScan !== false;
    this.trackTokens = sg.trackTokens !== false;
    this.maxResponseLength = sg.maxResponseLength;
    this.piiConfig = config.pii;
    this.injectionConfig = config.injection;
    this.extractText = config.extractText;
  }

  /** Wrap a source async iterable into a guarded stream. */
  wrap(source: AsyncIterable<T>): AsyncIterable<T> & { getReport: () => StreamSecurityReport } {
    const engine = this;
    const gen = async function* (): AsyncGenerator<T> {
      try {
        for await (const chunk of source) {
          if (engine.aborted) break;

          const text = engine.extractText(chunk);
          if (text) {
            engine.buffer += text;
            engine.charsSinceLastScan += text.length;
            engine.wordCount += countWords(text);

            engine._checkLengthLimit();

            if (!engine.aborted && engine.charsSinceLastScan >= engine.scanInterval) {
              engine._periodicScan();
            }
          }

          if (engine.aborted) break;
          yield chunk;
        }
      } catch (err) {
        // Provider error — build partial report
        engine._buildReport();
        throw err;
      }

      // Stream completed or aborted — run final scan
      if (engine.doFinalScan && !engine.aborted) {
        engine._finalScan();
      }
      engine._buildReport();
    };

    const stream = gen();
    return Object.assign(stream, {
      getReport: () => engine.getReport(),
    });
  }

  /** Get the security report (available after stream completes or aborts). */
  getReport(): StreamSecurityReport {
    if (!this.report) {
      this._buildReport();
    }
    return this.report!;
  }

  /** Get violations detected so far. */
  getViolations(): StreamViolation[] {
    return [...this.violations];
  }

  /** Get approximate token count so far. */
  getApproximateTokens(): number {
    return Math.ceil(this.buffer.length / 4);
  }

  /** Get the buffered response text so far. */
  getResponseText(): string {
    return this.buffer;
  }

  /** Whether the stream was aborted. */
  isAborted(): boolean {
    return this.aborted;
  }

  // ── Internal methods ──

  private _checkLengthLimit(): void {
    if (!this.maxResponseLength) return;

    const { maxChars, maxWords } = this.maxResponseLength;
    if (maxChars && this.buffer.length > maxChars) {
      this._handleViolation({
        type: 'length',
        offset: this.buffer.length,
        details: { current: this.buffer.length, limit: maxChars, unit: 'chars' },
        timestamp: Date.now(),
      });
    }
    if (maxWords && this.wordCount > maxWords) {
      this._handleViolation({
        type: 'length',
        offset: this.buffer.length,
        details: { current: this.wordCount, limit: maxWords, unit: 'words' },
        timestamp: Date.now(),
      });
    }
  }

  private _periodicScan(): void {
    this.charsSinceLastScan = 0;
    const scanText = this.buffer.slice(this.windowStart);

    // PII scan on window
    if (this.doPiiScan) {
      let detections = detectPII(scanText, { types: this.piiConfig?.types });

      if (this.piiConfig?.providers?.length) {
        const providerDets = this.piiConfig.providers.map((p) => {
          try { return p.detect(scanText, { types: this.piiConfig?.types }); }
          catch { return []; }
        });
        detections = mergeDetections(detections, ...providerDets);
      }

      if (detections.length > 0) {
        // Adjust offsets relative to full buffer
        const adjusted = detections.map((d) => ({
          ...d,
          start: d.start + this.windowStart,
          end: d.end + this.windowStart,
        }));
        this._handleViolation({
          type: 'pii',
          offset: adjusted[0].start,
          details: adjusted,
          timestamp: Date.now(),
        });
      }
    }

    // Injection scan on window
    if (this.doInjectionScan) {
      const analysis = detectInjection(scanText, {
        blockThreshold: this.injectionConfig?.blockThreshold,
      });
      if (analysis.action === 'warn' || analysis.action === 'block') {
        this._handleViolation({
          type: 'injection',
          offset: this.windowStart,
          details: analysis,
          timestamp: Date.now(),
        });
      }
    }

    // Slide window forward, keeping overlap
    if (this.buffer.length > this.windowOverlap) {
      this.windowStart = this.buffer.length - this.windowOverlap;
    }
  }

  private _finalScan(): void {
    const fullText = this.buffer;
    if (!fullText) return;

    // Full-text PII scan
    if (this.doPiiScan) {
      let detections = detectPII(fullText, { types: this.piiConfig?.types });
      if (this.piiConfig?.providers?.length) {
        const providerDets = this.piiConfig.providers.map((p) => {
          try { return p.detect(fullText, { types: this.piiConfig?.types }); }
          catch { return []; }
        });
        detections = mergeDetections(detections, ...providerDets);
      }
      if (detections.length > 0) {
        this._handleViolation({
          type: 'pii',
          offset: detections[0].start,
          details: detections,
          timestamp: Date.now(),
        });
      }
    }

    // Full-text injection scan
    if (this.doInjectionScan) {
      const analysis = detectInjection(fullText, {
        blockThreshold: this.injectionConfig?.blockThreshold,
      });
      if (analysis.action === 'warn' || analysis.action === 'block') {
        this._handleViolation({
          type: 'injection',
          offset: 0,
          details: analysis,
          timestamp: Date.now(),
        });
      }
    }
  }

  private _handleViolation(violation: StreamViolation): void {
    this.violations.push(violation);
    this.onStreamViolation?.(violation);

    if (this.onViolation === 'abort') {
      this.aborted = true;
    }
  }

  private _buildReport(): void {
    // Collect all PII detections from violations
    const allPiiDetections: PIIDetection[] = [];
    let injectionRisk: InjectionAnalysis | undefined;

    for (const v of this.violations) {
      if (v.type === 'pii' && Array.isArray(v.details)) {
        allPiiDetections.push(...(v.details as PIIDetection[]));
      }
      if (v.type === 'injection') {
        // Use the highest-risk injection analysis
        const analysis = v.details as InjectionAnalysis;
        if (!injectionRisk || analysis.riskScore > injectionRisk.riskScore) {
          injectionRisk = analysis;
        }
      }
    }

    this.report = {
      piiDetections: allPiiDetections,
      injectionRisk,
      responseText: this.buffer,
      streamViolations: [...this.violations],
      aborted: this.aborted,
      approximateTokens: this.trackTokens ? Math.ceil(this.buffer.length / 4) : 0,
      responseLength: this.buffer.length,
      responseWordCount: this.wordCount,
    };
  }
}

/** Count words in a text fragment. */
function countWords(text: string): number {
  const trimmed = text.trim();
  if (!trimmed) return 0;
  return trimmed.split(/\s+/).length;
}

/**
 * Extract text content from a streaming chunk.
 * Handles OpenAI-style streaming format: choices[0].delta.content
 * @internal
 */
export function extractChunkContent(chunk: any): string | null {
  // OpenAI format
  if (chunk?.choices?.[0]?.delta?.content) {
    return chunk.choices[0].delta.content;
  }
  // Plain string chunks
  if (typeof chunk === 'string') {
    return chunk;
  }
  return null;
}
