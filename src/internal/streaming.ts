/**
 * Streaming support — wraps async iterable responses with security scanning.
 * Buffers chunks, runs PII detection and injection analysis after stream ends.
 * @internal
 */

import { detectPII, mergeDetections, type PIIDetection, type PIIDetectOptions, type PIIDetectorProvider } from './pii';
import { detectInjection, type InjectionAnalysis } from './injection';

export interface StreamSecurityReport {
  piiDetections: PIIDetection[];
  injectionRisk?: InjectionAnalysis;
  responseText: string;
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
        return { piiDetections: [], responseText: '', };
      }
      return report;
    },
  };
}

/**
 * Extract text content from a streaming chunk.
 * Handles OpenAI-style streaming format: choices[0].delta.content
 * @internal
 */
function extractChunkContent(chunk: any): string | null {
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
