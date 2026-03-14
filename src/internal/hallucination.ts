/**
 * Hallucination detection module — detects unfaithful LLM responses.
 *
 * Uses n-gram overlap heuristics as a rule-based baseline.
 * ML providers (e.g., vectara/HHEM cross-encoder) can be plugged in via the providers pattern.
 * @internal
 */

export interface HallucinationOptions {
  enabled?: boolean;
  /** Explicit reference text to compare the LLM response against. */
  sourceText?: string;
  /** Auto-extract source from system message if no explicit sourceText given. Default: true */
  extractFromSystemPrompt?: boolean;
  /** Faithfulness score threshold (0-1). Below this = hallucination detected. Default: 0.5 */
  threshold?: number;
  /** Block the response when hallucination is detected. Default: false */
  blockOnDetection?: boolean;
  onDetect?: (result: HallucinationResult) => void;
  /** Pluggable hallucination detection providers (e.g., ML cross-encoder). */
  providers?: HallucinationDetectorProvider[];
}

export interface HallucinationResult {
  /** Whether hallucination was detected (faithfulness below threshold). */
  hallucinated: boolean;
  /** Faithfulness score 0-1 from detection. */
  faithfulnessScore: number;
  /** Severity classification based on score. */
  severity: 'low' | 'medium' | 'high';
}

export interface HallucinationDetectorProvider {
  detect(generated: string, source: string): HallucinationResult | Promise<HallucinationResult>;
  readonly name: string;
}

/**
 * Compute n-gram overlap between generated text and source text.
 * Returns a score between 0 and 1 (1 = fully faithful).
 */
function ngramOverlap(generated: string, source: string, n: number): number {
  const normalize = (s: string) => s.toLowerCase().replace(/[^\w\s]/g, '').split(/\s+/).filter(Boolean);
  const genTokens = normalize(generated);
  const srcTokens = normalize(source);

  if (genTokens.length < n || srcTokens.length < n) {
    // Not enough tokens — if source is very short, we can't assess overlap meaningfully
    return genTokens.length === 0 ? 1.0 : 0.5;
  }

  const srcNgrams = new Set<string>();
  for (let i = 0; i <= srcTokens.length - n; i++) {
    srcNgrams.add(srcTokens.slice(i, i + n).join(' '));
  }

  let matches = 0;
  const genNgramCount = genTokens.length - n + 1;
  for (let i = 0; i <= genTokens.length - n; i++) {
    const ngram = genTokens.slice(i, i + n).join(' ');
    if (srcNgrams.has(ngram)) {
      matches++;
    }
  }

  return genNgramCount > 0 ? matches / genNgramCount : 0;
}

/**
 * Rule-based hallucination detection using multi-level n-gram overlap.
 *
 * Computes a blended faithfulness score from unigram, bigram, and trigram overlap.
 * This is a rough heuristic — ML providers (e.g., HHEM) are far more accurate.
 */
export function detectHallucination(
  generated: string,
  source: string,
  options?: { threshold?: number },
): HallucinationResult {
  const threshold = options?.threshold ?? 0.5;

  if (!generated || !source) {
    return { hallucinated: false, faithfulnessScore: 1.0, severity: 'low' };
  }

  // Blended n-gram overlap: unigram (40%), bigram (35%), trigram (25%)
  const uni = ngramOverlap(generated, source, 1);
  const bi = ngramOverlap(generated, source, 2);
  const tri = ngramOverlap(generated, source, 3);
  let score = uni * 0.4 + bi * 0.35 + tri * 0.25;

  // Round to 2 decimal places
  score = Math.round(score * 100) / 100;

  const hallucinated = score < threshold;

  let severity: 'low' | 'medium' | 'high';
  if (score >= 0.7) {
    severity = 'low';
  } else if (score >= 0.4) {
    severity = 'medium';
  } else {
    severity = 'high';
  }

  return { hallucinated, faithfulnessScore: score, severity };
}

/**
 * Merge multiple hallucination results. Uses the minimum faithfulness score (most conservative).
 */
export function mergeHallucinationResults(results: HallucinationResult[]): HallucinationResult {
  if (results.length === 0) {
    return { hallucinated: false, faithfulnessScore: 1.0, severity: 'low' };
  }

  // Use minimum faithfulness score (most conservative — catches most hallucinations)
  let minScore = 1.0;
  for (const r of results) {
    if (r.faithfulnessScore < minScore) {
      minScore = r.faithfulnessScore;
    }
  }

  let severity: 'low' | 'medium' | 'high';
  if (minScore >= 0.7) {
    severity = 'low';
  } else if (minScore >= 0.4) {
    severity = 'medium';
  } else {
    severity = 'high';
  }

  return {
    hallucinated: results.some((r) => r.hallucinated),
    faithfulnessScore: Math.round(minScore * 100) / 100,
    severity,
  };
}
