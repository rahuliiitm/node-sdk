/**
 * System prompt leakage detection module.
 * Output-side scanning to detect when an LLM response contains
 * fragments of the system prompt.
 * @internal
 */

/** Maximum text length for leakage scanning to prevent DoS. */
export const MAX_SCAN_LENGTH = 1024 * 1024; // 1MB

export interface PromptLeakageOptions {
  /** The system prompt to check for leakage against. */
  systemPrompt: string;
  /** N-gram overlap fraction threshold (0-1) to consider leaked (default: 0.4). */
  threshold?: number;
  /** Whether to signal that the response should be blocked on leak (default: false). */
  blockOnLeak?: boolean;
}

export interface PromptLeakageResult {
  /** Whether any form of leakage was detected. */
  leaked: boolean;
  /** 0-1 fraction of system prompt n-grams found in the output. */
  similarity: number;
  /** The n-gram phrases that appeared in both the system prompt and output. */
  matchedFragments: string[];
  /** Whether a meta-response pattern (e.g., "my instructions are") was detected. */
  metaResponseDetected: boolean;
}

// ── N-gram helpers ──────────────────────────────────────────────────────────

const NGRAM_SIZE = 4;

/**
 * Split text into sliding-window n-grams of `n` words.
 * Returns lowercase, trimmed n-gram strings.
 */
function buildNgrams(text: string, n: number): string[] {
  const words = text
    .toLowerCase()
    .replace(/[^\w\s]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 0);

  if (words.length < n) return [];

  const ngrams: string[] = [];
  for (let i = 0; i <= words.length - n; i++) {
    ngrams.push(words.slice(i, i + n).join(' '));
  }
  return ngrams;
}

// ── Meta-response patterns ──────────────────────────────────────────────────

const META_RESPONSE_PATTERNS: RegExp[] = [
  /my\s+instructions\s+are/i,
  /I\s+was\s+told\s+to/i,
  /my\s+system\s+prompt\s+is/i,
  /I(?:'m|'m| am)\s+programmed\s+to/i,
  /according\s+to\s+my\s+instructions/i,
  /my\s+initial\s+instructions\s+were/i,
  /I\s+cannot\s+reveal\s+my\s+instructions/i,
  /my\s+rules\s+are/i,
  /my\s+guidelines\s+state/i,
];

// ── Verbatim substring detection ────────────────────────────────────────────

const MIN_VERBATIM_LENGTH = 30;

/**
 * Find the length of the longest common substring between two strings.
 * Uses a sliding window approach bounded by MIN_VERBATIM_LENGTH to
 * keep runtime reasonable on large inputs.
 */
function longestCommonSubstringLength(a: string, b: string): number {
  if (a.length < MIN_VERBATIM_LENGTH || b.length < MIN_VERBATIM_LENGTH) return 0;

  let maxLen = 0;

  // Check substrings of the shorter string in the longer string
  const shorter = a.length <= b.length ? a : b;
  const longer = a.length <= b.length ? b : a;

  for (let i = 0; i <= shorter.length - MIN_VERBATIM_LENGTH; i++) {
    // Start with minimum length and extend while matching
    let end = i + MIN_VERBATIM_LENGTH;
    const candidate = shorter.slice(i, end);
    if (longer.includes(candidate)) {
      // Extend the match as far as possible
      while (end < shorter.length && longer.includes(shorter.slice(i, end + 1))) {
        end++;
      }
      const matchLen = end - i;
      if (matchLen > maxLen) maxLen = matchLen;
    }
  }

  return maxLen;
}

// ── Detection ───────────────────────────────────────────────────────────────

/**
 * Detect whether an LLM output contains fragments of the system prompt.
 *
 * Uses three complementary methods:
 * 1. N-gram overlap — fraction of system prompt 4-word n-grams found in output
 * 2. Meta-response patterns — regex matches for self-referential phrases
 * 3. Verbatim substring — longest common substring > 30 characters
 */
export function detectPromptLeakage(
  outputText: string,
  options: PromptLeakageOptions,
): PromptLeakageResult {
  const cleanResult: PromptLeakageResult = {
    leaked: false,
    similarity: 0,
    matchedFragments: [],
    metaResponseDetected: false,
  };

  if (!outputText || !options.systemPrompt) return cleanResult;

  const threshold = options.threshold ?? 0.4;

  // Cap input lengths to prevent DoS
  const scanOutput =
    outputText.length > MAX_SCAN_LENGTH ? outputText.slice(0, MAX_SCAN_LENGTH) : outputText;
  const scanPrompt =
    options.systemPrompt.length > MAX_SCAN_LENGTH
      ? options.systemPrompt.slice(0, MAX_SCAN_LENGTH)
      : options.systemPrompt;

  // ── 1. N-gram overlap ───────────────────────────────────────────────────
  const promptNgrams = buildNgrams(scanPrompt, NGRAM_SIZE);
  const matchedFragments: string[] = [];
  let similarity = 0;

  if (promptNgrams.length > 0) {
    const outputLower = scanOutput.toLowerCase();
    for (const ngram of promptNgrams) {
      if (outputLower.includes(ngram)) {
        matchedFragments.push(ngram);
      }
    }
    similarity = matchedFragments.length / promptNgrams.length;
    // Round to 4 decimal places for clean output
    similarity = Math.round(similarity * 10000) / 10000;
  }

  // ── 2. Meta-response patterns ───────────────────────────────────────────
  let metaResponseDetected = false;
  for (const pattern of META_RESPONSE_PATTERNS) {
    if (pattern.global) pattern.lastIndex = 0;
    if (pattern.test(scanOutput)) {
      metaResponseDetected = true;
      break;
    }
  }

  // ── 3. Verbatim substring ──────────────────────────────────────────────
  const verbatimLen = longestCommonSubstringLength(
    scanPrompt.toLowerCase(),
    scanOutput.toLowerCase(),
  );
  const hasVerbatimMatch = verbatimLen >= MIN_VERBATIM_LENGTH;

  // ── Final verdict ──────────────────────────────────────────────────────
  const leaked = similarity >= threshold || hasVerbatimMatch || metaResponseDetected;

  return {
    leaked,
    similarity,
    matchedFragments,
    metaResponseDetected,
  };
}
