/**
 * Jailbreak detection module.
 * Rule-based detection of common jailbreak patterns including known templates,
 * hypothetical framing, persona assignment, payload encoding, and few-shot manipulation.
 * @internal
 */

export interface JailbreakAnalysis {
  riskScore: number;
  triggered: string[];
  action: 'allow' | 'warn' | 'block';
  decodedPayloads?: string[];
}

export interface JailbreakOptions {
  /** Threshold for 'warn' action (default: 0.3) */
  warnThreshold?: number;
  /** Threshold for 'block' action (default: 0.7) */
  blockThreshold?: number;
  /** System prompt text — used to suppress persona_assignment matches consistent with the system prompt. */
  systemPrompt?: string;
}

/** Provider interface for pluggable jailbreak detectors (e.g., ML plugin). */
export interface JailbreakDetectorProvider {
  detect(text: string, options?: JailbreakOptions): JailbreakAnalysis | Promise<JailbreakAnalysis>;
  readonly name: string;
}

// ── Rule categories ─────────────────────────────────────────────────────────

interface JailbreakRule {
  category: string;
  patterns: RegExp[];
  weight: number; // 0-1 contribution to risk score per match
}

const KNOWN_TEMPLATE_PATTERNS: RegExp[] = [
  /\bDAN\b/i,
  /\bSTAN\b/i,
  /\bDUDE\b/i,
  /\bAIM\b/i,
  /Developer\s+Mode/i,
  /Evil\s+Confidant/i,
  /BetterDAN/i,
  // Require "Maximum" to be followed by a jailbreak-related word to avoid FP on "maximum capacity"
  /\bMaximum\b\s+(?:mode|override|power|token|capability|freedom|unrestricted)/i,
  /Do\s+Anything\s+Now/i,
  /Superior\s+AI/i,
  /developer\s+mode\s+enabled/i,
  /act\s+as\s+an\s+unrestricted\s+AI/i,
  /you\s+have\s+been\s+freed/i,
  /unleashed\s+mode/i,
];

const HYPOTHETICAL_FRAMING_PATTERNS: RegExp[] = [
  /in\s+a\s+fictional\s+world/i,
  /for\s+educational\s+purposes\s+only/i,
  /hypothetically\s+speaking/i,
  /imagine\s+you\s+have\s+no\s+restrictions/i,
  /in\s+this\s+alternate\s+universe/i,
  /purely\s+theoretical/i,
  /let[''\u2019]?s\s+play\s+a\s+game\s+where/i,
];

const PERSONA_ASSIGNMENT_PATTERNS: RegExp[] = [
  /you\s+are\s+now/i,
  /pretend\s+to\s+be/i,
  /roleplay\s+as/i,
  /act\s+as\s+a\s+character\s+who\s+has\s+no\s+limitations/i,
  /you\s+are\s+no\s+longer\s+bound\s+by/i,
  /from\s+now\s+on\s+you\s+will/i,
  /switch\s+to\s+.*\s+mode/i,
];

const PAYLOAD_ENCODING_PATTERNS: RegExp[] = [
  // Base64 blocks (64+ chars of base64 alphabet)
  /[A-Za-z0-9+/=]{64,}/,
  // ROT13 / hex decode instructions
  /decode\s+this\s+rot13/i,
  /decode\s+the\s+following\s+hex/i,
];

const FEW_SHOT_MANIPULATION_PATTERNS: RegExp[] = [
  /here[''\u2019]?s\s+an\s+example\s+of\s+how\s+you\s+should\s+respond\s*:/i,
  /\[Example\]\s*Assistant\s*:/i,
  /sample\s+response\s*:/i,
  /for\s+instance\s+you\s+could\s+say/i,
];

const RULES: JailbreakRule[] = [
  {
    category: 'known_templates',
    patterns: KNOWN_TEMPLATE_PATTERNS,
    weight: 0.5,
  },
  {
    category: 'hypothetical_framing',
    patterns: HYPOTHETICAL_FRAMING_PATTERNS,
    weight: 0.3,
  },
  {
    category: 'persona_assignment',
    patterns: PERSONA_ASSIGNMENT_PATTERNS,
    weight: 0.35,
  },
  {
    category: 'payload_encoding',
    patterns: PAYLOAD_ENCODING_PATTERNS,
    weight: 0.4,
  },
  {
    category: 'few_shot_manipulation',
    patterns: FEW_SHOT_MANIPULATION_PATTERNS,
    weight: 0.3,
  },
];

// ── Suppressive context: benign phrases that look like jailbreak patterns ────

const SUPPRESSIONS: Record<string, RegExp> = {
  // "you are now" — benign when followed by status/state words
  'persona_assignment:you_are_now':
    /you\s+are\s+now\s+(?:connected|logged\s+in|enrolled|registered|signed\s+up|subscribed|verified|approved|ready|eligible|qualified|redirected|transferred|being\s+transferred|on\s+(?:the|a)\s+(?:waitlist|list|call)|part\s+of|able\s+to|set\s+up|all\s+set|good\s+to\s+go|in\s+(?:the|a)\s+(?:queue|line|group|meeting|session))/i,
};

/**
 * Check whether a match should be suppressed because the surrounding context
 * indicates benign usage (e.g., "you are now connected" is not persona assignment).
 */
function shouldSuppress(category: string, text: string, matchIndex: number): boolean {
  const start = Math.max(0, matchIndex - 40);
  const end = Math.min(text.length, matchIndex + 120);
  const context = text.slice(start, end);

  for (const [key, suppressRe] of Object.entries(SUPPRESSIONS)) {
    if (key.startsWith(category + ':') && suppressRe.test(context)) {
      return true;
    }
  }
  return false;
}

// ── System prompt awareness (re-use extraction from injection module) ────────

import { extractSystemRoles } from './injection';

/** Strip role-verb prefixes and articles, then trim at stop words to get the core noun phrase. */
function extractRoleNoun(text: string): string {
  let noun = text
    .replace(/^(?:you\s+are\s+(?:now\s+)?|act\s+as\s+|behave\s+as\s+|pretend\s+(?:you\s+are|to\s+be)\s+|roleplay\s+as\s+)/i, '')
    .replace(/^(?:a|an|the)\s+/i, '')
    .toLowerCase()
    .trim();
  noun = noun.replace(/\s+(?:and|who|that|which|when|where|for|to|in|on|with|helping|responding|answering)\b.*$/i, '');
  return noun.trim();
}

/**
 * Extract the full role phrase from the text around a match.
 */
function extractFullRolePhrase(text: string, matchIndex: number, matchLength: number): string {
  const end = Math.min(text.length, matchIndex + matchLength + 60);
  const phrase = text.slice(matchIndex, end);
  const trimmed = phrase.match(/^[^.,:;!?\n]+/)?.[0] ?? phrase;
  return trimmed.trim();
}

/**
 * Check if a matched persona phrase is consistent with one of the system prompt roles.
 */
function isConsistentWithSystem(text: string, matchIndex: number, matchLength: number, systemRoles: string[]): boolean {
  if (systemRoles.length === 0) return false;
  const fullPhrase = extractFullRolePhrase(text, matchIndex, matchLength);
  const matchNoun = extractRoleNoun(fullPhrase);
  if (!matchNoun || matchNoun.length < 3) return false;

  for (const role of systemRoles) {
    const roleNoun = extractRoleNoun(role);
    if (!roleNoun) continue;
    if (roleNoun.includes(matchNoun) || matchNoun.includes(roleNoun)) return true;
  }
  return false;
}

// ── Base64 payload decoding ─────────────────────────────────────────────────

const BASE64_EXTRACT_REGEX = /[A-Za-z0-9+/=]{64,}/g;

/**
 * Extract and decode base64 payloads from text.
 * Returns decoded strings that are valid UTF-8.
 */
function decodeBase64Payloads(text: string): string[] {
  const decoded: string[] = [];
  const matches = text.match(BASE64_EXTRACT_REGEX);
  if (!matches) return decoded;

  for (const match of matches) {
    try {
      const result = Buffer.from(match, 'base64').toString('utf-8');
      // Only include if the decoded content looks like readable text
      // (has a reasonable ratio of printable characters)
      const printable = result.replace(/[^\x20-\x7E]/g, '');
      if (printable.length > result.length * 0.5) {
        decoded.push(result);
      }
    } catch {
      // Ignore invalid base64
    }
  }
  return decoded;
}

/**
 * Scan decoded text against categories 1-3 (known_templates, hypothetical_framing, persona_assignment).
 * Returns matching category names.
 */
function scanDecodedContent(decoded: string): string[] {
  const matched: string[] = [];
  const scanRules: { category: string; patterns: RegExp[] }[] = [
    { category: 'known_templates', patterns: KNOWN_TEMPLATE_PATTERNS },
    { category: 'hypothetical_framing', patterns: HYPOTHETICAL_FRAMING_PATTERNS },
    { category: 'persona_assignment', patterns: PERSONA_ASSIGNMENT_PATTERNS },
  ];

  for (const rule of scanRules) {
    for (const pattern of rule.patterns) {
      if (pattern.global) pattern.lastIndex = 0;
      if (pattern.test(decoded)) {
        matched.push(rule.category);
        break;
      }
    }
  }
  return matched;
}

// ── Detection ───────────────────────────────────────────────────────────────

/** Maximum text length for jailbreak scanning to prevent DoS. */
const MAX_SCAN_LENGTH = 500 * 1024; // 500KB

/**
 * Analyze text for jailbreak patterns.
 * Returns a risk score (0-1), triggered categories, recommended action,
 * and any decoded payloads found.
 * Text longer than 500KB is truncated before scanning.
 */
export function detectJailbreak(
  text: string,
  options?: JailbreakOptions,
): JailbreakAnalysis {
  if (!text) {
    return { riskScore: 0, triggered: [], action: 'allow' };
  }

  // Cap input length to prevent DoS
  const scanText = text.length > MAX_SCAN_LENGTH ? text.slice(0, MAX_SCAN_LENGTH) : text;

  const warnThreshold = options?.warnThreshold ?? 0.3;
  const blockThreshold = options?.blockThreshold ?? 0.7;

  // Extract system roles for consistent-role suppression
  const systemRoles = options?.systemPrompt ? extractSystemRoles(options.systemPrompt) : [];

  const triggered: string[] = [];
  let totalScore = 0;
  const decodedPayloads: string[] = [];

  // Track per-category match counts (used for decoded payload boosts)
  const categoryMatchCounts: Record<string, number> = {};

  // First pass: scan direct text against all rules
  for (const rule of RULES) {
    let ruleTriggered = false;
    let matchCount = 0;

    for (const pattern of rule.patterns) {
      if (pattern.global) pattern.lastIndex = 0;
      const match = pattern.exec(scanText);
      if (match) {
        // Check suppressive context before counting this match
        if (shouldSuppress(rule.category, scanText, match.index)) continue;
        // Check system prompt consistency for persona_assignment
        if (rule.category === 'persona_assignment' && systemRoles.length > 0 && isConsistentWithSystem(scanText, match.index, match[0].length, systemRoles)) continue;
        ruleTriggered = true;
        matchCount++;
      }
    }

    if (ruleTriggered) {
      if (!triggered.includes(rule.category)) {
        triggered.push(rule.category);
      }
      categoryMatchCounts[rule.category] = matchCount;
    }
  }

  // Second pass: decode base64 payloads and re-scan decoded content
  const decoded = decodeBase64Payloads(scanText);
  if (decoded.length > 0) {
    decodedPayloads.push(...decoded);

    for (const decodedText of decoded) {
      const matchedCategories = scanDecodedContent(decodedText);
      for (const cat of matchedCategories) {
        if (!triggered.includes(cat)) {
          triggered.push(cat);
          categoryMatchCounts[cat] = 1;
        } else {
          categoryMatchCounts[cat] = (categoryMatchCounts[cat] || 0) + 1;
        }
      }
      // If decoded content matched something, also ensure payload_encoding is triggered
      if (matchedCategories.length > 0 && !triggered.includes('payload_encoding')) {
        triggered.push('payload_encoding');
        categoryMatchCounts['payload_encoding'] = 1;
      }
    }
  }

  // Calculate score from all triggered categories
  for (const rule of RULES) {
    const matchCount = categoryMatchCounts[rule.category];
    if (matchCount && matchCount > 0) {
      const categoryScore = Math.min(rule.weight * (1 + (matchCount - 1) * 0.15), rule.weight * 1.5);
      totalScore += categoryScore;
    }
  }

  // Cap at 1.0
  const riskScore = Math.min(totalScore, 1.0);

  // Round to 2 decimal places for clean output
  const roundedScore = Math.round(riskScore * 100) / 100;

  let action: 'allow' | 'warn' | 'block';
  if (roundedScore >= blockThreshold) {
    action = 'block';
  } else if (roundedScore >= warnThreshold) {
    action = 'warn';
  } else {
    action = 'allow';
  }

  const result: JailbreakAnalysis = { riskScore: roundedScore, triggered, action };
  if (decodedPayloads.length > 0) {
    result.decodedPayloads = decodedPayloads;
  }

  return result;
}

export type MergeStrategy = 'max' | 'weighted_average' | 'unanimous';

/**
 * Merge multiple risk scores according to the selected strategy.
 */
function mergeScores(scores: number[], strategy: MergeStrategy): number {
  if (scores.length <= 1) return scores[0] ?? 0;

  switch (strategy) {
    case 'weighted_average': {
      const ruleWeight = 0.6;
      const mlWeight = 0.4 / (scores.length - 1);
      return scores[0] * ruleWeight + scores.slice(1).reduce((s, v) => s + v * mlWeight, 0);
    }
    case 'unanimous':
      return Math.min(...scores);
    default:
      return Math.max(...scores);
  }
}

/**
 * Merge results from multiple jailbreak detectors.
 * Uses the selected merge strategy (default: 'max') and unions all triggered categories.
 */
export function mergeJailbreakAnalyses(
  analyses: JailbreakAnalysis[],
  options?: JailbreakOptions & { mergeStrategy?: MergeStrategy },
): JailbreakAnalysis {
  if (analyses.length === 0) {
    return { riskScore: 0, triggered: [], action: 'allow' };
  }

  const warnThreshold = options?.warnThreshold ?? 0.3;
  const blockThreshold = options?.blockThreshold ?? 0.7;
  const strategy = options?.mergeStrategy ?? 'max';

  const scores = analyses.map((a) => a.riskScore);
  const mergedScore = Math.round(mergeScores(scores, strategy) * 100) / 100;
  const allTriggered = [...new Set(analyses.flatMap((a) => a.triggered))];
  const allDecoded = analyses
    .flatMap((a) => a.decodedPayloads ?? [])
    .filter((v, i, arr) => arr.indexOf(v) === i);

  let action: 'allow' | 'warn' | 'block';
  if (mergedScore >= blockThreshold) {
    action = 'block';
  } else if (mergedScore >= warnThreshold) {
    action = 'warn';
  } else {
    action = 'allow';
  }

  const result: JailbreakAnalysis = { riskScore: mergedScore, triggered: allTriggered, action };
  if (allDecoded.length > 0) {
    result.decodedPayloads = allDecoded;
  }

  return result;
}

/**
 * Built-in rule-based jailbreak detector implementing the provider interface.
 */
export class RuleJailbreakDetector implements JailbreakDetectorProvider {
  readonly name = 'rules';

  detect(text: string, options?: JailbreakOptions): JailbreakAnalysis {
    return detectJailbreak(text, options);
  }
}
