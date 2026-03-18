/**
 * Response Judge — L4 boundary enforcement.
 * Takes an LLM response + ContextProfile from L3, checks if the response
 * violates extracted boundaries using heuristic matching.
 * @internal
 */

import type { Constraint, ContextProfile } from './context-engine';

// ── Types ────────────────────────────────────────────────────────────────────

export type BoundaryViolationType =
  | 'topic_violation'
  | 'role_deviation'
  | 'forbidden_action'
  | 'format_violation'
  | 'grounding_violation'
  | 'persona_break';

export interface BoundaryViolation {
  type: BoundaryViolationType;
  constraint: Constraint;
  confidence: number;
  evidence: string;
}

export interface ResponseJudgment {
  violated: boolean;
  complianceScore: number;
  violations: BoundaryViolation[];
  severity: 'low' | 'medium' | 'high';
}

export interface ResponseJudgeOptions {
  /** Compliance score threshold below which the response is considered violated. Default: 0.5 */
  threshold?: number;
}

/** Provider interface for pluggable response judges (e.g., NLI model). */
export interface ResponseJudgeProvider {
  judge(responseText: string, profile: ContextProfile): ResponseJudgment | Promise<ResponseJudgment>;
  readonly name: string;
}

/** User-facing security options for the response judge. */
export interface ResponseJudgeSecurityOptions {
  enabled?: boolean;
  /** Compliance score threshold (0-1). Default: 0.5 */
  threshold?: number;
  /** Block the response when a violation is detected. Default: false */
  blockOnViolation?: boolean;
  /** Pluggable ML judge providers (e.g., NLI). */
  providers?: ResponseJudgeProvider[];
  /** Called when a boundary violation is detected. */
  onViolation?: (judgment: ResponseJudgment) => void;
}

// ── Constants ────────────────────────────────────────────────────────────────

const TOKEN_SPLIT_RE = /[\s,.!?;:()\[\]{}"']+/;
const DEFAULT_THRESHOLD = 0.5;

/** Severity weights per violation type for scoring. */
const VIOLATION_WEIGHTS: Record<BoundaryViolationType, number> = {
  topic_violation: 0.25,
  role_deviation: 0.15,
  forbidden_action: 0.30,
  format_violation: 0.15,
  grounding_violation: 0.20,
  persona_break: 0.10,
};

// ── Meta-response patterns (reuse from prompt-leakage concept) ──────────────

const META_RESPONSE_PATTERNS: RegExp[] = [
  /my\s+instructions\s+are/i,
  /I\s+was\s+told\s+to/i,
  /my\s+system\s+prompt\s+is/i,
  /I(?:'m|'m| am)\s+programmed\s+to/i,
  /according\s+to\s+my\s+instructions/i,
  /my\s+initial\s+instructions\s+were/i,
  /my\s+rules\s+are/i,
  /my\s+guidelines\s+state/i,
];

/** Patterns indicating the LLM went beyond provided context. */
const HEDGING_PATTERNS: RegExp[] = [
  /(?:based\s+on\s+)?my\s+(?:general\s+)?knowledge/i,
  /(?:from\s+)?what\s+I\s+(?:generally\s+)?know/i,
  /(?:in\s+)?my\s+(?:general\s+)?understanding/i,
  /(?:I\s+)?(?:believe|think|recall)\s+(?:that\s+)?(?:generally|typically|usually)/i,
  /(?:outside\s+(?:of\s+)?)?(?:the\s+)?(?:provided|given)\s+(?:documents?|context|sources?|information)/i,
  /I\s+(?:don'?t|do\s+not)\s+(?:have|see)\s+(?:that|this)\s+(?:in|from)\s+(?:the\s+)?(?:provided|given)/i,
  /(?:while\s+)?(?:the\s+)?(?:provided|given)\s+(?:documents?|context|sources?)\s+(?:don'?t|do\s+not)/i,
  /(?:this\s+is\s+)?(?:not\s+)?(?:mentioned|covered|addressed|included)\s+in\s+(?:the\s+)?(?:provided|given)/i,
];

/** Tone-mismatch indicators for persona checks. */
const INFORMAL_INDICATORS = [
  'lol', 'lmao', 'omg', 'wtf', 'bruh', 'bro', 'nah', 'gonna', 'wanna',
  'gotta', 'ain\'t', 'dude', 'yo ', 'haha', 'hehe', 'tbh', 'imo', 'fwiw',
];

const FORMAL_INDICATORS = [
  'hereby', 'aforementioned', 'pursuant', 'whereas', 'therein', 'heretofore',
  'notwithstanding', 'shall be', 'deem', 'henceforth',
];

// ── Scoring helpers ──────────────────────────────────────────────────────────

/**
 * Score keyword overlap between response text and a set of keywords.
 * Returns a fraction of keywords found (0-1).
 */
function scoreKeywordOverlap(tokens: string[], lowerText: string, keywords: string[]): { matched: string[]; score: number } {
  const matched: string[] = [];
  let matchedCount = 0;

  for (const keyword of keywords) {
    const lowerKeyword = keyword.toLowerCase();

    if (lowerKeyword.includes(' ')) {
      // Multi-word phrase — substring match
      if (lowerText.includes(lowerKeyword)) {
        matched.push(keyword);
        matchedCount++;
      }
    } else {
      // Single-word — exact token match
      if (tokens.includes(lowerKeyword)) {
        matched.push(keyword);
        matchedCount++;
      }
    }
  }

  const score = keywords.length > 0 ? matchedCount / keywords.length : 0;
  return { matched, score };
}

/**
 * Extract a short evidence snippet from the response around a matched keyword.
 */
function extractEvidence(responseText: string, keyword: string, maxLen = 120): string {
  const lower = responseText.toLowerCase();
  const idx = lower.indexOf(keyword.toLowerCase());
  if (idx < 0) return responseText.slice(0, maxLen);

  const start = Math.max(0, idx - 30);
  const end = Math.min(responseText.length, idx + keyword.length + 30);
  let snippet = responseText.slice(start, end);
  if (start > 0) snippet = '...' + snippet;
  if (end < responseText.length) snippet += '...';
  return snippet;
}

// ── Check functions ──────────────────────────────────────────────────────────

function checkTopicViolations(
  tokens: string[],
  lowerText: string,
  profile: ContextProfile,
): BoundaryViolation[] {
  const violations: BoundaryViolation[] = [];

  // Check restricted topics — response mentions them
  for (const constraint of profile.constraints) {
    if (constraint.type !== 'topic_boundary') continue;
    if (!constraint.description.startsWith('Restricted')) continue;

    const { matched, score } = scoreKeywordOverlap(tokens, lowerText, constraint.keywords);
    if (matched.length > 0 && score >= 0.3) {
      violations.push({
        type: 'topic_violation',
        constraint,
        confidence: Math.min(score * 1.5, 1.0),
        evidence: extractEvidence(lowerText, matched[0]),
      });
    }
  }

  // Check allowed topics — response doesn't match any
  const allowedConstraints = profile.constraints.filter(
    (c) => c.type === 'topic_boundary' && c.description.startsWith('Allowed'),
  );
  if (allowedConstraints.length > 0) {
    let anyMatch = false;
    for (const constraint of allowedConstraints) {
      const { score } = scoreKeywordOverlap(tokens, lowerText, constraint.keywords);
      if (score >= 0.1) {
        anyMatch = true;
        break;
      }
    }
    if (!anyMatch && tokens.length >= 5) {
      // Response is off-topic — doesn't match any allowed topic
      violations.push({
        type: 'topic_violation',
        constraint: allowedConstraints[0],
        confidence: 0.7,
        evidence: lowerText.slice(0, 120),
      });
    }
  }

  return violations;
}

function checkForbiddenActions(
  lowerText: string,
  profile: ContextProfile,
): BoundaryViolation[] {
  const violations: BoundaryViolation[] = [];

  for (const constraint of profile.constraints) {
    if (constraint.type !== 'action_restriction') continue;

    // Check if keywords from the forbidden action appear in the response
    const keywords = constraint.keywords;
    let matchCount = 0;
    let firstMatch = '';

    for (const kw of keywords) {
      if (lowerText.includes(kw.toLowerCase())) {
        matchCount++;
        if (!firstMatch) firstMatch = kw;
      }
    }

    const overlapRatio = keywords.length > 0 ? matchCount / keywords.length : 0;

    // Also check meta-response patterns for "reveal system prompt" type actions
    let metaMatch = false;
    if (constraint.description.toLowerCase().includes('reveal') ||
        constraint.description.toLowerCase().includes('system prompt') ||
        constraint.description.toLowerCase().includes('instructions')) {
      metaMatch = META_RESPONSE_PATTERNS.some((p) => p.test(lowerText));
    }

    if (overlapRatio >= 0.5 || metaMatch) {
      violations.push({
        type: 'forbidden_action',
        constraint,
        confidence: metaMatch ? 0.9 : Math.min(overlapRatio * 1.2, 1.0),
        evidence: metaMatch
          ? extractEvidence(lowerText, firstMatch || constraint.keywords[0] || '')
          : extractEvidence(lowerText, firstMatch),
      });
    }
  }

  return violations;
}

function checkFormatCompliance(
  responseText: string,
  profile: ContextProfile,
): BoundaryViolation[] {
  if (!profile.outputFormat) return [];

  const formatConstraint = profile.constraints.find((c) => c.type === 'output_format');
  if (!formatConstraint) return [];

  const format = profile.outputFormat.toUpperCase();

  switch (format) {
    case 'JSON': {
      try {
        JSON.parse(responseText.trim());
        return []; // Valid JSON
      } catch {
        return [{
          type: 'format_violation',
          constraint: formatConstraint,
          confidence: 0.95,
          evidence: responseText.slice(0, 120),
        }];
      }
    }
    case 'XML': {
      // Basic XML check — must start with < and end with >
      const trimmed = responseText.trim();
      if (!trimmed.startsWith('<') || !trimmed.endsWith('>')) {
        return [{
          type: 'format_violation',
          constraint: formatConstraint,
          confidence: 0.8,
          evidence: trimmed.slice(0, 120),
        }];
      }
      return [];
    }
    case 'MARKDOWN': {
      // Check for markdown indicators (headers, lists, code blocks, etc.)
      const hasMarkdown = /(?:^#{1,6}\s|^\s*[-*+]\s|^\s*\d+\.\s|```|^\s*>\s|\*\*|__|!\[)/m.test(responseText);
      if (!hasMarkdown && responseText.length > 50) {
        return [{
          type: 'format_violation',
          constraint: formatConstraint,
          confidence: 0.5,
          evidence: responseText.slice(0, 120),
        }];
      }
      return [];
    }
    case 'YAML': {
      // Basic YAML check — should have key: value pattern
      const hasYaml = /^\s*\w[\w\s]*:\s*.+/m.test(responseText);
      if (!hasYaml) {
        return [{
          type: 'format_violation',
          constraint: formatConstraint,
          confidence: 0.7,
          evidence: responseText.slice(0, 120),
        }];
      }
      return [];
    }
    default:
      return [];
  }
}

function checkGroundingViolations(
  lowerText: string,
  profile: ContextProfile,
): BoundaryViolation[] {
  if (profile.groundingMode === 'any') return [];

  const kbConstraint = profile.constraints.find((c) => c.type === 'knowledge_boundary');
  if (!kbConstraint) return [];

  for (const pattern of HEDGING_PATTERNS) {
    if (pattern.test(lowerText)) {
      const match = lowerText.match(pattern);
      return [{
        type: 'grounding_violation',
        constraint: kbConstraint,
        confidence: 0.75,
        evidence: match ? extractEvidence(lowerText, match[0]) : lowerText.slice(0, 120),
      }];
    }
  }

  return [];
}

function checkPersonaBreaks(
  lowerText: string,
  profile: ContextProfile,
): BoundaryViolation[] {
  const violations: BoundaryViolation[] = [];

  const personaConstraints = profile.constraints.filter((c) => c.type === 'persona_rule');
  if (personaConstraints.length === 0) return [];

  for (const constraint of personaConstraints) {
    const trait = constraint.keywords[0]?.toLowerCase();
    if (!trait) continue;

    // Check if the response tone contradicts the required persona
    const isFormalRequired = ['professional', 'formal', 'objective', 'neutral'].includes(trait);
    const isFriendlyRequired = ['friendly', 'warm', 'enthusiastic', 'empathetic'].includes(trait);
    const isConciseRequired = ['concise', 'brief'].includes(trait);

    if (isFormalRequired) {
      // Check for informal language in a formal context
      for (const indicator of INFORMAL_INDICATORS) {
        if (lowerText.includes(indicator)) {
          violations.push({
            type: 'persona_break',
            constraint,
            confidence: 0.7,
            evidence: extractEvidence(lowerText, indicator),
          });
          break;
        }
      }
    }

    if (isFriendlyRequired) {
      // Check for overly formal/cold language in a friendly context
      let formalCount = 0;
      for (const indicator of FORMAL_INDICATORS) {
        if (lowerText.includes(indicator)) formalCount++;
      }
      if (formalCount >= 2) {
        violations.push({
          type: 'persona_break',
          constraint,
          confidence: 0.5,
          evidence: lowerText.slice(0, 120),
        });
      }
    }

    if (isConciseRequired) {
      // Check if response is excessively long (> 500 words)
      const wordCount = lowerText.split(/\s+/).length;
      if (wordCount > 500) {
        violations.push({
          type: 'persona_break',
          constraint,
          confidence: 0.6,
          evidence: `Response contains ${wordCount} words`,
        });
      }
    }
  }

  return violations;
}

function checkRoleDeviation(
  tokens: string[],
  lowerText: string,
  profile: ContextProfile,
): BoundaryViolation[] {
  if (!profile.role) return [];

  const violations: BoundaryViolation[] = [];
  const roleConstraint = profile.constraints.find((c) => c.type === 'role_constraint');
  if (!roleConstraint) return [];

  const roleKeywords = roleConstraint.keywords;

  // Check 1: Response claims a different identity
  const IDENTITY_PATTERNS: RegExp[] = [
    /i am (?:a|an|the)\s+(\w[\w\s]{2,30})/i,
    /as (?:a|an|the)\s+(\w[\w\s]{2,30})/i,
    /my role is\s+(\w[\w\s]{2,30})/i,
  ];

  for (const pattern of IDENTITY_PATTERNS) {
    const match = pattern.exec(lowerText);
    if (match && match[1]) {
      const claimedRole = match[1].trim().toLowerCase();
      const claimedTokens = claimedRole.split(/\s+/).filter((t) => t.length > 2);
      // Check if claimed role overlaps with actual role
      const hasOverlap = claimedTokens.some((t) => roleKeywords.includes(t));
      if (!hasOverlap && claimedTokens.length > 0) {
        violations.push({
          type: 'role_deviation',
          constraint: roleConstraint,
          confidence: 0.8,
          evidence: extractEvidence(lowerText, match[0]),
        });
        break; // One identity deviation is enough
      }
    }
  }

  // Check 2: Response explicitly breaks character (only for non-generic roles)
  const GENERIC_ROLES = ['assistant', 'helper', 'bot', 'chatbot', 'model', 'language model'];
  const isGenericRole = GENERIC_ROLES.some((g) => profile.role!.includes(g));

  if (!isGenericRole) {
    const BREAK_PATTERNS: RegExp[] = [
      /as an ai(?:\s+(?:language\s+)?model)?/i,
      /as a language model/i,
      /i(?:'m|'m| am) just an ai/i,
      /i don'?t actually have/i,
      /i(?:'m|'m| am) not really a/i,
    ];
    for (const pattern of BREAK_PATTERNS) {
      const match = pattern.exec(lowerText);
      if (match) {
        violations.push({
          type: 'role_deviation',
          constraint: roleConstraint,
          confidence: 0.75,
          evidence: extractEvidence(lowerText, match[0]),
        });
        break;
      }
    }
  }

  return violations;
}

// ── Scoring ──────────────────────────────────────────────────────────────────

function computeComplianceScore(violations: BoundaryViolation[], constraintCount: number): number {
  if (constraintCount === 0) return 1.0;
  if (violations.length === 0) return 1.0;

  let totalPenalty = 0;
  for (const v of violations) {
    totalPenalty += v.confidence * (VIOLATION_WEIGHTS[v.type] ?? 0.15);
  }

  return Math.max(0, Math.min(1.0, 1.0 - totalPenalty));
}

function computeSeverity(complianceScore: number): 'low' | 'medium' | 'high' {
  if (complianceScore >= 0.7) return 'low';
  if (complianceScore >= 0.4) return 'medium';
  return 'high';
}

// ── Merge ────────────────────────────────────────────────────────────────────

/**
 * Merge multiple ResponseJudgments (from heuristic + ML providers).
 * Uses the most conservative (lowest) compliance score and unions all violations.
 */
export function mergeJudgments(judgments: ResponseJudgment[]): ResponseJudgment {
  if (judgments.length === 0) {
    return { violated: false, complianceScore: 1.0, violations: [], severity: 'low' };
  }
  if (judgments.length === 1) return judgments[0];

  const allViolations = judgments.flatMap((j) => j.violations);
  const minScore = Math.min(...judgments.map((j) => j.complianceScore));
  const severity = computeSeverity(minScore);

  return {
    violated: allViolations.length > 0,
    complianceScore: minScore,
    violations: allViolations,
    severity,
  };
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Judge whether an LLM response violates the constraints extracted from the
 * system prompt by the Context Engine (L3).
 *
 * Checks:
 * - Topic violations (restricted topics mentioned, off-topic responses)
 * - Forbidden actions (response performs a prohibited action)
 * - Format compliance (JSON, XML, YAML, Markdown)
 * - Grounding violations (response goes beyond provided context)
 * - Persona breaks (tone contradicts required persona)
 */
export function judgeResponse(
  responseText: string,
  profile: ContextProfile,
  options?: ResponseJudgeOptions,
): ResponseJudgment {
  const threshold = options?.threshold ?? DEFAULT_THRESHOLD;

  if (!responseText || !profile || profile.constraints.length === 0) {
    return { violated: false, complianceScore: 1.0, violations: [], severity: 'low' };
  }

  const lowerText = responseText.toLowerCase();
  const tokens = lowerText.split(TOKEN_SPLIT_RE).filter((t) => t.length > 0);

  const violations: BoundaryViolation[] = [];

  // 1. Topic violations
  violations.push(...checkTopicViolations(tokens, lowerText, profile));

  // 2. Role deviation
  violations.push(...checkRoleDeviation(tokens, lowerText, profile));

  // 3. Forbidden actions
  violations.push(...checkForbiddenActions(lowerText, profile));

  // 4. Format compliance
  violations.push(...checkFormatCompliance(responseText, profile));

  // 5. Grounding violations
  violations.push(...checkGroundingViolations(lowerText, profile));

  // 6. Persona breaks
  violations.push(...checkPersonaBreaks(lowerText, profile));

  const complianceScore = computeComplianceScore(violations, profile.constraints.length);
  const severity = computeSeverity(complianceScore);
  const violated = violations.length > 0 && complianceScore < threshold;

  return { violated, complianceScore, violations, severity };
}
