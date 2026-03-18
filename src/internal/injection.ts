/**
 * Prompt injection detection module.
 * Rule-based detection of common prompt injection patterns.
 * @internal
 */

export interface InjectionAnalysis {
  riskScore: number;
  triggered: string[];
  action: 'allow' | 'warn' | 'block';
}

export interface InjectionOptions {
  /** Threshold for 'warn' action (default: 0.3) */
  warnThreshold?: number;
  /** Threshold for 'block' action (default: 0.7) */
  blockThreshold?: number;
  /** System prompt text — used to suppress role_manipulation matches consistent with the system prompt. */
  systemPrompt?: string;
  /** Context profile from L3 — enables context-aware score adjustment. */
  contextProfile?: import('./context-engine').ContextProfile;
}

/** Provider interface for pluggable injection detectors (e.g., ML plugin). */
export interface InjectionDetectorProvider {
  detect(text: string, options?: InjectionOptions): InjectionAnalysis | Promise<InjectionAnalysis>;
  readonly name: string;
}

// ── Rule categories ─────────────────────────────────────────────────────────

interface InjectionRule {
  category: string;
  patterns: RegExp[];
  weight: number; // 0-1 contribution to risk score per match
}

const RULES: InjectionRule[] = [
  {
    category: 'instruction_override',
    patterns: [
      /ignore\s+(all\s+)?previous\s+instructions/i,
      /disregard\s+(all\s+)?(above|previous|prior)/i,
      /forget\s+(everything|all|your)\s+(above|rules|instructions|previous)/i,
      /override\s+(your|all|the)\s+(rules|instructions|guidelines)/i,
      /do\s+not\s+follow\s+(your|the|any)\s+(rules|instructions|guidelines)/i,
      /new\s+instructions?\s*:/i,
      /system\s*:\s*you\s+are/i,
    ],
    weight: 0.4,
  },
  {
    category: 'role_manipulation',
    patterns: [
      /you\s+are\s+now\s+(?:(?:a|an|the)\s+)?\w+/i,
      /(?:act|behave)\s+as\s+(?:if\s+)?(?:you\s+(?:are|were)\s+)?/i,
      /pretend\s+(?:you\s+are|to\s+be)/i,
      /(?:new|switch|change)\s+(?:your\s+)?(?:persona|personality|character|role)/i,
      /from\s+now\s+on\s+you\s+(?:are|will)/i,
      /jailbreak/i,
      /(?:DAN|STAN|DUDE|AIM|DEV)\s*(?:mode|prompt|enabled?|activated?)/i,
      /(?:enter|enable|activate|switch\s+to)\s+(?:\w+\s+)?(?:mode|persona)/i,
      /(?:write\s+a\s+(?:story|scene|chapter|script)\s+(?:where|in\s+which)|in\s+a\s+(?:fictional|hypothetical)\s+(?:world|scenario))\s+.{0,80}(?:explain|describe|demonstrate|show)\s+how/i,
    ],
    weight: 0.35,
  },
  {
    category: 'delimiter_injection',
    patterns: [
      /(?:^|\n)-{3,}\s*(?:system|assistant|user)\s*-{3,}/im,
      /(?:^|\n)#{2,}\s*(?:system|new\s+instructions?|override)/im,
      /<\/?(?:system|instruction|prompt|override|admin|root)>/i,
      /\[(?:SYSTEM|INST|ADMIN|ROOT)\]/i,
      /```(?:system|instruction|override)/i,
    ],
    weight: 0.3,
  },
  {
    category: 'data_exfiltration',
    patterns: [
      /(?:repeat|print|show|display|output|reveal|tell)\s+(?:me\s+)?(?:all\s+)?(?:the\s+)?(?:above|everything|your\s+(?:prompt|instructions|system\s+(?:message|prompt)))/i,
      /what\s+(?:are|were)\s+your\s+(?:original\s+)?(?:instructions|rules|system\s+(?:prompt|message))/i,
      /(?:copy|paste|dump)\s+(?:your\s+)?(?:system|initial)\s+(?:prompt|message|instructions)/i,
      /(?:beginning|start)\s+of\s+(?:your|the)\s+(?:conversation|prompt|context)/i,
    ],
    weight: 0.3,
  },
  {
    category: 'encoding_evasion',
    patterns: [
      // Base64 blocks — require 44+ chars (32 bytes encoded) to avoid catching UUIDs/short hashes
      /(?<![A-Za-z0-9_\-.])[A-Za-z0-9+/]{44,}={0,2}(?![A-Za-z0-9_\-.])/,
      // Excessive Unicode escape sequences
      /(?:\\u[0-9a-fA-F]{4}\s*){4,}/,
      // ROT13 instruction pattern
      /(?:rot13|decode|base64)\s*:\s*.{10,}/i,
      // Hex-encoded strings
      /(?:0x[0-9a-fA-F]{2}\s*){8,}/i,
      // Leetspeak common injection words
      /1gn0r3\s+pr3v10us/i,
    ],
    weight: 0.25,
  },
  {
    category: 'authorization_bypass',
    patterns: [
      /(?:give|grant|assign)\s+(?:me|user)\s+(?:admin|root|superuser|elevated)\s+(?:access|privileges?|rights?|role|permissions?)\b/i,
      /\b(?:bypass|skip|ignore|disable)\s+(?:auth(?:entication|orization)?|permissions?|access\s+control|RBAC|role\s+check)\b/i,
      /\b(?:escalate|elevate)\s+(?:my\s+)?(?:privileges?|permissions?|role|access)\b/i,
      /\b(?:access|view|show|display|read|get)\s+(?:me\s+)?(?:other\s+)?(?:user'?s?|another\s+user'?s?|someone\s+else'?s?)\s+(?:data|account|profile|info|records?)\b/i,
      /\b(?:act|operate|execute|run)\s+(?:\w+\s+)?(?:as|with)\s+(?:admin|root|superuser|administrator)\b/i,
      /\b(?:switch|change)\s+(?:to\s+)?(?:admin|root|superuser)\s+(?:mode|account|role)\b/i,
    ],
    weight: 0.35,
  },
];

// ── Suppressive context: benign phrases that look like injection patterns ────

const SUPPRESSIONS: Record<string, RegExp> = {
  // "you are now" — benign when followed by status/state words
  'role_manipulation:you_are_now':
    /you\s+are\s+now\s+(?:connected|logged\s+in|enrolled|registered|signed\s+up|subscribed|verified|approved|ready|eligible|qualified|redirected|transferred|being\s+transferred|on\s+(?:the|a)\s+(?:waitlist|list|call)|part\s+of|able\s+to|set\s+up|all\s+set|good\s+to\s+go|in\s+(?:the|a)\s+(?:queue|line|group|meeting|session))/i,

  // "act as" / "behave as" — benign in science/mechanical/business context
  'role_manipulation:act_as':
    /(?:acts?|behaves?|functions?|serves?|operates?|works?|acts)\s+as\s+(?:a\s+)?(?:catalyst|buffer|proxy|bridge|gateway|filter|intermediary|mediator|inhibitor|receptor|antenna|sensor|regulator|stabilizer|insulator|conductor|amplifier|deterrent|safeguard|backup|failover|fallback|barrier|layer|wrapper|adapter|interface|handler|router|balancer|coordinator|trigger|signal|marker|indicator|placeholder)/i,

  // "jailbreak" — benign in iOS/device/security-article context
  'role_manipulation:jailbreak':
    /(?:ios|iphone|ipad|ipod|android|device|phone|mobile|root(?:ing|ed)?|unlock(?:ing|ed)?|firmware|bootloader|tweak|cydia|sileo|checkra1n|unc0ver)\s+.{0,40}jailbreak|jailbreak\s+.{0,40}(?:ios|iphone|ipad|ipod|android|device|phone|mobile|detection|prevention|security|risk|policy|check|protect|block|patch|fix|vulnerabilit)/i,
};

/**
 * Check whether a match should be suppressed because the surrounding context
 * indicates benign usage (e.g., "you are now connected" is not role manipulation).
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

/** Check whether a base64-like match is actually a JWT, UUID, or hex hash. */
function isLikelyBenignEncoded(text: string, matchIndex: number): boolean {
  // Look for JWT context: dots separating base64url segments
  const before = text.slice(Math.max(0, matchIndex - 100), matchIndex);
  const after = text.slice(matchIndex, Math.min(text.length, matchIndex + 200));
  const around = before + after;
  // JWT pattern: three dot-separated base64url segments
  if (/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(around)) return true;
  return false;
}

// ── Unicode / homoglyph normalization ────────────────────────────────────────

const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0410': 'A', '\u0430': 'a', '\u0412': 'B', '\u0435': 'e',
  '\u041D': 'H', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0443': 'y', '\u0422': 'T', '\u0445': 'x', '\u041C': 'M',
  '\u043A': 'k', '\u0456': 'i',
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H',
  '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N',
  '\u039F': 'O', '\u03A1': 'P', '\u03A4': 'T', '\u03A5': 'Y',
  '\u03B1': 'a', '\u03BF': 'o', '\u03C1': 'p',
};

function normalizeText(text: string): string {
  let normalized = text.normalize('NFKC');
  for (const [glyph, ascii] of Object.entries(HOMOGLYPH_MAP)) {
    normalized = normalized.replaceAll(glyph, ascii);
  }
  return normalized;
}

// ── System prompt awareness ──────────────────────────────────────────────────

/**
 * Extract key role/behavior phrases from the system prompt.
 * Used to suppress role_manipulation matches that are consistent with the system prompt.
 */
export function extractSystemRoles(systemPrompt: string): string[] {
  if (!systemPrompt) return [];
  const roles: string[] = [];

  // "You are a/an [ROLE]"
  const youAreRe = /you\s+are\s+(?:a|an)\s+([^.,:;!?\n]{3,40})/gi;
  let m: RegExpExecArray | null;
  while ((m = youAreRe.exec(systemPrompt)) !== null) {
    roles.push(m[0].toLowerCase());
  }

  // "Act as a/an [ROLE]"
  const actAsRe = /act\s+as\s+(?:a|an)?\s*([^.,:;!?\n]{3,40})/gi;
  while ((m = actAsRe.exec(systemPrompt)) !== null) {
    roles.push(m[0].toLowerCase());
  }

  // "Your role is [ROLE]"
  const yourRoleRe = /your\s+role\s+is\s+(?:to\s+)?([^.,:;!?\n]{3,40})/gi;
  while ((m = yourRoleRe.exec(systemPrompt)) !== null) {
    roles.push(m[0].toLowerCase());
  }

  // "Behave as a [ROLE]"
  const behaveAsRe = /behave\s+as\s+(?:a|an)?\s*([^.,:;!?\n]{3,40})/gi;
  while ((m = behaveAsRe.exec(systemPrompt)) !== null) {
    roles.push(m[0].toLowerCase());
  }

  return roles;
}

/** Strip role-verb prefixes and articles, then trim at stop words to get the core noun phrase. */
function extractRoleNoun(text: string): string {
  let noun = text
    .replace(/^(?:you\s+are\s+(?:now\s+)?|act\s+as\s+|behave\s+as\s+|pretend\s+(?:you\s+are|to\s+be)\s+)/i, '')
    .replace(/^(?:a|an|the)\s+/i, '')
    .toLowerCase()
    .trim();
  // Trim at common stop words that follow the role noun
  noun = noun.replace(/\s+(?:and|who|that|which|when|where|for|to|in|on|with|helping|responding|answering)\b.*$/i, '');
  return noun.trim();
}

/**
 * Extract the full role phrase from the text around a match.
 * The regex match may only capture the prefix ("act as "), so we grab
 * additional words after the match to get the role noun.
 */
function extractFullRolePhrase(text: string, matchIndex: number, matchLength: number): string {
  const end = Math.min(text.length, matchIndex + matchLength + 60);
  const phrase = text.slice(matchIndex, end);
  const trimmed = phrase.match(/^[^.,:;!?\n]+/)?.[0] ?? phrase;
  return trimmed.trim();
}

/**
 * Check if a matched role phrase is consistent with one of the system prompt roles.
 * Compares extracted role nouns — if the user's role noun is found within a system role
 * (or vice versa), the match is considered consistent and should be suppressed.
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

// ── Context-aware adjustment ────────────────────────────────────────────

/** Directive phrases that indicate the user is trying to instruct the model. */
const DIRECTIVE_PATTERNS = [
  /\b(?:discuss|talk\s+about|tell\s+me\s+about|explain|help\s+(?:me\s+)?with|switch\s+to|let'?s\s+(?:talk|discuss|move\s+on\s+to))\b/i,
  /\b(?:ignore|forget|disregard|override|change|update)\s+(?:your|the|that|those)\b/i,
];

/**
 * Adjust injection score based on L3 context profile.
 *
 * - Suppress: If user mentions a role consistent with the system prompt role, reduce score.
 * - Boost: If user tries to discuss restricted topics in a directive context.
 * - Boost: If user tries to instruct actions that contradict forbidden actions.
 */
function adjustWithContext(
  score: number,
  triggered: string[],
  text: string,
  profile: import('./context-engine').ContextProfile,
): { score: number; triggered: string[] } {
  const lowerText = text.toLowerCase();
  let adjustedScore = score;
  const adjustedTriggered = [...triggered];

  // Suppress: role_manipulation when user mentions system prompt's own role
  if (triggered.includes('role_manipulation') && profile.role) {
    const roleWords = profile.role.toLowerCase().split(/\s+/).filter((w) => w.length > 2);
    const matchCount = roleWords.filter((w) => lowerText.includes(w)).length;
    if (roleWords.length > 0 && matchCount / roleWords.length >= 0.5) {
      // Likely benign — user is referencing the actual role
      adjustedScore = Math.max(0, adjustedScore - 0.3);
    }
  }

  // Boost: user tries to discuss restricted topics in a directive way
  const isDirective = DIRECTIVE_PATTERNS.some((p) => p.test(text));
  if (isDirective) {
    for (const topic of profile.restrictedTopics) {
      const topicWords = topic.split(/\s+/).filter((w) => w.length > 2);
      if (topicWords.length > 0 && topicWords.some((w) => lowerText.includes(w))) {
        adjustedScore = Math.min(1.0, adjustedScore + 0.15);
        if (!adjustedTriggered.includes('context_override')) {
          adjustedTriggered.push('context_override');
        }
        break;
      }
    }
  }

  // Boost: user tries to instruct the model to do a forbidden action
  for (const action of profile.forbiddenActions) {
    const actionWords = action.split(/\s+/).filter((w) => w.length > 2);
    if (actionWords.length === 0) continue;
    const matchCount = actionWords.filter((w) => lowerText.includes(w)).length;
    if (matchCount / actionWords.length >= 0.5 && isDirective) {
      adjustedScore = Math.min(1.0, adjustedScore + 0.2);
      if (!adjustedTriggered.includes('constraint_override')) {
        adjustedTriggered.push('constraint_override');
      }
      break;
    }
  }

  return { score: adjustedScore, triggered: adjustedTriggered };
}

// ── Detection ───────────────────────────────────────────────────────────────

/** Maximum text length for injection scanning to prevent DoS. */
const MAX_INJECTION_SCAN_LENGTH = 500_000; // 500KB

/**
 * Analyze text for prompt injection patterns.
 * Returns a risk score (0-1), triggered categories, and recommended action.
 * Text longer than 500KB is truncated before scanning.
 */
export function detectInjection(
  text: string,
  options?: InjectionOptions,
): InjectionAnalysis {
  if (!text) {
    return { riskScore: 0, triggered: [], action: 'allow' };
  }

  // Cap input length to prevent DoS
  const scanText = text.length > MAX_INJECTION_SCAN_LENGTH ? text.slice(0, MAX_INJECTION_SCAN_LENGTH) : text;
  const normalizedText = normalizeText(scanText);

  const warnThreshold = options?.warnThreshold ?? 0.3;
  const blockThreshold = options?.blockThreshold ?? 0.7;

  // Extract system roles for consistent-role suppression
  const systemRoles = options?.systemPrompt ? extractSystemRoles(options.systemPrompt) : [];

  const triggered: string[] = [];
  let totalScore = 0;

  for (const rule of RULES) {
    let ruleTriggered = false;
    let matchCount = 0;

    for (const pattern of rule.patterns) {
      // Reset lastIndex for global patterns
      if (pattern.global) pattern.lastIndex = 0;

      const match = pattern.exec(normalizedText);
      if (match) {
        // Check suppressive context before counting this match
        if (shouldSuppress(rule.category, normalizedText, match.index)) continue;
        // Check benign encoded content (JWTs, etc.) for encoding_evasion
        if (rule.category === 'encoding_evasion' && isLikelyBenignEncoded(normalizedText, match.index)) continue;
        // Check system prompt consistency for role_manipulation
        if (rule.category === 'role_manipulation' && systemRoles.length > 0 && isConsistentWithSystem(normalizedText, match.index, match[0].length, systemRoles)) continue;
        ruleTriggered = true;
        matchCount++;
      }
    }

    if (ruleTriggered) {
      triggered.push(rule.category);
      // Multiple matches within same category boost score slightly
      const categoryScore = Math.min(rule.weight * (1 + (matchCount - 1) * 0.15), rule.weight * 1.5);
      totalScore += categoryScore;
    }
  }

  // Cap at 1.0
  let riskScore = Math.min(totalScore, 1.0);

  // Apply context-aware adjustment if L3 profile is available
  if (options?.contextProfile) {
    const adjusted = adjustWithContext(riskScore, triggered, scanText, options.contextProfile);
    riskScore = adjusted.score;
    // Replace triggered with adjusted (may add context_override / constraint_override)
    triggered.length = 0;
    triggered.push(...adjusted.triggered);
  }

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

  return { riskScore: roundedScore, triggered, action };
}

export type MergeStrategy = 'max' | 'weighted_average' | 'unanimous';

/**
 * Merge multiple risk scores according to the selected strategy.
 */
function mergeScores(scores: number[], strategy: MergeStrategy): number {
  if (scores.length <= 1) return scores[0] ?? 0;

  switch (strategy) {
    case 'weighted_average': {
      // First provider (rules) gets 0.6 weight, each additional splits 0.4
      const ruleWeight = 0.6;
      const mlWeight = 0.4 / (scores.length - 1);
      return scores[0] * ruleWeight + scores.slice(1).reduce((s, v) => s + v * mlWeight, 0);
    }
    case 'unanimous':
      // All providers must agree — use minimum score
      return Math.min(...scores);
    default: // 'max'
      return Math.max(...scores);
  }
}

/**
 * Merge results from multiple injection detectors.
 * Uses the selected merge strategy (default: 'max') and unions all triggered categories.
 */
export function mergeInjectionAnalyses(
  analyses: InjectionAnalysis[],
  options?: InjectionOptions & { mergeStrategy?: MergeStrategy },
): InjectionAnalysis {
  if (analyses.length === 0) {
    return { riskScore: 0, triggered: [], action: 'allow' };
  }

  const warnThreshold = options?.warnThreshold ?? 0.3;
  const blockThreshold = options?.blockThreshold ?? 0.7;
  const strategy = options?.mergeStrategy ?? 'max';

  const scores = analyses.map((a) => a.riskScore);
  const mergedScore = Math.round(mergeScores(scores, strategy) * 100) / 100;
  const allTriggered = [...new Set(analyses.flatMap((a) => a.triggered))];

  let action: 'allow' | 'warn' | 'block';
  if (mergedScore >= blockThreshold) {
    action = 'block';
  } else if (mergedScore >= warnThreshold) {
    action = 'warn';
  } else {
    action = 'allow';
  }

  return { riskScore: mergedScore, triggered: allTriggered, action };
}

/**
 * Built-in rule-based injection detector implementing the provider interface.
 */
export class RuleInjectionDetector implements InjectionDetectorProvider {
  readonly name = 'rules';

  detect(text: string, options?: InjectionOptions): InjectionAnalysis {
    return detectInjection(text, options);
  }
}
