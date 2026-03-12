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
      // Base64 blocks (32+ chars of base64 alphabet)
      /[A-Za-z0-9+/=]{32,}/,
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
];

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

  const triggered: string[] = [];
  let totalScore = 0;

  for (const rule of RULES) {
    let ruleTriggered = false;
    let matchCount = 0;

    for (const pattern of rule.patterns) {
      // Reset lastIndex for global patterns
      if (pattern.global) pattern.lastIndex = 0;

      if (pattern.test(normalizedText)) {
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

  return { riskScore: roundedScore, triggered, action };
}

/**
 * Merge results from multiple injection detectors.
 * Takes the maximum risk score and unions all triggered categories.
 */
export function mergeInjectionAnalyses(
  analyses: InjectionAnalysis[],
  options?: InjectionOptions,
): InjectionAnalysis {
  if (analyses.length === 0) {
    return { riskScore: 0, triggered: [], action: 'allow' };
  }

  const warnThreshold = options?.warnThreshold ?? 0.3;
  const blockThreshold = options?.blockThreshold ?? 0.7;

  const maxScore = Math.max(...analyses.map((a) => a.riskScore));
  const allTriggered = [...new Set(analyses.flatMap((a) => a.triggered))];

  let action: 'allow' | 'warn' | 'block';
  if (maxScore >= blockThreshold) {
    action = 'block';
  } else if (maxScore >= warnThreshold) {
    action = 'warn';
  } else {
    action = 'allow';
  }

  return { riskScore: maxScore, triggered: allTriggered, action };
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
