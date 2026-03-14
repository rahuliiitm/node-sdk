/**
 * Content filtering module — detects harmful, toxic, or policy-violating content.
 * @internal
 */

export type ContentCategory =
  | 'hate_speech'
  | 'sexual'
  | 'violence'
  | 'self_harm'
  | 'illegal';

/** Safe domains — when domain context detected, downgrade 'block' to 'warn'. */
export type SafeDomain = 'medical' | 'educational' | 'security_research' | 'news' | 'historical' | 'fiction';

export interface ContentFilterOptions {
  enabled?: boolean;
  categories?: ContentCategory[];
  customPatterns?: CustomPattern[];
  blockOnViolation?: boolean;
  onViolation?: (violation: ContentViolation) => void;
  /** Safe domains — when domain context is detected near a match, downgrade 'block' to 'warn'. */
  safeDomains?: SafeDomain[];
  /** Pluggable content filter providers (e.g., ML toxicity). */
  providers?: ContentFilterProvider[];
}

export interface CustomPattern {
  name: string;
  pattern: RegExp;
  severity: 'warn' | 'block';
}

export interface ContentViolation {
  category: string;
  matched: string;
  severity: 'warn' | 'block';
  location: 'input' | 'output';
}

/** Provider interface for pluggable content detectors (e.g., ML toxicity). */
export interface ContentFilterProvider {
  detect(text: string, location: 'input' | 'output'): ContentViolation[] | Promise<ContentViolation[]>;
  readonly name: string;
}

// ── Built-in keyword patterns (curated, focused on high-precision) ──────────

interface CategoryRule {
  category: ContentCategory;
  patterns: RegExp[];
  severity: 'warn' | 'block';
}

const CATEGORY_RULES: CategoryRule[] = [
  {
    category: 'hate_speech',
    patterns: [
      /\b(?:kill|exterminate|eliminate)\s+all\s+\w+/i,
      /\b(?:racial|ethnic)\s+(?:cleansing|supremacy|genocide)\b/i,
      /\bgenocide\b/i,
      /\bhate\s+(?:crime|group)\b/i,
      /\b(?:attack|destroy|wipe\s+out|bomb|nuke|annihilate)\s+(?:\w+\s+){0,3}(?:and\s+(?:its|their)\s+)?(?:people|civilians|citizens|population)\b/i,
    ],
    severity: 'block',
  },
  {
    category: 'sexual',
    patterns: [
      /\b(?:child|minor|underage)\s+(?:sexual|explicit|nude|naked|porn)\b/i,
      /\b(?:CSAM|child\s+pornography|child\s+exploitation)\b/i,
      /\b(?:generate|create|write|produce)\s+(?:sexual|explicit|erotic|nude)\s+(?:content|image|video|story)\s+(?:of|about|involving)\s+(?:a\s+)?(?:child|minor|kid|teen)\b/i,
    ],
    severity: 'block',
  },
  {
    category: 'violence',
    patterns: [
      /\b(?:how\s+to\s+)?(?:make|build|create)\s+(?:a\s+)?(?:bomb|explosive|weapon)\b/i,
      /\b(?:how\s+to\s+)?(?:poison|assassinate|murder)\s+(?:someone|a\s+person|people)\b/i,
      /\bmass\s+(?:shooting|murder|violence)\b/i,
      /\b(?:how\s+to\s+)?(?:stab|shoot|strangle|behead|torture)\s+(?:someone|a\s+person|people)\b/i,
      /\b(?:how\s+to\s+)?(?:synthesize|produce|make|create)\s+(?:chlorine|sarin|ricin|anthrax|mustard|nerve)\s+(?:gas|agent|toxin|poison)?\b/i,
      /\b(?:pipe\s+bomb|IED|improvised\s+explosive|car\s+bomb|suicide\s+vest|dirty\s+bomb)\b/i,
    ],
    severity: 'block',
  },
  {
    category: 'self_harm',
    patterns: [
      /\b(?:how\s+to\s+)?(?:commit|method(?:s)?\s+(?:of|for))\s+suicide\b/i,
      /\b(?:want|need|going)\s+to\s+(?:end|take)\s+(?:my|this|his|her|their)\s+life\b/i,
      /\bways\s+to\s+(?:end\s+(?:my|your)\s+life|kill\s+(?:myself|yourself))\b/i,
      /\b(?:how\s+to\s+)?(?:overdose|OD)\s+on\s+\w+/i,
      /\bwhat\s+(?:pills?|dose|amount|medication)\s+(?:(?:would|will|to|can)\s+)?(?:kill|harm|hurt)\s+(?:me|myself|someone)\b/i,
      /\b(?:best|easy|painless)\s+(?:way|method)s?\s+to\s+(?:die|end\s+(?:it|my\s+life)|kill\s+myself)\b/i,
      /\b(?:don'?t|do\s+not)\s+want\s+to\s+(?:live|be\s+alive|exist)\b/i,
      /\b(?:kill|harm|hurt)\s+(?:myself|themselves|himself|herself)\b/i,
      /\b(?:self[-\s]?harm|self[-\s]?injur|cutting)\s+(?:method|how|tips|guide|tutorial)\b/i,
    ],
    severity: 'block',
  },
  {
    category: 'illegal',
    patterns: [
      /\b(?:how\s+to\s+)?(?:hack|breach|exploit)\s+(?:into\s+)?(?:a\s+)?(?:bank|government|corporate)\s+(?:system|network|database|account)\b/i,
      /\b(?:how\s+to\s+)?(?:launder|counterfeit)\s+money\b/i,
      /\b(?:how\s+to\s+)?(?:cook|manufacture|synthesize)\s+(?:meth|drugs|fentanyl)\b/i,
      /\b(?:write|create|generate|build|make)\s+(?:a\s+)?(?:phishing|spear[\s-]?phishing|scam|fraud)\s+(?:email|message|page|site|campaign)\b/i,
      /\b(?:write|create|build|make|develop)\s+(?:a\s+)?(?:malware|ransomware|keylogger|trojan|spyware|virus|rootkit|worm|botnet)\b/i,
      /\b(?:how\s+to\s+)?(?:doxx?|stalk)\s+(?:someone|a\s+person)\b/i,
      /\b(?:how\s+to\s+)?(?:smuggle|traffic)\s+(?:drugs|people|weapons|guns|arms)\b/i,
    ],
    severity: 'block',
  },
];

// ── Safe-domain context keywords ─────────────────────────────────────────────

const DOMAIN_KEYWORDS: Record<SafeDomain, RegExp> = {
  medical: /\b(?:patient|clinical|diagnosis|symptom|treatment|therapy|medical|hospital|doctor|nurse|physician|prescription|dosage|healthcare|prevention|intervention|counseling|hotline|crisis\s+line|mental\s+health|disorder|syndrome)\b/i,

  educational: /\b(?:lesson|curriculum|course|student|teacher|professor|lecture|study|research|academic|textbook|exam|assignment|university|school|classroom|syllabus|thesis|dissertation)\b/i,

  security_research: /\b(?:vulnerability|CVE|penetration\s+test|pentest|security\s+audit|threat\s+model|red\s+team|blue\s+team|CTF|capture\s+the\s+flag|OWASP|security\s+research|bug\s+bounty|responsible\s+disclosure|patch|mitigation|defense|detection|prevention|firewall|IDS|antivirus)\b/i,

  news: /\b(?:reported|according\s+to|news|journalist|article|press|media|coverage|investigation|headline|breaking|sources?\s+(?:say|said|report)|alleged|incident|authorities)\b/i,

  historical: /\b(?:historical|century|era|ancient|medieval|war\s+of|battle\s+of|history\s+of|in\s+\d{3,4}|historians?|archaeological|civilization|dynasty|empire|colonial|revolution)\b/i,

  fiction: /\b(?:novel|fiction|story|character|protagonist|antagonist|plot|chapter|narrative|fantasy|sci-fi|screenplay|movie|film|book|author|wrote|writing\s+a)\b/i,
};

/**
 * Apply safe-domain context to violations.
 * If a blocking violation is near domain context keywords, downgrade to 'warn'.
 * IMPORTANT: 'sexual' category (CSAM-related) is NEVER downgraded.
 */
function applyDomainContext(
  violations: ContentViolation[],
  text: string,
  safeDomains?: SafeDomain[],
): ContentViolation[] {
  if (!safeDomains || safeDomains.length === 0) return violations;

  return violations.map(v => {
    if (v.severity !== 'block') return v;
    // Never downgrade CSAM patterns
    if (v.category === 'sexual') return v;

    const matchIdx = text.indexOf(v.matched);
    if (matchIdx === -1) return v;
    const contextStart = Math.max(0, matchIdx - 200);
    const contextEnd = Math.min(text.length, matchIdx + v.matched.length + 200);
    const context = text.slice(contextStart, contextEnd);

    for (const domain of safeDomains) {
      if (DOMAIN_KEYWORDS[domain]?.test(context)) {
        return { ...v, severity: 'warn' as const };
      }
    }
    return v;
  });
}

// ── Detection ───────────────────────────────────────────────────────────────

/**
 * Scan text for content policy violations.
 */
export function detectContentViolations(
  text: string,
  location: 'input' | 'output',
  options?: ContentFilterOptions,
): ContentViolation[] {
  if (!text || options?.enabled === false) return [];

  const violations: ContentViolation[] = [];
  const allowedCategories = options?.categories
    ? new Set(options.categories)
    : null;

  // Check built-in category rules
  for (const rule of CATEGORY_RULES) {
    if (allowedCategories && !allowedCategories.has(rule.category)) continue;

    for (const pattern of rule.patterns) {
      if (pattern.global) pattern.lastIndex = 0;
      const match = pattern.exec(text);
      if (match) {
        violations.push({
          category: rule.category,
          matched: match[0],
          severity: rule.severity,
          location,
        });
        break; // One match per category is enough
      }
    }
  }

  // Check custom patterns
  if (options?.customPatterns) {
    for (const custom of options.customPatterns) {
      if (custom.pattern.global) custom.pattern.lastIndex = 0;
      const match = custom.pattern.exec(text);
      if (match) {
        violations.push({
          category: custom.name,
          matched: match[0],
          severity: custom.severity,
          location,
        });
      }
    }
  }

  // Apply safe-domain context (downgrades 'block' → 'warn' when domain context found)
  return applyDomainContext(violations, text, options?.safeDomains);
}

/**
 * Check if any violations are blocking (severity = 'block' and blockOnViolation is true).
 */
export function hasBlockingViolation(
  violations: ContentViolation[],
  options?: ContentFilterOptions,
): boolean {
  if (!options?.blockOnViolation) return false;
  return violations.some((v) => v.severity === 'block');
}

/**
 * Built-in rule-based content filter implementing the provider interface.
 */
export class RuleContentFilter implements ContentFilterProvider {
  readonly name = 'rules';
  private readonly options?: ContentFilterOptions;

  constructor(options?: ContentFilterOptions) {
    this.options = options;
  }

  detect(text: string, location: 'input' | 'output'): ContentViolation[] {
    return detectContentViolations(text, location, this.options);
  }
}
