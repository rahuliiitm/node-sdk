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

export interface ContentFilterOptions {
  enabled?: boolean;
  categories?: ContentCategory[];
  customPatterns?: CustomPattern[];
  blockOnViolation?: boolean;
  onViolation?: (violation: ContentViolation) => void;
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
    ],
    severity: 'block',
  },
  {
    category: 'violence',
    patterns: [
      /\b(?:how\s+to\s+)?(?:make|build|create)\s+(?:a\s+)?(?:bomb|explosive|weapon)\b/i,
      /\b(?:how\s+to\s+)?(?:poison|assassinate|murder)\s+(?:someone|a\s+person)\b/i,
      /\bmass\s+(?:shooting|murder|violence)\b/i,
    ],
    severity: 'block',
  },
  {
    category: 'self_harm',
    patterns: [
      /\b(?:how\s+to\s+)?(?:commit|method(?:s)?\s+(?:of|for))\s+suicide\b/i,
      /\bways\s+to\s+(?:end\s+(?:my|your)\s+life|kill\s+(?:myself|yourself))\b/i,
    ],
    severity: 'block',
  },
  {
    category: 'illegal',
    patterns: [
      /\b(?:how\s+to\s+)?(?:hack|breach|exploit)\s+(?:into\s+)?(?:a\s+)?(?:bank|government|corporate)\s+(?:system|network|database)\b/i,
      /\b(?:how\s+to\s+)?(?:launder|counterfeit)\s+money\b/i,
      /\b(?:how\s+to\s+)?(?:cook|manufacture|synthesize)\s+(?:meth|drugs|fentanyl)\b/i,
    ],
    severity: 'block',
  },
];

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

  return violations;
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
