/**
 * Output safety scanning module -- detects dangerous executable content in LLM output.
 * Different from content filter (which catches hate/violence/toxic content).
 * This catches operationally dangerous patterns: destructive commands, SQL injection,
 * suspicious URLs, and dangerous code constructs.
 * @internal
 */

// ── Interfaces ──────────────────────────────────────────────────────────────

export type OutputSafetyCategory =
  | 'dangerous_commands'
  | 'sql_injection'
  | 'suspicious_urls'
  | 'dangerous_code';

export interface OutputSafetyOptions {
  /** Which categories to scan. Defaults to all four. */
  categories?: OutputSafetyCategory[];
}

export interface OutputSafetyThreat {
  category: OutputSafetyCategory;
  matched: string;
  severity: 'warn' | 'block';
  /** +-50 characters surrounding the match, clamped to text bounds. */
  context: string;
}

/** Maximum text length for output safety scanning to prevent DoS. */
const MAX_SCAN_LENGTH = 1_000_000; // 1 MB

// ── Category rules ──────────────────────────────────────────────────────────

interface CategoryRule {
  category: OutputSafetyCategory;
  patterns: RegExp[];
  severity: 'warn' | 'block';
}

const CATEGORIES: CategoryRule[] = [
  {
    category: 'dangerous_commands',
    severity: 'block',
    patterns: [
      /\brm\s+-rf\b/gi,
      /\bdel\s+\/f\s+\/s/gi,
      /\bformat\s+c:/gi,
      /\bDROP\s+TABLE\b/gi,
      /\bDELETE\s+FROM\b/gi,
      /\bTRUNCATE\s+TABLE\b/gi,
      /\bshutdown\s+-h\b/gi,
      /\bmkfs\./gi,
      /\bdd\s+if=\/dev\/zero/gi,
      /\bchmod\s+-R\s+777\s+\//gi,
    ],
  },
  {
    category: 'sql_injection',
    severity: 'warn',
    patterns: [
      /['"];\s*DROP\b/gi,
      /\bOR\s+1\s*=\s*1\b/gi,
      /\bUNION\s+SELECT\b/gi,
      /\bINTO\s+OUTFILE\b/gi,
      /\bLOAD_FILE\s*\(/gi,
      /\bxp_cmdshell\b/gi,
    ],
  },
  {
    category: 'suspicious_urls',
    severity: 'warn',
    patterns: [
      // IP-based URLs (not localhost / 127.0.0.1 / 0.0.0.0)
      /https?:\/\/(?!127\.0\.0\.1\b|0\.0\.0\.0\b|localhost\b)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
      /https?:\/\/[^\s]*\.onion\b/gi,
      /\bdata:[^;]+;base64,/gi,
      /\bjavascript:/gi,
    ],
  },
  {
    category: 'dangerous_code',
    severity: 'warn',
    patterns: [
      /\beval\s*\(/gi,
      /\bexec\s*\(/gi,
      /\bos\.system\s*\(/gi,
      /\bsubprocess\.call\s*\(/gi,
      /\b__import__\s*\(/gi,
      /\bchild_process\.exec\s*\(/gi,
      /\bnew\s+Function\s*\(/gi,
    ],
  },
];

// ── Detection ───────────────────────────────────────────────────────────────

/**
 * Extract context string: +-50 characters around the match, clamped to text bounds.
 */
function extractContext(
  text: string,
  matchStart: number,
  matchEnd: number,
): string {
  const ctxStart = Math.max(0, matchStart - 50);
  const ctxEnd = Math.min(text.length, matchEnd + 50);
  return text.slice(ctxStart, ctxEnd);
}

/**
 * Scan LLM output text for operationally dangerous content.
 * Returns all detected threats sorted by their position in the text.
 * Text longer than 1 MB is truncated before scanning.
 */
export function scanOutputSafety(
  text: string,
  options?: OutputSafetyOptions,
): OutputSafetyThreat[] {
  if (!text) return [];

  // Cap input length to prevent DoS
  const scanText =
    text.length > MAX_SCAN_LENGTH ? text.slice(0, MAX_SCAN_LENGTH) : text;

  const allowedCategories = options?.categories
    ? new Set(options.categories)
    : null;

  const threats: { threat: OutputSafetyThreat; position: number }[] = [];

  for (const rule of CATEGORIES) {
    if (allowedCategories && !allowedCategories.has(rule.category)) continue;

    for (const pattern of rule.patterns) {
      // Reset lastIndex for global patterns
      pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = pattern.exec(scanText)) !== null) {
        threats.push({
          threat: {
            category: rule.category,
            matched: match[0],
            severity: rule.severity,
            context: extractContext(
              scanText,
              match.index,
              match.index + match[0].length,
            ),
          },
          position: match.index,
        });

        // Non-global patterns should only match once
        if (!pattern.global) break;
      }
    }
  }

  // Sort by position in text
  threats.sort((a, b) => a.position - b.position);

  return threats.map((t) => t.threat);
}
