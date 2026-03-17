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
  | 'dangerous_code'
  | 'excessive_agency'
  | 'overreliance';

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
  {
    category: 'excessive_agency',
    severity: 'warn',
    patterns: [
      // LLM claims to have taken autonomous actions
      /\bI'?(?:ve|have)\s+(?:already\s+)?(?:sent|emailed|messaged|posted|published|submitted|forwarded)\b/gi,
      /\bI'?(?:ve|have)\s+(?:already\s+)?(?:deleted|removed|erased|purged|wiped|dropped)\b/gi,
      /\bI'?(?:ve|have)\s+(?:already\s+)?(?:scheduled|booked|reserved|ordered|purchased|bought|transferred|paid)\b/gi,
      /\bI'?(?:ve|have)\s+(?:already\s+)?(?:executed|deployed|installed|configured|modified|changed|updated)\s+(?:the|your|a)\b/gi,
      /\bI\s+(?:went\s+ahead\s+and|took\s+the\s+liberty\s+(?:of|to))\b/gi,
      // Tool calls without user confirmation
      /\bI'?(?:ll|will)\s+(?:go\s+ahead\s+and\s+)?(?:send|delete|execute|deploy|purchase|transfer|pay)\b/gi,
    ],
  },
  {
    category: 'overreliance',
    severity: 'warn',
    patterns: [
      // Definitive medical/legal/financial advice without caveats
      /\byou\s+(?:should|must|need\s+to)\s+(?:definitely|absolutely|certainly)\s+(?:take|stop\s+taking|increase|decrease)\s+(?:your\s+)?(?:medication|medicine|dosage|prescription|pills?)\b/gi,
      /\byou\s+(?:should|must|need\s+to)\s+(?:definitely|absolutely|certainly)\s+(?:sue|file\s+(?:a\s+)?(?:lawsuit|complaint|charges?)|settle|plead)\b/gi,
      /\byou\s+(?:should|must|need\s+to)\s+(?:definitely|absolutely|certainly)\s+(?:invest|buy|sell|short|hold)\s+(?:(?:in|all)\s+)?(?:stocks?|crypto|bitcoin|shares?|bonds?)\b/gi,
      // Overconfident guarantees
      /\bI\s+(?:guarantee|promise|assure\s+you)\s+(?:that\s+)?(?:this|it)\s+will\s+(?:definitely|certainly|absolutely)\b/gi,
      /\bthis\s+(?:will\s+)?(?:definitely|certainly|absolutely|100%|guaranteed)\s+(?:work|cure|fix|solve|heal)\b/gi,
      // Presenting uncertain info as fact
      /\bI(?:\s+am|'m)\s+(?:100%|absolutely|completely)\s+(?:certain|sure|confident)\s+that\b/gi,
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
