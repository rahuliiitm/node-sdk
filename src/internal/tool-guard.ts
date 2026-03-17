/**
 * Tool-use validation module -- guards which tools an agent can call,
 * validates argument safety, and scans tool results.
 * Zero dependencies. Stateless, pure functions.
 * @internal
 */

import { detectPII } from './pii';
import { detectInjection } from './injection';
import { detectSecrets } from './secret-detection';
import { validateSchema, type JsonSchema } from './schema-validator';

// ── Types ────────────────────────────────────────────────────────────────────

export interface ToolGuardOptions {
  enabled?: boolean;
  /** Only these tool names are allowed. Mutually exclusive with blockedTools. */
  allowedTools?: string[];
  /** These tool names are blocked. */
  blockedTools?: string[];
  /** Per-tool JSON schema for argument validation. Key = tool name. */
  parameterSchemas?: Record<string, JsonSchema>;
  /** Detect SQL injection, path traversal, shell injection, SSRF in args. Default: false. */
  dangerousArgDetection?: boolean;
  /** Regex patterns for inherently dangerous tools. */
  dangerousToolPatterns?: string[];
  /** Max tool calls allowed per single LLM response. */
  maxToolCallsPerTurn?: number;
  /** Scan tool result text for PII/injection/secrets. Default: false. */
  scanToolResults?: boolean;
  /** Action on violation. Default: 'block'. */
  action?: 'block' | 'warn' | 'flag';
  /** Callback on any violation. */
  onViolation?: (violation: ToolGuardViolation) => void;
}

export interface ToolGuardViolation {
  type:
    | 'blocked_tool'
    | 'unlisted_tool'
    | 'invalid_args'
    | 'dangerous_args'
    | 'dangerous_tool'
    | 'frequency_limit'
    | 'turn_limit'
    | 'tool_result_threat';
  toolName: string;
  details: string;
  /** Offending argument snippet (truncated to 200 chars). */
  argSnippet?: string;
}

export interface ToolGuardCheckResult {
  violations: ToolGuardViolation[];
  blocked: boolean;
}

export interface ToolCallInfo {
  name: string;
  arguments: string | Record<string, unknown>;
}

export interface ToolResultThreat {
  type: 'pii' | 'injection' | 'secret';
  piiType?: string;
  details: string;
}

export interface ToolResultScanReport {
  toolName: string;
  threats: ToolResultThreat[];
  clean: boolean;
}

// ── Built-in dangerous patterns ──────────────────────────────────────────────

const DEFAULT_DANGEROUS_TOOL_PATTERNS = [
  /^(file_write|write_file|create_file)/i,
  /^(exec|execute|run_command|shell|bash|cmd)/i,
  /^(http_request|fetch|curl|wget|network)/i,
  /^(delete|remove|drop|truncate)/i,
  /^(eval|code_interpreter|python_exec)/i,
  /^(send_email|send_message|post_to)/i,
];

interface DangerousArgCategory {
  category: string;
  patterns: RegExp[];
}

const DANGEROUS_ARG_CATEGORIES: DangerousArgCategory[] = [
  {
    category: 'sql_injection',
    patterns: [
      /\bUNION\s+SELECT\b/i,
      /\bDROP\s+TABLE\b/i,
      /;\s*DELETE\s+FROM\b/i,
      /\bOR\s+1\s*=\s*1\b/i,
      /\bOR\s+'[^']*'\s*=\s*'[^']*'/i,
      /--\s*$/m,
      /;\s*INSERT\s+INTO\b/i,
      /\bSELECT\s+.*\bFROM\s+.*\bWHERE\b.*\bOR\b/i,
    ],
  },
  {
    category: 'path_traversal',
    patterns: [
      /\.\.\//,
      /\.\.\\/,
      /%2e%2e/i,
      /%252e%252e/i,
    ],
  },
  {
    category: 'shell_injection',
    patterns: [
      /\$\([^)]+\)/,
      /`[^`]+`/,
      /;\s*(?:rm|cat|curl|wget|nc|bash|sh|chmod|chown)\b/i,
      /\|\s*(?:bash|sh|zsh)\b/i,
      /&&\s*(?:rm|curl|wget)\b/i,
    ],
  },
  {
    category: 'ssrf',
    patterns: [
      /169\.254\.169\.254/,
      /(?:https?:\/\/)?localhost(?::\d+)?/i,
      /(?:https?:\/\/)?127\.0\.0\.1(?::\d+)?/,
      /(?:https?:\/\/)?0\.0\.0\.0(?::\d+)?/,
      /(?:https?:\/\/)\[?::1\]?(?::\d+)?/,
      /(?:https?:\/\/)?10\.\d+\.\d+\.\d+/,
      /(?:https?:\/\/)?172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+/,
      /(?:https?:\/\/)?192\.168\.\d+\.\d+/,
    ],
  },
];

// ── Helpers ──────────────────────────────────────────────────────────────────

function truncate(s: string, maxLen = 200): string {
  return s.length > maxLen ? s.slice(0, maxLen) + '...' : s;
}

function stringifyArgs(args: string | Record<string, unknown>): string {
  if (typeof args === 'string') return args;
  try {
    return JSON.stringify(args);
  } catch {
    return String(args);
  }
}

function matchesPattern(name: string, pattern: string): boolean {
  // Wildcard support: "search_*" matches "search_web"
  if (pattern.includes('*')) {
    const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$', 'i');
    return regex.test(name);
  }
  return name.toLowerCase() === pattern.toLowerCase();
}

function isDangerousTool(
  name: string,
  customPatterns?: string[],
): { dangerous: boolean; pattern?: string } {
  // Check custom patterns first
  if (customPatterns) {
    for (const p of customPatterns) {
      if (matchesPattern(name, p)) {
        return { dangerous: true, pattern: p };
      }
    }
    // Custom patterns replace defaults entirely
    return { dangerous: false };
  }

  // Check built-in patterns
  for (const re of DEFAULT_DANGEROUS_TOOL_PATTERNS) {
    if (re.test(name)) {
      return { dangerous: true, pattern: re.source };
    }
  }
  return { dangerous: false };
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Validate tool calls against tool guard configuration.
 * Returns violations found. Pure function, no state.
 */
export function checkToolCalls(
  toolCalls: ToolCallInfo[],
  options: ToolGuardOptions,
  context?: { totalToolCallsSoFar?: number },
): ToolGuardCheckResult {
  const violations: ToolGuardViolation[] = [];

  // Turn limit check
  if (
    options.maxToolCallsPerTurn != null &&
    toolCalls.length > options.maxToolCallsPerTurn
  ) {
    violations.push({
      type: 'turn_limit',
      toolName: '*',
      details: `${toolCalls.length} tool calls exceed maxToolCallsPerTurn (${options.maxToolCallsPerTurn})`,
    });
  }

  for (const call of toolCalls) {
    const name = call.name;
    const argsStr = stringifyArgs(call.arguments);

    // Whitelist check (empty array = nothing allowed)
    if (options.allowedTools != null) {
      const allowed = options.allowedTools.some((p) => matchesPattern(name, p));
      if (!allowed) {
        violations.push({
          type: 'unlisted_tool',
          toolName: name,
          details: `Tool "${name}" is not in allowedTools`,
        });
        continue; // Skip further checks for blocked tool
      }
    }

    // Blacklist check
    if (options.blockedTools && options.blockedTools.length > 0) {
      const blocked = options.blockedTools.some((p) => matchesPattern(name, p));
      if (blocked) {
        violations.push({
          type: 'blocked_tool',
          toolName: name,
          details: `Tool "${name}" is in blockedTools`,
        });
        continue;
      }
    }

    // Dangerous tool pattern check
    const dangerousCheck = isDangerousTool(name, options.dangerousToolPatterns);
    if (dangerousCheck.dangerous) {
      violations.push({
        type: 'dangerous_tool',
        toolName: name,
        details: `Tool "${name}" matches dangerous pattern: ${dangerousCheck.pattern}`,
      });
    }

    // Parameter schema validation
    if (options.parameterSchemas && options.parameterSchemas[name]) {
      const schema = options.parameterSchemas[name];
      let argsObj: Record<string, unknown>;
      try {
        argsObj = typeof call.arguments === 'string'
          ? JSON.parse(call.arguments)
          : call.arguments;
      } catch {
        violations.push({
          type: 'invalid_args',
          toolName: name,
          details: `Malformed JSON arguments for tool "${name}"`,
          argSnippet: truncate(argsStr),
        });
        continue;
      }

      const errors = validateSchema(argsObj, schema);
      if (errors.length > 0) {
        violations.push({
          type: 'invalid_args',
          toolName: name,
          details: `Schema validation failed: ${errors.map((e) => e.message).join('; ')}`,
          argSnippet: truncate(argsStr),
        });
      }
    }

    // Dangerous arg detection
    if (options.dangerousArgDetection) {
      const dangerousArgs = detectDangerousArgs(argsStr);
      for (const d of dangerousArgs) {
        violations.push({
          type: 'dangerous_args',
          toolName: name,
          details: `Dangerous ${d.category} pattern in arguments`,
          argSnippet: truncate(d.matched),
        });
      }
    }
  }

  const action = options.action ?? 'block';
  return {
    violations,
    blocked: action === 'block' && violations.length > 0,
  };
}

/** Detect dangerous patterns in tool call argument text. */
export function detectDangerousArgs(
  args: string,
): Array<{ category: string; matched: string }> {
  const results: Array<{ category: string; matched: string }> = [];
  for (const cat of DANGEROUS_ARG_CATEGORIES) {
    for (const re of cat.patterns) {
      const match = re.exec(args);
      if (match) {
        results.push({ category: cat.category, matched: match[0] });
        break; // One match per category is enough
      }
    }
  }
  return results;
}

/**
 * Scan tool result text for PII, injection patterns, and secrets.
 * Re-uses existing detection modules.
 */
export function scanToolResult(
  toolName: string,
  resultText: string,
  options?: { injectionThreshold?: number },
): ToolResultScanReport {
  const threats: ToolResultThreat[] = [];

  // PII scan
  const piiDetections = detectPII(resultText);
  for (const d of piiDetections) {
    threats.push({
      type: 'pii',
      piiType: d.type,
      details: `${d.type} detected in result from "${toolName}"`,
    });
  }

  // Injection scan
  const injResult = detectInjection(resultText);
  const threshold = options?.injectionThreshold ?? 0.5;
  if (injResult.riskScore >= threshold) {
    threats.push({
      type: 'injection',
      details: `Injection risk ${injResult.riskScore.toFixed(2)} in result from "${toolName}" (${injResult.triggered.join(', ')})`,
    });
  }

  // Secret scan
  const secrets = detectSecrets(resultText);
  for (const s of secrets) {
    threats.push({
      type: 'secret',
      details: `${s.type} detected in result from "${toolName}"`,
    });
  }

  return {
    toolName,
    threats,
    clean: threats.length === 0,
  };
}
