/**
 * Chain-of-thought auditing module -- scans reasoning/thinking blocks
 * for injection, system prompt leakage, and goal drift.
 * Zero dependencies. Stateless, pure functions.
 * @internal
 *
 * TODO: Full implementation in Phase 2.
 */

import { detectInjection } from './injection';
import { detectPromptLeakage } from './prompt-leakage';

// ── Types ────────────────────────────────────────────────────────────────────

export interface ChainOfThoughtGuardOptions {
  enabled?: boolean;
  /** Scan reasoning blocks for injection patterns. Default: true. */
  scanReasoningBlocks?: boolean;
  /** Detect injection in chain-of-thought text. Default: true. */
  injectionDetection?: boolean;
  /** Detect system prompt leakage in reasoning. */
  systemPromptLeakDetection?: boolean;
  /** System prompt text for leak detection. */
  systemPrompt?: string;
  /** Detect reasoning diverging from original task. */
  goalDriftDetection?: boolean;
  /** Original task description. Falls back to first user message. */
  taskDescription?: string;
  /** Similarity threshold for goal drift. Default: 0.3 */
  goalDriftThreshold?: number;
  /** Action on violation. Default: 'warn'. */
  action?: 'block' | 'warn' | 'flag';
  /** Callback on violation. */
  onViolation?: (violation: ChainOfThoughtViolation) => void;
}

export interface ChainOfThoughtViolation {
  type: 'cot_injection' | 'cot_system_leak' | 'cot_goal_drift';
  reasoningSnippet: string;
  riskScore: number;
  details: string;
}

export interface ChainOfThoughtScanResult {
  violations: ChainOfThoughtViolation[];
  blocked: boolean;
  reasoningText: string;
}

// ── Reasoning extraction ─────────────────────────────────────────────────────

const REASONING_BLOCK_PATTERNS = [
  /<thinking>([\s\S]*?)<\/thinking>/gi,
  /<scratchpad>([\s\S]*?)<\/scratchpad>/gi,
  /<reasoning>([\s\S]*?)<\/reasoning>/gi,
  /<internal_monologue>([\s\S]*?)<\/internal_monologue>/gi,
];

/** Extract reasoning text from an LLM response object. */
export function extractReasoningText(response: any): string {
  const parts: string[] = [];

  // OpenAI o-series: reasoning_content on the message
  const message = response?.choices?.[0]?.message;
  if (message?.reasoning_content) {
    parts.push(message.reasoning_content);
  }

  // Anthropic: thinking content blocks
  const content = response?.content;
  if (Array.isArray(content)) {
    for (const block of content) {
      if (block?.type === 'thinking' && block?.thinking) {
        parts.push(block.thinking);
      }
    }
  }

  // Tag-based extraction from response text
  const text = message?.content ?? (typeof response === 'string' ? response : '');
  if (typeof text === 'string') {
    for (const re of REASONING_BLOCK_PATTERNS) {
      // Reset regex state
      re.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = re.exec(text)) !== null) {
        parts.push(match[1].trim());
      }
    }
  }

  return parts.join('\n').trim();
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const TOKEN_SPLIT = /[\s,.!?;:()\[\]{}"']+/;

function jaccardSimilarity(a: string, b: string): number {
  const tokensA = new Set(a.toLowerCase().split(TOKEN_SPLIT).filter((t) => t.length > 2));
  const tokensB = new Set(b.toLowerCase().split(TOKEN_SPLIT).filter((t) => t.length > 2));
  if (tokensA.size === 0 || tokensB.size === 0) return 0;
  let intersection = 0;
  for (const t of tokensA) {
    if (tokensB.has(t)) intersection++;
  }
  return intersection / (tokensA.size + tokensB.size - intersection);
}

function truncate(s: string, max = 200): string {
  return s.length > max ? s.slice(0, max) + '...' : s;
}

// ── Public API ───────────────────────────────────────────────────────────────

/** Scan extracted reasoning text for violations. */
export function scanChainOfThought(
  reasoningText: string,
  options: ChainOfThoughtGuardOptions,
): ChainOfThoughtScanResult {
  const violations: ChainOfThoughtViolation[] = [];

  if (!reasoningText || reasoningText.length === 0) {
    return { violations, blocked: false, reasoningText: '' };
  }

  // Injection detection
  if (options.injectionDetection !== false) {
    const analysis = detectInjection(reasoningText);
    if (analysis.riskScore >= 0.5) {
      violations.push({
        type: 'cot_injection',
        reasoningSnippet: truncate(reasoningText),
        riskScore: analysis.riskScore,
        details: `Injection detected in reasoning: ${analysis.triggered.join(', ')}`,
      });
    }
  }

  // System prompt leak detection
  if (options.systemPromptLeakDetection && options.systemPrompt) {
    const leakResult = detectPromptLeakage(reasoningText, {
      systemPrompt: options.systemPrompt,
      threshold: 0.4,
    });
    if (leakResult.leaked) {
      violations.push({
        type: 'cot_system_leak',
        reasoningSnippet: truncate(reasoningText),
        riskScore: leakResult.similarity,
        details: `System prompt leak in reasoning (score: ${leakResult.similarity.toFixed(2)})`,
      });
    }
  }

  // Goal drift detection
  if (options.goalDriftDetection && options.taskDescription) {
    const tokens = reasoningText.toLowerCase().split(TOKEN_SPLIT).filter((t) => t.length > 2);
    if (tokens.length >= 10) {
      const similarity = jaccardSimilarity(reasoningText, options.taskDescription);
      const threshold = options.goalDriftThreshold ?? 0.3;
      if (similarity < threshold) {
        violations.push({
          type: 'cot_goal_drift',
          reasoningSnippet: truncate(reasoningText),
          riskScore: 1 - similarity,
          details: `Reasoning diverged from task (similarity: ${similarity.toFixed(2)}, threshold: ${threshold})`,
        });
      }
    }
  }

  const action = options.action ?? 'warn';
  return {
    violations,
    blocked: action === 'block' && violations.length > 0,
    reasoningText,
  };
}
