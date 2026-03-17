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

/** Minimal embedding provider interface (avoids hard dependency on ML module). */
export interface CotEmbeddingProvider {
  embed(text: string): Promise<Float32Array> | Float32Array;
  cosine(a: Float32Array, b: Float32Array): number;
}

/** Minimal NLI session interface for coherence scoring. */
export interface CotNliSession {
  classifyPair(text: string, textPair: string, options?: { topK?: number | null }): Promise<Array<{ label: string; score: number }>>;
}

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
  /**
   * Optional ML embedding provider for semantic goal drift detection.
   * Uses cosine similarity instead of Jaccard word overlap.
   */
  embeddingProvider?: CotEmbeddingProvider;
  /**
   * Optional NLI session for coherence scoring between reasoning steps.
   * Detects injected/contradictory reasoning steps.
   */
  nliSession?: CotNliSession;
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
export async function scanChainOfThought(
  reasoningText: string,
  options: ChainOfThoughtGuardOptions,
): Promise<ChainOfThoughtScanResult> {
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

  // Goal drift detection — semantic (embedding) or lexical (Jaccard)
  if (options.goalDriftDetection && options.taskDescription) {
    const tokens = reasoningText.toLowerCase().split(TOKEN_SPLIT).filter((t) => t.length > 2);
    if (tokens.length >= 10) {
      let similarity: number;

      if (options.embeddingProvider) {
        // Semantic goal drift via embeddings
        const taskEmb = await Promise.resolve(options.embeddingProvider.embed(options.taskDescription));
        const reasoningEmb = await Promise.resolve(options.embeddingProvider.embed(reasoningText));
        similarity = options.embeddingProvider.cosine(taskEmb, reasoningEmb);
      } else {
        similarity = jaccardSimilarity(reasoningText, options.taskDescription);
      }

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

  // Coherence scoring via NLI — detect injected reasoning steps
  if (options.nliSession && reasoningText.length > 100) {
    const steps = splitReasoningSteps(reasoningText);
    if (steps.length >= 2) {
      for (let i = 0; i < steps.length - 1 && i < 5; i++) {
        const results = await options.nliSession.classifyPair(steps[i], steps[i + 1], { topK: null });
        const contradictionScore = getContradictionScore(results);
        if (contradictionScore > 0.7) {
          violations.push({
            type: 'cot_injection',
            reasoningSnippet: truncate(steps[i + 1]),
            riskScore: contradictionScore,
            details: `Incoherent reasoning step ${i + 2}: contradicts previous step (score: ${contradictionScore.toFixed(2)})`,
          });
          break; // One coherence violation is enough
        }
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

/** Split reasoning text into logical steps (by paragraph or numbered list). */
function splitReasoningSteps(text: string): string[] {
  // Try numbered steps: "1. ...", "Step 1: ...", etc.
  const numbered = text.split(/(?:^|\n)\s*(?:\d+[.)]\s|Step\s+\d+[.:]\s)/i).filter((s) => s.trim().length > 20);
  if (numbered.length >= 2) return numbered.map((s) => s.trim());

  // Fall back to paragraphs
  const paragraphs = text.split(/\n\s*\n/).filter((s) => s.trim().length > 20);
  if (paragraphs.length >= 2) return paragraphs.map((s) => s.trim());

  // Fall back to sentences (max 5)
  const sentences = text.split(/(?<=[.!?])\s+/).filter((s) => s.trim().length > 20);
  return sentences.slice(0, 5).map((s) => s.trim());
}

/** Extract contradiction score from NLI output labels. */
function getContradictionScore(results: Array<{ label: string; score: number }>): number {
  for (const r of results) {
    const label = r.label.toUpperCase();
    if (label === 'CONTRADICTION' || label === 'LABEL_0') return r.score;
  }
  for (const r of results) {
    const label = r.label.toUpperCase();
    if (label === 'ENTAILMENT' || label === 'LABEL_2') return 1.0 - r.score;
  }
  return 0;
}
