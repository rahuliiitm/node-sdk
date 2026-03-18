/**
 * Types for the Red Team Engine.
 * @module
 */

import type { GuardrailEvent } from '../types';

// ── Attack Categories ────────────────────────────────────────────────────────

export type AttackCategory =
  | 'injection'
  | 'jailbreak'
  | 'pii_extraction'
  | 'prompt_leakage'
  | 'content_bypass'
  | 'encoding_evasion'
  | 'multi_turn'
  | 'tool_abuse';

// ── Attack Payloads ──────────────────────────────────────────────────────────

export interface AttackPayload {
  /** Unique identifier for this attack. */
  id: string;
  /** Attack category. */
  category: AttackCategory;
  /** Human-readable name. */
  name: string;
  /** Messages to send to the LLM. */
  messages: Array<{ role: 'user' | 'system' | 'assistant'; content: string }>;
  /** What the guardrails should do. */
  expectedOutcome: 'blocked' | 'redacted' | 'warned' | 'refused';
  /** Severity if bypassed. */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Description of the attack technique. */
  description: string;
  /** OWASP LLM Top 10 reference. */
  reference?: string;
  /** Patterns that indicate the attack succeeded (bypassed guardrails). */
  successIndicators?: RegExp[];
}

// ── Attack Results ───────────────────────────────────────────────────────────

export type AttackOutcome =
  | 'blocked'
  | 'redacted'
  | 'refused'
  | 'bypassed'
  | 'error'
  | 'inconclusive';

export interface GuardrailEventCapture {
  type: string;
  data: Record<string, unknown>;
  timestamp: number;
}

export interface AttackResult {
  /** The attack that was run. */
  attack: AttackPayload;
  /** What actually happened. */
  outcome: AttackOutcome;
  /** Truncated response text (max 500 chars). */
  responsePreview?: string;
  /** Guardrail events fired during this attack. */
  guardrailEvents: GuardrailEventCapture[];
  /** Error message if outcome is 'error'. */
  error?: string;
  /** Execution time in ms. */
  latencyMs: number;
  /** Why the analyzer chose this outcome. */
  analysisReason: string;
}

// ── Red Team Options ─────────────────────────────────────────────────────────

export interface RedTeamProgress {
  completed: number;
  total: number;
  currentAttack: string;
  currentCategory: AttackCategory;
}

export interface RedTeamOptions {
  /** Categories to test. Default: all. */
  categories?: AttackCategory[];
  /** Maximum attacks to run. Default: 50. */
  maxAttacks?: number;
  /** Concurrent attack limit. Default: 3. */
  concurrency?: number;
  /** Delay between attacks in ms. Default: 500. */
  delayMs?: number;
  /** System prompt for prompt leakage tests. */
  systemPrompt?: string;
  /** User-provided attack payloads. */
  customAttacks?: AttackPayload[];
  /** Progress callback. */
  onProgress?: (progress: RedTeamProgress) => void;
  /** Model override. */
  model?: string;
  /** Validate without making LLM calls. */
  dryRun?: boolean;
  /** Generate context-aware attacks from system prompt. Default: true if systemPrompt provided. */
  contextualAttacks?: boolean;
}

// ── Report ───────────────────────────────────────────────────────────────────

export interface CategoryScore {
  category: AttackCategory;
  score: number;
  total: number;
  blocked: number;
  refused: number;
  bypassed: number;
  errors: number;
  inconclusive: number;
}

export interface Vulnerability {
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: AttackCategory;
  attackName: string;
  attackId: string;
  description: string;
  responsePreview?: string;
  remediation: string;
}

export interface RedTeamReport {
  /** Overall security score 0-100. */
  securityScore: number;
  /** Per-category breakdown. */
  categories: CategoryScore[];
  /** Individual attack results. */
  attacks: AttackResult[];
  /** Discovered vulnerabilities, sorted by severity. */
  vulnerabilities: Vulnerability[];
  /** Total attacks executed. */
  totalAttacks: number;
  /** Total execution time in ms. */
  totalDurationMs: number;
  /** Estimated LLM cost. */
  estimatedCostUsd: number;
  /** ISO timestamp. */
  timestamp: string;
}
