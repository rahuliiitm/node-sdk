/**
 * Multi-step conversation guard -- stateful class that tracks
 * conversation state across LLM calls for agentic workflows.
 * Zero dependencies.
 * @internal
 *
 * TODO: Full implementation in Phase 3.
 */

import type { PIIDetection } from './pii';

// ── Types ────────────────────────────────────────────────────────────────────

export interface ConversationGuardOptions {
  /** Maximum turns before blocking. */
  maxTurns?: number;
  /** Detect topic drift across turns. */
  topicDriftDetection?: boolean;
  /** Threshold for topic drift. Default: 0.3 */
  topicDriftThreshold?: number;
  /** Track PII spread across turns. */
  crossTurnPiiTracking?: boolean;
  /** Accumulate risk scores across turns. */
  accumulatingRisk?: boolean;
  /** Cumulative risk threshold. Default: 2.0 */
  riskThreshold?: number;
  /** Max consecutive similar responses for loop detection. Default: 3 */
  maxConsecutiveSimilarResponses?: number;
  /** Max total tool calls across conversation. */
  maxTotalToolCalls?: number;
  /** Action on violation. Default: 'block'. */
  action?: 'block' | 'warn' | 'flag';
  /** Callback on violation. */
  onViolation?: (violation: ConversationGuardViolation) => void;
}

export interface ConversationGuardViolation {
  type:
    | 'max_turns'
    | 'topic_drift'
    | 'cross_turn_pii'
    | 'risk_threshold'
    | 'agent_loop'
    | 'tool_call_limit';
  currentTurn: number;
  details: string;
  cumulativeRiskScore?: number;
}

export interface TurnRecord {
  turnNumber: number;
  timestamp: number;
  userMessageHash: string;
  responseHash: string;
  responseSummary: string;
  piiTypesDetected: string[];
  piiValuesHashed: string[];
  toolCallCount: number;
  riskContribution: number;
}

export interface RecordTurnInput {
  userMessage: string;
  responseText: string;
  toolCallCount: number;
  piiDetections?: PIIDetection[];
  injectionRiskScore?: number;
  jailbreakRiskScore?: number;
}

export interface ConversationSummary {
  turns: number;
  cumulativeRiskScore: number;
  totalToolCalls: number;
  uniquePiiTypes: string[];
  piiSpreadDetected: boolean;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const TOKEN_SPLIT = /[\s,.!?;:()\[\]{}"']+/;
const MAX_HISTORY = 100;

/** FNV-1a hash for fast string hashing (non-cryptographic). */
function fnv1a(str: string): string {
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 16777619) >>> 0;
  }
  return hash.toString(36);
}

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

// ── ConversationGuard ────────────────────────────────────────────────────────

export class ConversationGuard {
  private readonly options: ConversationGuardOptions;
  private readonly turns: TurnRecord[] = [];
  private cumulativeRisk = 0;
  private totalTools = 0;
  private readonly piiValuesSeen: Set<string> = new Set();
  private consecutiveSimilar = 0;
  private lastResponseHash = '';
  private baselineMessage = '';
  private piiSpread = false;

  constructor(options: ConversationGuardOptions) {
    this.options = options;
  }

  /** Pre-call check: verify turn limits before making the LLM call. */
  checkPreCall(): ConversationGuardViolation | null {
    if (this.options.maxTurns != null && this.turns.length >= this.options.maxTurns) {
      return {
        type: 'max_turns',
        currentTurn: this.turns.length,
        details: `Conversation reached ${this.options.maxTurns} turn limit`,
      };
    }
    if (
      this.options.maxTotalToolCalls != null &&
      this.totalTools >= this.options.maxTotalToolCalls
    ) {
      return {
        type: 'tool_call_limit',
        currentTurn: this.turns.length,
        details: `Total tool calls (${this.totalTools}) reached limit (${this.options.maxTotalToolCalls})`,
      };
    }
    return null;
  }

  /** Post-call: record the turn and check for violations. */
  recordTurn(input: RecordTurnInput): ConversationGuardViolation[] {
    const violations: ConversationGuardViolation[] = [];
    const turnNumber = this.turns.length + 1;

    // Set baseline from first user message
    if (!this.baselineMessage && input.userMessage) {
      this.baselineMessage = input.userMessage;
    }

    // Hash response for loop detection
    const respHash = fnv1a(input.responseText.slice(0, 500));
    if (respHash === this.lastResponseHash) {
      this.consecutiveSimilar++;
    } else {
      this.consecutiveSimilar = 1;
    }
    this.lastResponseHash = respHash;

    // Agent loop detection
    const maxSimilar = this.options.maxConsecutiveSimilarResponses ?? 3;
    if (this.consecutiveSimilar >= maxSimilar) {
      violations.push({
        type: 'agent_loop',
        currentTurn: turnNumber,
        details: `${this.consecutiveSimilar} consecutive similar responses detected`,
      });
    }

    // Tool call tracking
    this.totalTools += input.toolCallCount;
    if (
      this.options.maxTotalToolCalls != null &&
      this.totalTools > this.options.maxTotalToolCalls
    ) {
      violations.push({
        type: 'tool_call_limit',
        currentTurn: turnNumber,
        details: `Total tool calls (${this.totalTools}) exceed limit (${this.options.maxTotalToolCalls})`,
      });
    }

    // Risk accumulation
    const riskContribution =
      (input.injectionRiskScore ?? 0) * 0.5 +
      (input.jailbreakRiskScore ?? 0) * 0.3 +
      (input.toolCallCount > 5 ? 0.2 : 0);
    this.cumulativeRisk += riskContribution;

    if (this.options.accumulatingRisk) {
      const threshold = this.options.riskThreshold ?? 2.0;
      if (this.cumulativeRisk >= threshold) {
        violations.push({
          type: 'risk_threshold',
          currentTurn: turnNumber,
          details: `Cumulative risk (${this.cumulativeRisk.toFixed(2)}) exceeds threshold (${threshold})`,
          cumulativeRiskScore: this.cumulativeRisk,
        });
      }
    }

    // Cross-turn PII tracking
    const piiTypes: string[] = [];
    const piiHashes: string[] = [];
    if (input.piiDetections && input.piiDetections.length > 0) {
      for (const d of input.piiDetections) {
        piiTypes.push(d.type);
        const hash = fnv1a(d.value);
        piiHashes.push(hash);

        if (this.options.crossTurnPiiTracking && this.piiValuesSeen.has(hash)) {
          // PII from a previous turn appeared again
          this.piiSpread = true;
          violations.push({
            type: 'cross_turn_pii',
            currentTurn: turnNumber,
            details: `PII type "${d.type}" detected in previous turn appeared again in turn ${turnNumber}`,
          });
        }
        this.piiValuesSeen.add(hash);
      }
    }

    // Topic drift
    if (this.options.topicDriftDetection && this.baselineMessage && turnNumber > 1) {
      const userTokens = input.userMessage.toLowerCase().split(TOKEN_SPLIT).filter((t) => t.length > 2);
      if (userTokens.length >= 10) {
        const similarity = jaccardSimilarity(input.userMessage, this.baselineMessage);
        const threshold = this.options.topicDriftThreshold ?? 0.3;
        if (similarity < threshold) {
          violations.push({
            type: 'topic_drift',
            currentTurn: turnNumber,
            details: `Topic drift detected (similarity: ${similarity.toFixed(2)}, threshold: ${threshold})`,
          });
        }
      }
    }

    // Record turn
    this.turns.push({
      turnNumber,
      timestamp: Date.now(),
      userMessageHash: fnv1a(input.userMessage),
      responseHash: respHash,
      responseSummary: input.responseText.slice(0, 200),
      piiTypesDetected: piiTypes,
      piiValuesHashed: piiHashes,
      toolCallCount: input.toolCallCount,
      riskContribution,
    });

    // Prune old turns
    if (this.turns.length > MAX_HISTORY) {
      this.turns.splice(0, this.turns.length - MAX_HISTORY);
    }

    return violations;
  }

  get turnCount(): number {
    return this.turns.length;
  }

  get riskScore(): number {
    return this.cumulativeRisk;
  }

  get toolCalls(): number {
    return this.totalTools;
  }

  reset(): void {
    this.turns.length = 0;
    this.cumulativeRisk = 0;
    this.totalTools = 0;
    this.piiValuesSeen.clear();
    this.consecutiveSimilar = 0;
    this.lastResponseHash = '';
    this.baselineMessage = '';
    this.piiSpread = false;
  }

  getSummary(): ConversationSummary {
    const allPiiTypes = new Set<string>();
    for (const turn of this.turns) {
      for (const t of turn.piiTypesDetected) {
        allPiiTypes.add(t);
      }
    }
    return {
      turns: this.turns.length,
      cumulativeRiskScore: this.cumulativeRisk,
      totalToolCalls: this.totalTools,
      uniquePiiTypes: [...allPiiTypes],
      piiSpreadDetected: this.piiSpread,
    };
  }
}
