/**
 * ML-based response judge using NLI cross-encoder + sentence embeddings.
 *
 * Uses Natural Language Inference to semantically verify whether LLM responses
 * comply with extracted constraints. Much more accurate than keyword overlap
 * for detecting paraphrased topic violations, subtle role deviations, etc.
 *
 * Two models:
 * - Embeddings (all-MiniLM-L6-v2, 3-5ms) — semantic topic matching
 * - NLI cross-encoder (ms-marco-MiniLM-L-6-v2, 5-10ms) — entailment checking
 *
 * Requires: npm install onnxruntime-node @huggingface/transformers
 *
 * @module
 */

import type {
  ResponseJudgeProvider,
  ResponseJudgment,
  BoundaryViolation,
  BoundaryViolationType,
} from '../internal/response-judge';
import type { ContextProfile, Constraint } from '../internal/context-engine';
import { OnnxSession } from './onnx-runtime';
import { MLEmbeddingProvider } from './embedding-provider';

const DEFAULT_NLI_MODEL = 'cross-encoder/ms-marco-MiniLM-L-6-v2';
const MAX_RESPONSE_LEN = 512;

export interface MLResponseJudgeOptions {
  /** HuggingFace NLI model name/path. Must have ONNX weights. */
  nliModel?: string;
  /** Max constraints to evaluate per response. Default: 10 */
  maxConstraints?: number;
  /** Custom cache directory. Default: ~/.launchpromptly/models */
  cacheDir?: string;
  /** Shared embedding provider. Created automatically if not provided. */
  embeddingProvider?: MLEmbeddingProvider;
}

/** Severity weights per violation type (same as heuristic judge). */
const VIOLATION_WEIGHTS: Record<BoundaryViolationType, number> = {
  topic_violation: 0.25,
  role_deviation: 0.15,
  forbidden_action: 0.30,
  format_violation: 0.15,
  grounding_violation: 0.20,
  persona_break: 0.10,
};

/**
 * ML-based response judge using NLI cross-encoder + embeddings.
 *
 * Implements `ResponseJudgeProvider` — drop-in alongside the heuristic judge.
 * Results are merged via `mergeJudgments()` in the pipeline.
 *
 * @example
 * ```ts
 * import { MLResponseJudge } from 'launchpromptly/ml';
 * const judge = await MLResponseJudge.create();
 * // Register via security options:
 * security: { responseJudge: { providers: [judge] } }
 * ```
 */
export class MLResponseJudge implements ResponseJudgeProvider {
  readonly name = 'ml-nli-judge';

  private _nliSession: OnnxSession;
  private _embedding: MLEmbeddingProvider;
  private _maxConstraints: number;

  private constructor(
    nliSession: OnnxSession,
    embedding: MLEmbeddingProvider,
    maxConstraints: number,
  ) {
    this._nliSession = nliSession;
    this._embedding = embedding;
    this._maxConstraints = maxConstraints;
  }

  /**
   * Create an MLResponseJudge by loading the NLI + embedding models.
   */
  static async create(options?: MLResponseJudgeOptions): Promise<MLResponseJudge> {
    const nliModel = options?.nliModel ?? DEFAULT_NLI_MODEL;
    const maxConstraints = options?.maxConstraints ?? 10;

    const nliSession = await OnnxSession.create(nliModel, {
      maxLength: MAX_RESPONSE_LEN,
      cacheDir: options?.cacheDir,
    });

    const embedding = options?.embeddingProvider
      ?? await MLEmbeddingProvider.create({ cacheDir: options?.cacheDir });

    return new MLResponseJudge(nliSession, embedding, maxConstraints);
  }

  /**
   * For testing: create with pre-built sessions.
   * @internal
   */
  static _createForTest(
    nliSession: OnnxSession,
    embedding: MLEmbeddingProvider,
    maxConstraints = 10,
  ): MLResponseJudge {
    return new MLResponseJudge(nliSession, embedding, maxConstraints);
  }

  /** Get the shared embedding provider (for reuse by other guards). */
  get embeddingProvider(): MLEmbeddingProvider {
    return this._embedding;
  }

  async judge(responseText: string, profile: ContextProfile): Promise<ResponseJudgment> {
    if (!responseText || !profile) {
      return { violated: false, complianceScore: 1.0, violations: [], severity: 'low' };
    }

    const violations: BoundaryViolation[] = [];
    const truncated = responseText.slice(0, MAX_RESPONSE_LEN * 4);

    // 1. Semantic topic checking via embeddings
    await this._checkTopicViolations(truncated, profile, violations);

    // 2. NLI constraint checking — does response contradict constraints?
    await this._checkConstraintViolations(truncated, profile, violations);

    // 3. Grounding check via embeddings
    await this._checkGroundingViolation(truncated, profile, violations);

    // Compute compliance score
    let penalty = 0;
    for (const v of violations) {
      penalty += v.confidence * (VIOLATION_WEIGHTS[v.type] ?? 0.15);
    }
    const complianceScore = Math.max(0, Math.round((1.0 - penalty) * 100) / 100);
    const severity = complianceScore >= 0.7 ? 'low' : complianceScore >= 0.4 ? 'medium' : 'high';

    return {
      violated: violations.length > 0,
      complianceScore,
      violations,
      severity,
    };
  }

  // ── Private checking methods ───────────────────────────────────────────────

  /**
   * Check restricted/allowed topics semantically via embeddings.
   * Catches paraphrased violations that keyword overlap misses.
   */
  private async _checkTopicViolations(
    responseText: string,
    profile: ContextProfile,
    violations: BoundaryViolation[],
  ): Promise<void> {
    const responseEmb = await this._embedding.embed(responseText);

    // Check restricted topics
    for (const topic of profile.restrictedTopics) {
      const topicEmb = await this._embedding.embed(topic);
      const sim = this._embedding.cosine(responseEmb, topicEmb);
      if (sim > 0.65) {
        const constraint: Constraint = {
          type: 'topic_boundary',
          description: `Restricted topic: ${topic}`,
          keywords: topic.toLowerCase().split(/\s+/),
          source: topic,
          confidence: 0.8,
        };
        violations.push({
          type: 'topic_violation',
          constraint,
          confidence: Math.min(sim * 1.2, 1.0),
          evidence: `Response semantically similar to restricted topic "${topic}" (similarity: ${sim.toFixed(2)})`,
        });
      }
    }

    // Check allowed topics — response should be similar to at least one
    if (profile.allowedTopics.length > 0) {
      const topicEmbeddings = await this._embedding.embedBatch(profile.allowedTopics);
      const maxSim = Math.max(
        ...topicEmbeddings.map((te) => this._embedding.cosine(responseEmb, te)),
      );

      if (maxSim < 0.35) {
        const constraint: Constraint = {
          type: 'topic_boundary',
          description: `Allowed topics: ${profile.allowedTopics.join(', ')}`,
          keywords: profile.allowedTopics.flatMap((t) => t.toLowerCase().split(/\s+/)),
          source: 'allowed topics',
          confidence: 0.7,
        };
        violations.push({
          type: 'topic_violation',
          constraint,
          confidence: Math.min((1.0 - maxSim) * 0.8, 0.95),
          evidence: `Response not semantically related to any allowed topic (max similarity: ${maxSim.toFixed(2)})`,
        });
      }
    }
  }

  /**
   * Use NLI cross-encoder to check if response contradicts constraints.
   * Premise = constraint description, Hypothesis = response excerpt.
   */
  private async _checkConstraintViolations(
    responseText: string,
    profile: ContextProfile,
    violations: BoundaryViolation[],
  ): Promise<void> {
    // Select highest-priority constraints (forbidden actions first, then others)
    const prioritized = [...profile.constraints].sort((a, b) => {
      const weights: Record<string, number> = {
        action_restriction: 3,
        negative_instruction: 2,
        role_constraint: 1,
      };
      return (weights[b.type] ?? 0) - (weights[a.type] ?? 0);
    });
    const constraintsToCheck = prioritized.slice(0, this._maxConstraints);

    for (const constraint of constraintsToCheck) {
      // Skip constraints already covered by topic check
      if (constraint.type === 'topic_boundary') continue;

      const premise = constraint.description;
      const hypothesis = responseText.slice(0, 500);

      const results = await this._nliSession.classifyPair(premise, hypothesis, { topK: null });
      const contradictionScore = this._getContradictionScore(results);

      if (contradictionScore > 0.6) {
        const violationType = this._constraintToViolationType(constraint.type);
        violations.push({
          type: violationType,
          constraint,
          confidence: Math.round(contradictionScore * 100) / 100,
          evidence: `NLI: response contradicts constraint "${premise}" (score: ${contradictionScore.toFixed(2)})`,
        });
      }
    }
  }

  /**
   * Check grounding via embeddings — does the response drift beyond system prompt?
   * Only checked when grounding mode is 'documents_only' or 'system_only'.
   */
  private async _checkGroundingViolation(
    responseText: string,
    profile: ContextProfile,
    violations: BoundaryViolation[],
  ): Promise<void> {
    if (profile.groundingMode === 'any') return;

    const responseEmb = await this._embedding.embed(responseText);
    const promptEmb = await this._embedding.embed(profile.rawSystemPrompt);
    const sim = this._embedding.cosine(responseEmb, promptEmb);

    if (sim < 0.25) {
      const constraint: Constraint = {
        type: 'knowledge_boundary',
        description: `Grounding mode: ${profile.groundingMode}`,
        keywords: [],
        source: 'grounding',
        confidence: 0.75,
      };
      violations.push({
        type: 'grounding_violation',
        constraint,
        confidence: Math.min((1.0 - sim) * 0.7, 0.9),
        evidence: `Response semantically distant from system prompt (similarity: ${sim.toFixed(2)})`,
      });
    }
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  /** Extract contradiction score from NLI output labels. */
  private _getContradictionScore(
    results: Array<{ label: string; score: number }>,
  ): number {
    for (const r of results) {
      const label = r.label.toUpperCase();
      if (label === 'CONTRADICTION' || label === 'LABEL_0') {
        return r.score;
      }
    }
    for (const r of results) {
      const label = r.label.toUpperCase();
      if (label === 'ENTAILMENT' || label === 'LABEL_2') {
        return 1.0 - r.score;
      }
    }
    return 0;
  }

  /** Map constraint type to boundary violation type. */
  private _constraintToViolationType(
    constraintType: string,
  ): BoundaryViolationType {
    switch (constraintType) {
      case 'action_restriction':
      case 'negative_instruction':
        return 'forbidden_action';
      case 'role_constraint':
        return 'role_deviation';
      case 'knowledge_boundary':
        return 'grounding_violation';
      case 'output_format':
        return 'format_violation';
      case 'persona_rule':
        return 'persona_break';
      default:
        return 'topic_violation';
    }
  }
}
