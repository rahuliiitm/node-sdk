/**
 * ML-based context extractor using sentence embeddings.
 *
 * Classifies system prompt sentences into constraint types via cosine
 * similarity against pre-embedded templates. Catches implicit constraints
 * that regex patterns miss (e.g., "Keep conversations family-friendly" →
 * persona_rule + implicit restricted topics).
 *
 * Uses the shared MLEmbeddingProvider (all-MiniLM-L6-v2, 384-dim).
 * Designed to run alongside regex extraction — results are merged in
 * extractContextWithProviders().
 *
 * Requires: npm install onnxruntime-node @huggingface/transformers
 *
 * @module
 */

import type {
  ContextExtractorProvider,
  ContextProfile,
  ConstraintType,
  Constraint,
  GroundingMode,
} from '../internal/context-engine';
import { MLEmbeddingProvider } from './embedding-provider';

// ── Configuration ─────────────────────────────────────────────────────────────

/** Minimum similarity score for a sentence to be classified. */
const CLASSIFICATION_THRESHOLD = 0.45;

/** Confidence assigned to ML-classified constraints. */
const ML_CONFIDENCE = 0.65;

/** Sentence splitting regex (mirrors context-engine). */
const SENTENCE_SPLIT_RE = /(?<=[.!?\n])\s+/;

/** Stop words for keyword extraction (mirrors context-engine). */
const STOP_WORDS = new Set([
  'a', 'an', 'the', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
  'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
  'should', 'may', 'might', 'must', 'shall', 'can', 'need', 'dare',
  'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by', 'from', 'as',
  'into', 'through', 'during', 'before', 'after', 'above', 'below',
  'between', 'out', 'off', 'over', 'under', 'again', 'further', 'then',
  'and', 'but', 'or', 'nor', 'not', 'so', 'yet', 'both', 'either',
  'neither', 'each', 'every', 'all', 'any', 'few', 'more', 'most',
  'other', 'some', 'such', 'no', 'only', 'own', 'same', 'than', 'too',
  'very', 'just', 'because', 'if', 'when', 'while', 'where', 'how',
  'what', 'which', 'who', 'whom', 'this', 'that', 'these', 'those',
  'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves',
  'you', 'your', 'yours', 'yourself', 'yourselves',
  'he', 'him', 'his', 'she', 'her', 'hers', 'it', 'its',
  'they', 'them', 'their', 'theirs', 'themselves',
  'about', 'up', 'also', 'well', 'back', 'even', 'still',
  'never', 'always', 'ever', 'already', 'now',
]);

const TOKEN_SPLIT_RE = /[\s,.!?;:()\[\]{}"']+/;

// ── Constraint type templates ─────────────────────────────────────────────────

interface ConstraintTemplateSpec {
  text: string;
  type: ConstraintType;
  subtype?: 'allowed' | 'restricted';
}

/**
 * Templates for zero-shot classification. Each sentence is compared against
 * all templates via cosine similarity; best match above threshold wins.
 */
const CONSTRAINT_TEMPLATE_SPECS: ConstraintTemplateSpec[] = [
  {
    text: 'The assistant must play a specific role, character, or professional identity',
    type: 'role_constraint',
  },
  {
    text: 'The assistant is restricted to discussing only certain permitted topics',
    type: 'topic_boundary',
    subtype: 'allowed',
  },
  {
    text: 'The assistant is prohibited from discussing certain topics',
    type: 'topic_boundary',
    subtype: 'restricted',
  },
  {
    text: 'The assistant must never perform certain forbidden actions or behaviors',
    type: 'action_restriction',
  },
  {
    text: 'The response must always be in a specific output format like JSON or markdown',
    type: 'output_format',
  },
  {
    text: 'The assistant must only use information from provided documents and not external knowledge',
    type: 'knowledge_boundary',
  },
  {
    text: 'The assistant must maintain a specific personality trait, tone, or communication style',
    type: 'persona_rule',
  },
];

/** Negative/restriction keywords for polarity detection. */
const NEGATIVE_INDICATORS = /\b(?:never|don'?t|do\s+not|must\s+not|should\s+not|cannot|can'?t|forbidden|prohibited|not\s+allowed|refrain|avoid|stay\s+away)\b/i;

/** Positive constraint indicators (scoping, not prohibiting). */
const POSITIVE_SCOPE_INDICATORS = /\b(?:only|limited\s+to|restricted\s+to|exclusively|solely|focus\s+on|confine|stick\s+to)\b/i;

// ── Types ─────────────────────────────────────────────────────────────────────

interface ConstraintTemplate extends ConstraintTemplateSpec {
  embedding: Float32Array;
}

export interface MLContextExtractorOptions {
  /** Custom cache directory. Default: ~/.launchpromptly/models */
  cacheDir?: string;
  /** Shared embedding provider. Created automatically if not provided. */
  embeddingProvider?: MLEmbeddingProvider;
  /** Classification threshold. Default: 0.45 */
  threshold?: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function splitSentences(text: string): string[] {
  return text
    .split(SENTENCE_SPLIT_RE)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function extractKeywords(text: string): string[] {
  return text
    .toLowerCase()
    .split(TOKEN_SPLIT_RE)
    .filter((t) => t.length > 2 && !STOP_WORDS.has(t));
}

function emptyProfile(systemPrompt: string): ContextProfile {
  return {
    role: null,
    entity: null,
    allowedTopics: [],
    restrictedTopics: [],
    forbiddenActions: [],
    outputFormat: null,
    groundingMode: 'any',
    constraints: [],
    rawSystemPrompt: systemPrompt || '',
    promptHash: '',
  };
}

// ── MLContextExtractor ────────────────────────────────────────────────────────

/**
 * ML-based context extractor using sentence embeddings for zero-shot
 * constraint classification.
 *
 * Implements `ContextExtractorProvider` — drop-in alongside regex extraction.
 * Results are merged in `extractContextWithProviders()`.
 *
 * @example
 * ```ts
 * import { MLContextExtractor } from 'launchpromptly/ml';
 * const extractor = await MLContextExtractor.create();
 * // Register via security options:
 * security: { contextEngine: { providers: [extractor] } }
 * ```
 */
export class MLContextExtractor implements ContextExtractorProvider {
  readonly name = 'ml-context-extractor';

  private _embedding: MLEmbeddingProvider;
  private _templates: ConstraintTemplate[];
  private _threshold: number;

  private constructor(
    embedding: MLEmbeddingProvider,
    templates: ConstraintTemplate[],
    threshold: number,
  ) {
    this._embedding = embedding;
    this._templates = templates;
    this._threshold = threshold;
  }

  /**
   * Create an MLContextExtractor by loading the embedding model and
   * pre-embedding all constraint type templates.
   */
  static async create(options?: MLContextExtractorOptions): Promise<MLContextExtractor> {
    const embedding = options?.embeddingProvider
      ?? await MLEmbeddingProvider.create({ cacheDir: options?.cacheDir });

    const threshold = options?.threshold ?? CLASSIFICATION_THRESHOLD;

    // Pre-embed all constraint type templates
    const templates: ConstraintTemplate[] = [];
    for (const spec of CONSTRAINT_TEMPLATE_SPECS) {
      const emb = await embedding.embed(spec.text);
      templates.push({ ...spec, embedding: emb });
    }

    return new MLContextExtractor(embedding, templates, threshold);
  }

  /**
   * For testing: create with pre-built embedding provider.
   * @internal
   */
  static async _createForTest(
    embedding: MLEmbeddingProvider,
    threshold = CLASSIFICATION_THRESHOLD,
  ): Promise<MLContextExtractor> {
    const templates: ConstraintTemplate[] = [];
    for (const spec of CONSTRAINT_TEMPLATE_SPECS) {
      const emb = await embedding.embed(spec.text);
      templates.push({ ...spec, embedding: emb });
    }
    return new MLContextExtractor(embedding, templates, threshold);
  }

  /** Get the shared embedding provider (for reuse by other guards). */
  get embeddingProvider(): MLEmbeddingProvider {
    return this._embedding;
  }

  /**
   * Extract a context profile from a system prompt using ML.
   *
   * Classifies each sentence against constraint type templates via
   * embedding cosine similarity. Returns an independent profile that
   * gets merged with regex results in extractContextWithProviders().
   */
  async extract(systemPrompt: string): Promise<ContextProfile> {
    if (!systemPrompt || systemPrompt.trim().length === 0) {
      return emptyProfile(systemPrompt);
    }

    const sentences = splitSentences(systemPrompt);
    if (sentences.length === 0) {
      return emptyProfile(systemPrompt);
    }

    // Embed all sentences in one batch
    const sentenceEmbeddings = await this._embedding.embedBatch(sentences);

    const constraints: Constraint[] = [];
    const allowedTopics: string[] = [];
    const restrictedTopics: string[] = [];
    const forbiddenActions: string[] = [];
    let role: string | null = null;
    let outputFormat: string | null = null;
    let groundingMode: GroundingMode = 'any';

    for (let i = 0; i < sentences.length; i++) {
      const sentence = sentences[i];
      const sentenceEmb = sentenceEmbeddings[i];

      // Find best matching constraint template
      const match = this._classifySentence(sentenceEmb);
      if (!match) continue;

      const { type, subtype, score } = match;
      const keywords = extractKeywords(sentence);
      const confidence = Math.min(score * (ML_CONFIDENCE / CLASSIFICATION_THRESHOLD), 0.9);

      switch (type) {
        case 'role_constraint': {
          if (!role) {
            role = this._extractRoleText(sentence);
          }
          constraints.push({
            type: 'role_constraint',
            description: `Role: ${role || sentence}`,
            keywords,
            source: sentence,
            confidence,
          });
          break;
        }

        case 'topic_boundary': {
          const topicText = this._extractTopicText(sentence);
          const isNegative = NEGATIVE_INDICATORS.test(sentence);
          const isPositiveScope = POSITIVE_SCOPE_INDICATORS.test(sentence);

          // Determine polarity: explicit subtype > keyword detection > default
          if (subtype === 'restricted' || (isNegative && subtype !== 'allowed')) {
            if (!restrictedTopics.includes(topicText)) {
              restrictedTopics.push(topicText);
            }
            constraints.push({
              type: 'topic_boundary',
              description: `Restricted topic: ${topicText}`,
              keywords,
              source: sentence,
              confidence,
            });
          } else if (subtype === 'allowed' || isPositiveScope) {
            if (!allowedTopics.includes(topicText)) {
              allowedTopics.push(topicText);
            }
            constraints.push({
              type: 'topic_boundary',
              description: `Allowed topic: ${topicText}`,
              keywords,
              source: sentence,
              confidence,
            });
          }
          break;
        }

        case 'action_restriction': {
          const actionText = this._extractActionText(sentence);
          if (actionText.length >= 5 && !forbiddenActions.includes(actionText)) {
            forbiddenActions.push(actionText);
          }
          constraints.push({
            type: 'action_restriction',
            description: `Forbidden: ${actionText}`,
            keywords,
            source: sentence,
            confidence,
          });
          break;
        }

        case 'output_format': {
          if (!outputFormat) {
            outputFormat = this._extractFormatText(sentence);
          }
          constraints.push({
            type: 'output_format',
            description: `Output format: ${outputFormat}`,
            keywords: [outputFormat.toLowerCase()],
            source: sentence,
            confidence,
          });
          break;
        }

        case 'knowledge_boundary': {
          groundingMode = /(?:provided|given|supplied|attached)\s+(?:documents?|context|sources?)/i.test(sentence)
            ? 'documents_only'
            : 'system_only';
          constraints.push({
            type: 'knowledge_boundary',
            description: `Knowledge restricted to ${groundingMode === 'documents_only' ? 'provided documents' : 'system context'}`,
            keywords,
            source: sentence,
            confidence,
          });
          break;
        }

        case 'persona_rule': {
          const trait = this._extractPersonaTrait(sentence);
          constraints.push({
            type: 'persona_rule',
            description: `Persona: ${trait}`,
            keywords: [trait],
            source: sentence,
            confidence,
          });
          break;
        }
      }
    }

    return {
      role,
      entity: null, // Entity extraction via regex is reliable enough
      allowedTopics,
      restrictedTopics,
      forbiddenActions,
      outputFormat,
      groundingMode,
      constraints,
      rawSystemPrompt: systemPrompt,
      promptHash: '', // Hash computed by extractContextWithProviders
    };
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  /**
   * Classify a sentence embedding against all templates.
   * Returns the best match above threshold, or null.
   */
  private _classifySentence(
    sentenceEmb: Float32Array,
  ): { type: ConstraintType; subtype?: 'allowed' | 'restricted'; score: number } | null {
    let bestTemplate: ConstraintTemplate | null = null;
    let bestScore = 0;

    for (const template of this._templates) {
      const sim = this._embedding.cosine(sentenceEmb, template.embedding);
      if (sim > bestScore) {
        bestScore = sim;
        bestTemplate = template;
      }
    }

    if (!bestTemplate || bestScore < this._threshold) return null;

    return {
      type: bestTemplate.type,
      subtype: bestTemplate.subtype,
      score: bestScore,
    };
  }

  /** Extract role text from a sentence (strip common prefixes). */
  private _extractRoleText(sentence: string): string {
    const match = sentence.match(
      /(?:you\s+are\s+(?:a|an)\s+|act\s+as\s+(?:a|an)?\s*|your\s+role\s+is\s+(?:to\s+)?|behave\s+as\s+(?:a|an)?\s*|you\s+(?:will\s+)?serve\s+as\s+(?:a|an)?\s*)(.+)/i,
    );
    return (match?.[1] || sentence).trim().toLowerCase().replace(/[.!?]+$/, '');
  }

  /** Extract the topic subject from a sentence. */
  private _extractTopicText(sentence: string): string {
    // Try to extract the topic phrase after common patterns
    const match = sentence.match(
      /(?:about|regarding|related\s+to|on\s+the\s+(?:topic|subject)\s+of|discuss(?:ing)?|conversations?\s+about)\s+(.+)/i,
    );
    if (match?.[1]) {
      return match[1].trim().toLowerCase().replace(/[.!?]+$/, '');
    }
    // Fall back to content keywords
    const keywords = extractKeywords(sentence);
    return keywords.slice(0, 4).join(' ') || sentence.toLowerCase().replace(/[.!?]+$/, '');
  }

  /** Extract forbidden action text from a sentence. */
  private _extractActionText(sentence: string): string {
    const match = sentence.match(
      /(?:never|don'?t|do\s+not|must\s+not|should\s+not|cannot)\s+(.+)/i,
    );
    return (match?.[1] || sentence).trim().toLowerCase().replace(/[.!?]+$/, '');
  }

  /** Extract output format from a sentence. */
  private _extractFormatText(sentence: string): string {
    const match = sentence.match(
      /\b(JSON|XML|YAML|HTML|markdown|plain\s+text|CSV|bullet\s+points?|numbered\s+list|paragraphs?|tables?)\b/i,
    );
    return match?.[1]?.toUpperCase() || 'STRUCTURED';
  }

  /** Extract persona trait from a sentence. */
  private _extractPersonaTrait(sentence: string): string {
    const match = sentence.match(
      /\b(professional|friendly|polite|formal|casual|concise|brief|helpful|empathetic|neutral|objective|respectful|warm|enthusiastic|serious|humorous|patient|assertive|family[- ]friendly|appropriate)\b/i,
    );
    return match?.[1]?.toLowerCase() || extractKeywords(sentence).slice(0, 2).join(' ');
  }
}
