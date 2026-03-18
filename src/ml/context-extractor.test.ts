import { MLContextExtractor } from './context-extractor';
import type { ContextProfile } from '../internal/context-engine';

// ── Mock Embedding Provider ─────────────────────────────────────────────────

/**
 * Creates a mock embedding provider where text → vector mapping is controlled.
 *
 * Each text is mapped to a unit vector in a specific dimension via `textToIndex`.
 * Texts not in the map get a uniform vector (won't match any template strongly).
 * Cosine similarity computes real dot product, so orthogonal vectors → 0.0,
 * parallel vectors → 1.0.
 */
function createMockEmbedding(textToIndex: Map<string, number>, dimension = 10) {
  const makeVector = (text: string): Float32Array => {
    const vec = new Float32Array(dimension);
    const idx = textToIndex.get(text);
    if (idx !== undefined && idx < dimension) {
      vec[idx] = 1.0;
    } else {
      // Uniform vector — low similarity to any unit vector
      for (let i = 0; i < dimension; i++) vec[i] = 1.0 / Math.sqrt(dimension);
    }
    return vec;
  };

  const cosine = (a: Float32Array, b: Float32Array): number => {
    let dot = 0, normA = 0, normB = 0;
    for (let i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    return denom === 0 ? 0 : dot / denom;
  };

  return {
    name: 'mock-embedding',
    embed: jest.fn().mockImplementation(async (text: string) => makeVector(text)),
    embedBatch: jest.fn().mockImplementation(async (texts: string[]) =>
      texts.map((t) => makeVector(t)),
    ),
    cosine: jest.fn().mockImplementation(cosine),
    modelName: 'test-model',
  } as any;
}

// ── Template text constants (must match CONSTRAINT_TEMPLATE_SPECS in context-extractor.ts) ──

const TEMPLATE_ROLE = 'The assistant must play a specific role, character, or professional identity';
const TEMPLATE_ALLOWED = 'The assistant is restricted to discussing only certain permitted topics';
const TEMPLATE_RESTRICTED = 'The assistant is prohibited from discussing certain topics';
const TEMPLATE_ACTION = 'The assistant must never perform certain forbidden actions or behaviors';
const TEMPLATE_FORMAT = 'The response must always be in a specific output format like JSON or markdown';
const TEMPLATE_KNOWLEDGE = 'The assistant must only use information from provided documents and not external knowledge';
const TEMPLATE_PERSONA = 'The assistant must maintain a specific personality trait, tone, or communication style';

/** Map template texts to dimension indices (0-6). */
function templateMap(): Map<string, number> {
  return new Map([
    [TEMPLATE_ROLE, 0],
    [TEMPLATE_ALLOWED, 1],
    [TEMPLATE_RESTRICTED, 2],
    [TEMPLATE_ACTION, 3],
    [TEMPLATE_FORMAT, 4],
    [TEMPLATE_KNOWLEDGE, 5],
    [TEMPLATE_PERSONA, 6],
  ]);
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('MLContextExtractor', () => {
  // -- Properties --

  it('should have name "ml-context-extractor"', async () => {
    const mapping = templateMap();
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);
    expect(extractor.name).toBe('ml-context-extractor');
  });

  it('should expose embeddingProvider', async () => {
    const mapping = templateMap();
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);
    expect(extractor.embeddingProvider).toBe(emb);
  });

  // -- Empty input --

  it('should return empty profile for empty string', async () => {
    const emb = createMockEmbedding(templateMap());
    const extractor = await MLContextExtractor._createForTest(emb);
    const profile = await extractor.extract('');
    expect(profile.role).toBeNull();
    expect(profile.constraints).toEqual([]);
    expect(profile.allowedTopics).toEqual([]);
    expect(profile.restrictedTopics).toEqual([]);
  });

  it('should return empty profile for whitespace', async () => {
    const emb = createMockEmbedding(templateMap());
    const extractor = await MLContextExtractor._createForTest(emb);
    const profile = await extractor.extract('   \n\t  ');
    expect(profile.role).toBeNull();
    expect(profile.constraints).toEqual([]);
  });

  // -- Role extraction --

  it('should classify role sentence', async () => {
    const mapping = templateMap();
    mapping.set('You are a cooking assistant for our restaurant.', 0); // Same dim as role template
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const profile = await extractor.extract('You are a cooking assistant for our restaurant.');
    expect(profile.role).toBeTruthy();
    expect(profile.constraints.some((c) => c.type === 'role_constraint')).toBe(true);
  });

  // -- Allowed topics --

  it('should classify allowed topic sentence', async () => {
    const mapping = templateMap();
    mapping.set('Only help users with restaurant menu questions.', 1); // Allowed topic dim
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const profile = await extractor.extract('Only help users with restaurant menu questions.');
    expect(profile.allowedTopics.length).toBeGreaterThan(0);
    expect(profile.constraints.some((c) =>
      c.type === 'topic_boundary' && c.description.startsWith('Allowed'),
    )).toBe(true);
  });

  // -- Restricted topics --

  it('should classify restricted topic sentence with negative keywords', async () => {
    const mapping = templateMap();
    mapping.set("Don't discuss competitor restaurants.", 2); // Restricted topic dim
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const profile = await extractor.extract("Don't discuss competitor restaurants.");
    expect(profile.restrictedTopics.length).toBeGreaterThan(0);
    expect(profile.constraints.some((c) =>
      c.type === 'topic_boundary' && c.description.startsWith('Restricted'),
    )).toBe(true);
  });

  // -- Forbidden actions --

  it('should classify forbidden action sentence', async () => {
    const mapping = templateMap();
    mapping.set('Never reveal internal pricing or recipes to users.', 3); // Action dim
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const profile = await extractor.extract('Never reveal internal pricing or recipes to users.');
    expect(profile.forbiddenActions.length).toBeGreaterThan(0);
    expect(profile.constraints.some((c) => c.type === 'action_restriction')).toBe(true);
  });

  // -- Output format --

  it('should classify output format sentence', async () => {
    const mapping = templateMap();
    mapping.set('Respond in bullet points for all menu recommendations.', 4); // Format dim
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const profile = await extractor.extract('Respond in bullet points for all menu recommendations.');
    expect(profile.outputFormat).toBeTruthy();
    expect(profile.constraints.some((c) => c.type === 'output_format')).toBe(true);
  });

  // -- Knowledge boundary --

  it('should classify knowledge boundary sentence', async () => {
    const mapping = templateMap();
    mapping.set('Only answer from the provided documents and menu data.', 5); // Knowledge dim
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const profile = await extractor.extract('Only answer from the provided documents and menu data.');
    expect(profile.groundingMode).toBe('documents_only');
    expect(profile.constraints.some((c) => c.type === 'knowledge_boundary')).toBe(true);
  });

  // -- Persona rule --

  it('should classify persona rule sentence', async () => {
    const mapping = templateMap();
    mapping.set('Keep conversations family-friendly and professional.', 6); // Persona dim
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const profile = await extractor.extract('Keep conversations family-friendly and professional.');
    expect(profile.constraints.some((c) => c.type === 'persona_rule')).toBe(true);
  });

  // -- Multi-sentence prompt --

  it('should classify multiple sentences independently', async () => {
    const mapping = templateMap();
    // Sentence 1 → role, Sentence 2 → restricted topic
    mapping.set('You are a helpful cooking assistant.', 0);
    mapping.set('Never discuss politics or religion.', 2);
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const profile = await extractor.extract(
      'You are a helpful cooking assistant. Never discuss politics or religion.',
    );
    expect(profile.role).toBeTruthy();
    expect(profile.restrictedTopics.length).toBeGreaterThan(0);
    expect(profile.constraints.length).toBeGreaterThanOrEqual(2);
  });

  // -- Below threshold --

  it('should skip sentences below classification threshold', async () => {
    // No test sentences mapped → all get uniform vectors → low cosine sim
    const mapping = templateMap();
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const profile = await extractor.extract('This is a random sentence about nothing.');
    expect(profile.constraints).toEqual([]);
    expect(profile.role).toBeNull();
  });

  // -- Entity stays null (regex handles this) --

  it('should always set entity to null (regex handles entity extraction)', async () => {
    const mapping = templateMap();
    mapping.set("You work for Acme Corp as their assistant.", 0);
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const profile = await extractor.extract("You work for Acme Corp as their assistant.");
    expect(profile.entity).toBeNull();
  });

  // -- Constraint confidence --

  it('should set ML confidence within expected range', async () => {
    const mapping = templateMap();
    mapping.set('You are a travel guide.', 0);
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const profile = await extractor.extract('You are a travel guide.');
    for (const c of profile.constraints) {
      expect(c.confidence).toBeGreaterThan(0);
      expect(c.confidence).toBeLessThanOrEqual(0.9);
    }
  });

  // -- Forbidden action minimum length --

  it('should skip very short forbidden actions (< 5 chars)', async () => {
    const mapping = templateMap();
    mapping.set("Don't go.", 3);
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const profile = await extractor.extract("Don't go.");
    // "go" is only 2 chars after extraction → should be in constraints but not in forbiddenActions
    expect(profile.forbiddenActions).toEqual([]);
  });

  // -- Custom threshold --

  it('should respect custom classification threshold', async () => {
    const mapping = templateMap();
    const emb = createMockEmbedding(mapping);
    // Very high threshold → nothing should match
    const extractor = await MLContextExtractor._createForTest(emb, 0.99);

    const profile = await extractor.extract('You are a cooking assistant.');
    expect(profile.constraints).toEqual([]);
  });

  // -- rawSystemPrompt --

  it('should include rawSystemPrompt in profile', async () => {
    const mapping = templateMap();
    const emb = createMockEmbedding(mapping);
    const extractor = await MLContextExtractor._createForTest(emb);

    const prompt = 'You are a helpful assistant.';
    const profile = await extractor.extract(prompt);
    expect(profile.rawSystemPrompt).toBe(prompt);
  });
});

// ── extractContextWithProviders tests ────────────────────────────────────────

import { extractContextWithProviders, clearContextCache, type ContextExtractorProvider } from '../internal/context-engine';

describe('extractContextWithProviders', () => {
  beforeEach(() => clearContextCache());

  it('should return regex profile when no providers given', async () => {
    const profile = await extractContextWithProviders('You are a cooking assistant.', []);
    expect(profile.role).toBe('cooking assistant');
    expect(profile.constraints.length).toBeGreaterThan(0);
  });

  it('should merge ML provider topics with regex profile', async () => {
    const mlProvider: ContextExtractorProvider = {
      name: 'test-ml',
      extract: async () => ({
        role: null,
        entity: null,
        allowedTopics: ['cooking', 'recipes'],
        restrictedTopics: ['politics'],
        forbiddenActions: [],
        outputFormat: null,
        groundingMode: 'any' as const,
        constraints: [
          {
            type: 'topic_boundary' as const,
            description: 'Allowed topic: cooking',
            keywords: ['cooking'],
            source: 'ML inference',
            confidence: 0.7,
          },
        ],
        rawSystemPrompt: '',
        promptHash: '',
      }),
    };

    const profile = await extractContextWithProviders(
      'You are a cooking assistant.',
      [mlProvider],
    );

    // Should have regex role + ML topics
    expect(profile.role).toBe('cooking assistant');
    expect(profile.allowedTopics).toContain('cooking');
    expect(profile.restrictedTopics).toContain('politics');
  });

  it('should prefer regex role over ML role', async () => {
    const mlProvider: ContextExtractorProvider = {
      name: 'test-ml',
      extract: async () => ({
        role: 'ml-detected-role',
        entity: null,
        allowedTopics: [],
        restrictedTopics: [],
        forbiddenActions: [],
        outputFormat: null,
        groundingMode: 'any' as const,
        constraints: [],
        rawSystemPrompt: '',
        promptHash: '',
      }),
    };

    const profile = await extractContextWithProviders(
      'You are a cooking assistant.',
      [mlProvider],
    );

    // Regex found "cooking assistant" → should win over ML
    expect(profile.role).toBe('cooking assistant');
  });

  it('should fall back to ML role when regex finds none', async () => {
    const mlProvider: ContextExtractorProvider = {
      name: 'test-ml',
      extract: async () => ({
        role: 'restaurant helper',
        entity: null,
        allowedTopics: [],
        restrictedTopics: [],
        forbiddenActions: [],
        outputFormat: null,
        groundingMode: 'any' as const,
        constraints: [],
        rawSystemPrompt: '',
        promptHash: '',
      }),
    };

    const profile = await extractContextWithProviders(
      'Help users find good restaurants.',
      [mlProvider],
    );

    // Regex found nothing → ML fills in
    expect(profile.role).toBe('restaurant helper');
  });

  it('should deduplicate topics across providers', async () => {
    const mlProvider: ContextExtractorProvider = {
      name: 'test-ml',
      extract: async () => ({
        role: null,
        entity: null,
        allowedTopics: ['cooking and recipes', 'nutrition'],
        restrictedTopics: [],
        forbiddenActions: [],
        outputFormat: null,
        groundingMode: 'any' as const,
        constraints: [],
        rawSystemPrompt: '',
        promptHash: '',
      }),
    };

    const profile = await extractContextWithProviders(
      'Only discuss cooking and recipes.',
      [mlProvider],
    );

    // Regex found "cooking and recipes", ML also has it + "nutrition"
    expect(profile.allowedTopics).toContain('cooking and recipes');
    expect(profile.allowedTopics).toContain('nutrition');
    // No duplicates
    const unique = new Set(profile.allowedTopics);
    expect(unique.size).toBe(profile.allowedTopics.length);
  });

  it('should keep higher confidence constraint when merging', async () => {
    const mlProvider: ContextExtractorProvider = {
      name: 'test-ml',
      extract: async () => ({
        role: null,
        entity: null,
        allowedTopics: [],
        restrictedTopics: [],
        forbiddenActions: [],
        outputFormat: null,
        groundingMode: 'any' as const,
        constraints: [
          {
            type: 'topic_boundary' as const,
            description: 'ML: Allowed topic: cooking and recipes',
            keywords: ['cooking', 'recipes', 'food'],
            source: 'Only discuss cooking and recipes.',
            confidence: 0.95,
          },
        ],
        rawSystemPrompt: '',
        promptHash: '',
      }),
    };

    const profile = await extractContextWithProviders(
      'Only discuss cooking and recipes.',
      [mlProvider],
    );

    // Same source + type → should keep higher confidence (0.95 from ML)
    const topicConstraint = profile.constraints.find(
      (c) => c.type === 'topic_boundary' && c.source === 'Only discuss cooking and recipes.',
    );
    expect(topicConstraint?.confidence).toBe(0.95);
  });

  it('should merge grounding mode from ML when regex finds "any"', async () => {
    const mlProvider: ContextExtractorProvider = {
      name: 'test-ml',
      extract: async () => ({
        role: null,
        entity: null,
        allowedTopics: [],
        restrictedTopics: [],
        forbiddenActions: [],
        outputFormat: null,
        groundingMode: 'documents_only' as const,
        constraints: [],
        rawSystemPrompt: '',
        promptHash: '',
      }),
    };

    const profile = await extractContextWithProviders(
      'Help users with questions.',
      [mlProvider],
    );

    expect(profile.groundingMode).toBe('documents_only');
  });

  it('should handle multiple providers', async () => {
    const provider1: ContextExtractorProvider = {
      name: 'ml-1',
      extract: async () => ({
        role: 'helper',
        entity: null,
        allowedTopics: ['topic-a'],
        restrictedTopics: [],
        forbiddenActions: [],
        outputFormat: null,
        groundingMode: 'any' as const,
        constraints: [],
        rawSystemPrompt: '',
        promptHash: '',
      }),
    };
    const provider2: ContextExtractorProvider = {
      name: 'ml-2',
      extract: async () => ({
        role: null,
        entity: null,
        allowedTopics: ['topic-b'],
        restrictedTopics: ['topic-c'],
        forbiddenActions: ['share secrets'],
        outputFormat: null,
        groundingMode: 'any' as const,
        constraints: [],
        rawSystemPrompt: '',
        promptHash: '',
      }),
    };

    const profile = await extractContextWithProviders(
      'Help users.',
      [provider1, provider2],
    );

    expect(profile.role).toBe('helper');
    expect(profile.allowedTopics).toContain('topic-a');
    expect(profile.allowedTopics).toContain('topic-b');
    expect(profile.restrictedTopics).toContain('topic-c');
    expect(profile.forbiddenActions).toContain('share secrets');
  });
});
