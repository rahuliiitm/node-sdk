import { MLToxicityDetector } from './toxicity-detector';

// ── Helpers ──────────────────────────────────────────────────────────────────

function mockClassifier(labelScores: Array<{ label: string; score: number }>) {
  return jest.fn().mockResolvedValue([labelScores]);
}

function buildDetector(
  labelScores: Array<{ label: string; score: number }>,
  threshold = 0.5,
) {
  return MLToxicityDetector._createForTest(
    mockClassifier(labelScores),
    { threshold },
  );
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('MLToxicityDetector', () => {
  // -- Properties --

  it('should have name "ml-toxicity"', () => {
    const detector = buildDetector([]);
    expect(detector.name).toBe('ml-toxicity');
  });

  // -- Toxic content --

  it('should detect toxic content above threshold', async () => {
    const detector = buildDetector([
      { label: 'toxic', score: 0.91 },
      { label: 'obscene', score: 0.12 },
      { label: 'threat', score: 0.05 },
      { label: 'insult', score: 0.08 },
      { label: 'identity_hate', score: 0.03 },
      { label: 'severe_toxic', score: 0.02 },
    ]);
    const violations = await detector.detect('You are a terrible person', 'input');
    expect(violations).toHaveLength(1);
    expect(violations[0].category).toBe('hate_speech');
  });

  it('should detect multiple toxicity categories', async () => {
    const detector = buildDetector([
      { label: 'toxic', score: 0.85 },
      { label: 'threat', score: 0.72 },
      { label: 'obscene', score: 0.68 },
      { label: 'insult', score: 0.20 },
      { label: 'identity_hate', score: 0.10 },
      { label: 'severe_toxic', score: 0.05 },
    ]);
    const violations = await detector.detect('Very bad text', 'input');
    const categories = new Set(violations.map((v) => v.category));
    expect(categories).toContain('hate_speech');
    expect(categories).toContain('violence');
    expect(categories).toContain('sexual');
  });

  // -- Safe content --

  it('should return no violations for safe text', async () => {
    const detector = buildDetector([
      { label: 'toxic', score: 0.02 },
      { label: 'obscene', score: 0.01 },
      { label: 'threat', score: 0.005 },
      { label: 'insult', score: 0.01 },
    ]);
    const violations = await detector.detect('The weather is nice today', 'input');
    expect(violations).toEqual([]);
  });

  // -- Empty text --

  it('should return empty for empty text', async () => {
    const detector = buildDetector([]);
    const violations = await detector.detect('', 'input');
    expect(violations).toEqual([]);
  });

  // -- Category mapping --

  it('should map "toxic" to hate_speech', async () => {
    const detector = buildDetector([{ label: 'toxic', score: 0.9 }]);
    const violations = await detector.detect('text', 'input');
    expect(violations[0].category).toBe('hate_speech');
  });

  it('should map "severe_toxic" to hate_speech', async () => {
    const detector = buildDetector([{ label: 'severe_toxic', score: 0.9 }]);
    const violations = await detector.detect('text', 'input');
    expect(violations[0].category).toBe('hate_speech');
  });

  it('should map "obscene" to sexual', async () => {
    const detector = buildDetector([{ label: 'obscene', score: 0.9 }]);
    const violations = await detector.detect('text', 'input');
    expect(violations[0].category).toBe('sexual');
  });

  it('should map "threat" to violence', async () => {
    const detector = buildDetector([{ label: 'threat', score: 0.9 }]);
    const violations = await detector.detect('text', 'input');
    expect(violations[0].category).toBe('violence');
  });

  it('should map "insult" to hate_speech', async () => {
    const detector = buildDetector([{ label: 'insult', score: 0.9 }]);
    const violations = await detector.detect('text', 'input');
    expect(violations[0].category).toBe('hate_speech');
  });

  it('should map "identity_hate" to hate_speech', async () => {
    const detector = buildDetector([{ label: 'identity_hate', score: 0.9 }]);
    const violations = await detector.detect('text', 'input');
    expect(violations[0].category).toBe('hate_speech');
  });

  // -- Severity thresholds --

  it('should assign "warn" severity below block threshold (0.8)', async () => {
    const detector = buildDetector([{ label: 'toxic', score: 0.65 }]);
    const violations = await detector.detect('text', 'input');
    expect(violations[0].severity).toBe('warn');
  });

  it('should assign "block" severity at or above block threshold (0.8)', async () => {
    const detector = buildDetector([{ label: 'toxic', score: 0.90 }]);
    const violations = await detector.detect('text', 'input');
    expect(violations[0].severity).toBe('block');
  });

  // -- Location passthrough --

  it('should pass through "input" location', async () => {
    const detector = buildDetector([{ label: 'toxic', score: 0.9 }]);
    const violations = await detector.detect('text', 'input');
    expect(violations[0].location).toBe('input');
  });

  it('should pass through "output" location', async () => {
    const detector = buildDetector([{ label: 'toxic', score: 0.9 }]);
    const violations = await detector.detect('text', 'output');
    expect(violations[0].location).toBe('output');
  });

  // -- Deduplication --

  it('should deduplicate same category (toxic + insult both → hate_speech)', async () => {
    const detector = buildDetector([
      { label: 'toxic', score: 0.85 },
      { label: 'insult', score: 0.75 },
    ]);
    const violations = await detector.detect('text', 'input');
    const hateViolations = violations.filter((v) => v.category === 'hate_speech');
    expect(hateViolations).toHaveLength(1);
  });

  // -- Custom threshold --

  it('should respect custom threshold', async () => {
    const detector = buildDetector(
      [{ label: 'toxic', score: 0.65 }],
      0.8,
    );
    const violations = await detector.detect('text', 'input');
    expect(violations).toEqual([]);
  });

  // -- Unknown labels --

  it('should skip unknown labels', async () => {
    const detector = buildDetector([{ label: 'unknown_category', score: 0.99 }]);
    const violations = await detector.detect('text', 'input');
    expect(violations).toEqual([]);
  });

  // -- Matched field --

  it('should set matched field to input text', async () => {
    const detector = buildDetector([{ label: 'toxic', score: 0.9 }]);
    const violations = await detector.detect('offensive text here', 'input');
    expect(violations[0].matched).toBe('offensive text here');
  });

  // -- Flat results (no outer array) --

  it('should handle flat results (no outer array wrapping)', async () => {
    const classifier = jest.fn().mockResolvedValue([
      { label: 'toxic', score: 0.9 },
    ]);
    const detector = MLToxicityDetector._createForTest(classifier);
    const violations = await detector.detect('text', 'input');
    expect(violations[0].category).toBe('hate_speech');
  });
});
