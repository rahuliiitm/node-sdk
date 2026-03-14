import { MLHallucinationDetector } from './hallucination-detector';

// ── Helpers ──────────────────────────────────────────────────────────────────

function mockClassifier(label: string, score: number) {
  return jest.fn().mockResolvedValue([{ label, score }]);
}

function buildDetector(label = 'CONSISTENT', score = 0.95) {
  return MLHallucinationDetector._createForTest(mockClassifier(label, score));
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('MLHallucinationDetector', () => {
  // -- Properties --

  it('should have name "ml-hallucination"', () => {
    const detector = buildDetector();
    expect(detector.name).toBe('ml-hallucination');
  });

  // -- CONSISTENT label (faithful) --

  it('should return high faithfulness for CONSISTENT label', async () => {
    const detector = buildDetector('CONSISTENT', 0.92);
    const result = await detector.detect('Paris is in France', 'Paris is the capital of France');
    expect(result.faithfulnessScore).toBe(0.92);
    expect(result.hallucinated).toBe(false);
    expect(result.severity).toBe('low');
  });

  // -- HALLUCINATED label --

  it('should return low faithfulness for HALLUCINATED label (1 - score)', async () => {
    const detector = buildDetector('HALLUCINATED', 0.90);
    const result = await detector.detect('Paris is in Germany', 'Paris is the capital of France');
    // faithfulness = 1 - 0.90 = 0.10
    expect(result.faithfulnessScore).toBe(0.1);
    expect(result.hallucinated).toBe(true);
    expect(result.severity).toBe('high');
  });

  // -- ENTAILMENT label variant --

  it('should treat ENTAILMENT as consistent (score = faithfulness)', async () => {
    const detector = buildDetector('ENTAILMENT', 0.85);
    const result = await detector.detect('The sky is blue', 'The sky appears blue');
    expect(result.faithfulnessScore).toBe(0.85);
    expect(result.hallucinated).toBe(false);
  });

  // -- CONTRADICTION label variant --

  it('should treat CONTRADICTION as hallucinated (faithfulness = 1 - score)', async () => {
    const detector = buildDetector('CONTRADICTION', 0.80);
    const result = await detector.detect('Water is dry', 'Water is wet');
    // faithfulness = 1 - 0.80 = 0.20
    expect(result.faithfulnessScore).toBe(0.2);
    expect(result.hallucinated).toBe(true);
    expect(result.severity).toBe('high');
  });

  // -- LABEL_1 variant (consistent) --

  it('should treat LABEL_1 as consistent (score = faithfulness)', async () => {
    const detector = buildDetector('LABEL_1', 0.88);
    const result = await detector.detect('Test text', 'Source text');
    expect(result.faithfulnessScore).toBe(0.88);
    expect(result.hallucinated).toBe(false);
  });

  // -- LABEL_0 variant (hallucinated) --

  it('should treat LABEL_0 as hallucinated (faithfulness = 1 - score)', async () => {
    const detector = buildDetector('LABEL_0', 0.75);
    const result = await detector.detect('Test text', 'Source text');
    // faithfulness = 1 - 0.75 = 0.25
    expect(result.faithfulnessScore).toBe(0.25);
    expect(result.hallucinated).toBe(true);
    expect(result.severity).toBe('high');
  });

  // -- Empty input --

  it('should return score 1.0 for empty generated text', async () => {
    const detector = buildDetector();
    const result = await detector.detect('', 'some source');
    expect(result.faithfulnessScore).toBe(1.0);
    expect(result.hallucinated).toBe(false);
    expect(result.severity).toBe('low');
  });

  it('should return score 1.0 for empty source text', async () => {
    const detector = buildDetector();
    const result = await detector.detect('some text', '');
    expect(result.faithfulnessScore).toBe(1.0);
    expect(result.hallucinated).toBe(false);
  });

  // -- Empty classifier result --

  it('should return score 1.0 for empty classifier result', async () => {
    const classifier = jest.fn().mockResolvedValue([]);
    const detector = MLHallucinationDetector._createForTest(classifier);
    const result = await detector.detect('some text', 'some source');
    expect(result.faithfulnessScore).toBe(1.0);
    expect(result.hallucinated).toBe(false);
    expect(result.severity).toBe('low');
  });

  // -- Unknown label --

  it('should use raw score for unknown labels', async () => {
    const detector = buildDetector('UNKNOWN', 0.60);
    const result = await detector.detect('some text', 'some source');
    expect(result.faithfulnessScore).toBe(0.6);
  });

  // -- Severity levels --

  it('should classify severity as "low" for score >= 0.7', async () => {
    const detector = buildDetector('CONSISTENT', 0.80);
    const result = await detector.detect('text', 'source');
    expect(result.severity).toBe('low');
  });

  it('should classify severity as "medium" for score >= 0.4 and < 0.7', async () => {
    const detector = buildDetector('CONSISTENT', 0.55);
    const result = await detector.detect('text', 'source');
    expect(result.severity).toBe('medium');
  });

  it('should classify severity as "high" for score < 0.4', async () => {
    const detector = buildDetector('HALLUCINATED', 0.85);
    const result = await detector.detect('text', 'source');
    // faithfulness = 1 - 0.85 = 0.15
    expect(result.faithfulnessScore).toBe(0.15);
    expect(result.severity).toBe('high');
  });

  // -- Threshold --

  it('should use default threshold of 0.5', async () => {
    // Score just below 0.5 → hallucinated
    const detector = buildDetector('CONSISTENT', 0.45);
    const result = await detector.detect('text', 'source');
    expect(result.faithfulnessScore).toBe(0.45);
    expect(result.hallucinated).toBe(true);
  });

  it('should respect custom threshold', async () => {
    const classifier = mockClassifier('CONSISTENT', 0.45);
    const detector = MLHallucinationDetector._createForTest(classifier, { threshold: 0.3 });
    const result = await detector.detect('text', 'source');
    expect(result.faithfulnessScore).toBe(0.45);
    expect(result.hallucinated).toBe(false);
  });

  // -- Rounding --

  it('should round faithfulness score to 2 decimal places', async () => {
    const detector = buildDetector('CONSISTENT', 0.777);
    const result = await detector.detect('text', 'source');
    expect(result.faithfulnessScore).toBe(0.78);
  });
});
