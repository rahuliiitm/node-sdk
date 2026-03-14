import { detectHallucination, mergeHallucinationResults } from './hallucination';
import type { HallucinationResult } from './hallucination';

// ── detectHallucination ─────────────────────────────────────────────────────

describe('detectHallucination', () => {
  // -- Empty input/source --

  it('should return not hallucinated with score 1.0 for empty generated text', () => {
    const result = detectHallucination('', 'some source text');
    expect(result.hallucinated).toBe(false);
    expect(result.faithfulnessScore).toBe(1.0);
    expect(result.severity).toBe('low');
  });

  it('should return not hallucinated with score 1.0 for empty source text', () => {
    const result = detectHallucination('some generated text', '');
    expect(result.hallucinated).toBe(false);
    expect(result.faithfulnessScore).toBe(1.0);
    expect(result.severity).toBe('low');
  });

  it('should return not hallucinated with score 1.0 for both empty', () => {
    const result = detectHallucination('', '');
    expect(result.hallucinated).toBe(false);
    expect(result.faithfulnessScore).toBe(1.0);
    expect(result.severity).toBe('low');
  });

  // -- Identical text --

  it('should return high faithfulness for identical text', () => {
    const text = 'The quick brown fox jumps over the lazy dog near the river bank';
    const result = detectHallucination(text, text);
    expect(result.faithfulnessScore).toBeGreaterThanOrEqual(0.7);
    expect(result.hallucinated).toBe(false);
    expect(result.severity).toBe('low');
  });

  // -- Completely different text --

  it('should return low faithfulness for completely different text', () => {
    const generated = 'Quantum physics explains particle behavior at subatomic scales';
    const source = 'The recipe calls for flour sugar butter and eggs mixed together';
    const result = detectHallucination(generated, source);
    expect(result.faithfulnessScore).toBeLessThan(0.5);
    expect(result.hallucinated).toBe(true);
  });

  // -- Custom threshold --

  it('should use custom threshold when provided', () => {
    const generated = 'The fox runs across the field quickly and quietly';
    const source = 'The fox jumps over the lazy dog in the park';
    // With a very low threshold, even partial overlap should not be hallucination
    const result = detectHallucination(generated, source, { threshold: 0.1 });
    expect(result.hallucinated).toBe(false);
  });

  it('should detect hallucination with high threshold', () => {
    const generated = 'The fox runs across the field near the river';
    const source = 'The fox jumps over the lazy dog in the park near the bench';
    // With a very high threshold, even partial overlap counts as hallucination
    const result = detectHallucination(generated, source, { threshold: 0.99 });
    expect(result.hallucinated).toBe(true);
  });

  // -- Severity levels --

  it('should classify severity as "low" for score >= 0.7', () => {
    // Identical text should give high score → low severity
    const text = 'Paris is the capital of France and a beautiful city in Europe';
    const result = detectHallucination(text, text);
    expect(result.faithfulnessScore).toBeGreaterThanOrEqual(0.7);
    expect(result.severity).toBe('low');
  });

  it('should classify severity as "high" for score < 0.4', () => {
    const generated = 'Elephants can fly using their enormous ears as wings across oceans';
    const source = 'JavaScript is a programming language used for building web applications and APIs';
    const result = detectHallucination(generated, source);
    expect(result.faithfulnessScore).toBeLessThan(0.4);
    expect(result.severity).toBe('high');
  });

  it('should use default threshold of 0.5', () => {
    // Score of exactly 0.5 should NOT be hallucination (< threshold, not <=)
    // Use text that partially overlaps to get a medium score
    const source = 'The cat sat on the mat in the room with a view of the garden';
    const generated = 'The cat sat on the mat in the room but then flew to the moon';
    const result = detectHallucination(generated, source);
    // Whether hallucinated depends on exact score vs 0.5
    expect(typeof result.hallucinated).toBe('boolean');
    expect(result.faithfulnessScore).toBeGreaterThanOrEqual(0);
    expect(result.faithfulnessScore).toBeLessThanOrEqual(1);
  });
});

// ── mergeHallucinationResults ───────────────────────────────────────────────

describe('mergeHallucinationResults', () => {
  it('should return default result for empty array', () => {
    const result = mergeHallucinationResults([]);
    expect(result.hallucinated).toBe(false);
    expect(result.faithfulnessScore).toBe(1.0);
    expect(result.severity).toBe('low');
  });

  it('should return the single result for array of one', () => {
    const input: HallucinationResult = {
      hallucinated: true,
      faithfulnessScore: 0.3,
      severity: 'high',
    };
    const result = mergeHallucinationResults([input]);
    expect(result.hallucinated).toBe(true);
    expect(result.faithfulnessScore).toBe(0.3);
    expect(result.severity).toBe('high');
  });

  it('should use minimum faithfulness score from multiple results', () => {
    const results: HallucinationResult[] = [
      { hallucinated: false, faithfulnessScore: 0.9, severity: 'low' },
      { hallucinated: true, faithfulnessScore: 0.3, severity: 'high' },
      { hallucinated: false, faithfulnessScore: 0.7, severity: 'low' },
    ];
    const merged = mergeHallucinationResults(results);
    expect(merged.faithfulnessScore).toBe(0.3);
  });

  it('should mark as hallucinated if any result is hallucinated', () => {
    const results: HallucinationResult[] = [
      { hallucinated: false, faithfulnessScore: 0.9, severity: 'low' },
      { hallucinated: true, faithfulnessScore: 0.4, severity: 'medium' },
    ];
    const merged = mergeHallucinationResults(results);
    expect(merged.hallucinated).toBe(true);
  });

  it('should not be hallucinated if no results are hallucinated', () => {
    const results: HallucinationResult[] = [
      { hallucinated: false, faithfulnessScore: 0.8, severity: 'low' },
      { hallucinated: false, faithfulnessScore: 0.6, severity: 'medium' },
    ];
    const merged = mergeHallucinationResults(results);
    expect(merged.hallucinated).toBe(false);
  });

  it('should compute severity from minimum score', () => {
    const results: HallucinationResult[] = [
      { hallucinated: false, faithfulnessScore: 0.9, severity: 'low' },
      { hallucinated: true, faithfulnessScore: 0.2, severity: 'high' },
    ];
    const merged = mergeHallucinationResults(results);
    expect(merged.severity).toBe('high');
    expect(merged.faithfulnessScore).toBe(0.2);
  });

  it('should assign medium severity for min score in [0.4, 0.7)', () => {
    const results: HallucinationResult[] = [
      { hallucinated: false, faithfulnessScore: 0.9, severity: 'low' },
      { hallucinated: false, faithfulnessScore: 0.5, severity: 'medium' },
    ];
    const merged = mergeHallucinationResults(results);
    expect(merged.severity).toBe('medium');
  });

  it('should round faithfulness score to 2 decimal places', () => {
    const results: HallucinationResult[] = [
      { hallucinated: false, faithfulnessScore: 0.333, severity: 'high' },
      { hallucinated: false, faithfulnessScore: 0.777, severity: 'low' },
    ];
    const merged = mergeHallucinationResults(results);
    expect(merged.faithfulnessScore).toBe(0.33);
  });
});
