import { MLPIIDetector } from './pii-detector';

// ── Helpers ──────────────────────────────────────────────────────────────────

interface FakeNERResult {
  entity_group: string;
  entity?: string;
  score: number;
  word: string;
  start: number;
  end: number;
}

function mockPipeline(results: FakeNERResult[]) {
  return jest.fn().mockResolvedValue(results);
}

function buildDetector(results: FakeNERResult[], threshold = 0.5) {
  return MLPIIDetector._createForTest(mockPipeline(results), { threshold });
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('MLPIIDetector', () => {
  // -- Properties --

  it('should have name "ml-ner"', () => {
    const detector = buildDetector([]);
    expect(detector.name).toBe('ml-ner');
  });

  it('should include core and extended types in supportedTypes', () => {
    const detector = buildDetector([]);
    expect(detector.supportedTypes).toContain('us_address');
    expect(detector.supportedTypes).toContain('person_name');
    expect(detector.supportedTypes).toContain('org_name');
  });

  // -- Person name detection --

  it('should detect person names (B-PER entity)', async () => {
    const detector = buildDetector([
      { entity_group: 'PER', score: 0.95, word: 'John Smith', start: 0, end: 10 },
    ]);
    const dets = await detector.detect('John Smith works here');
    expect(dets).toHaveLength(1);
    expect(dets[0].type).toBe('person_name');
    expect(dets[0].value).toBe('John Smith');
    expect(dets[0].confidence).toBe(0.95);
  });

  // -- Organization detection --

  it('should detect organization names (ORG entity)', async () => {
    const detector = buildDetector([
      { entity_group: 'ORG', score: 0.87, word: 'Acme Corp', start: 9, end: 18 },
    ]);
    const dets = await detector.detect('Works at Acme Corp');
    expect(dets).toHaveLength(1);
    expect(dets[0].type).toBe('org_name');
    expect(dets[0].value).toBe('Acme Corp');
  });

  // -- Location detection --

  it('should detect locations (LOC entity)', async () => {
    const detector = buildDetector([
      { entity_group: 'LOC', score: 0.85, word: 'New York', start: 9, end: 17 },
    ]);
    const dets = await detector.detect('Lives in New York');
    expect(dets).toHaveLength(1);
    expect(dets[0].type).toBe('us_address');
  });

  // -- IOB label variants --

  it('should handle B-PER label format', async () => {
    const detector = buildDetector([
      { entity_group: 'B-PER', entity: 'B-PER', score: 0.90, word: 'Alice', start: 0, end: 5 },
    ]);
    const dets = await detector.detect('Alice said hello');
    expect(dets[0].type).toBe('person_name');
  });

  it('should handle B-ORG label format', async () => {
    const detector = buildDetector([
      { entity_group: 'B-ORG', entity: 'B-ORG', score: 0.88, word: 'Google', start: 0, end: 6 },
    ]);
    const dets = await detector.detect('Google is a company');
    expect(dets[0].type).toBe('org_name');
  });

  it('should handle PERSON label format', async () => {
    const detector = buildDetector([
      { entity_group: 'PERSON', score: 0.92, word: 'Bob', start: 0, end: 3 },
    ]);
    const dets = await detector.detect('Bob is here');
    expect(dets[0].type).toBe('person_name');
  });

  // -- Filtering --

  it('should respect type filtering', async () => {
    const detector = buildDetector([
      { entity_group: 'PER', score: 0.95, word: 'John', start: 0, end: 4 },
      { entity_group: 'ORG', score: 0.87, word: 'Acme', start: 18, end: 22 },
    ]);
    const dets = await detector.detect('John works at Acme', {
      types: ['person_name' as any],
    });
    expect(dets).toHaveLength(1);
    expect(dets[0].type).toBe('person_name');
  });

  it('should return empty when type filter matches nothing', async () => {
    const detector = buildDetector([
      { entity_group: 'PER', score: 0.95, word: 'John', start: 0, end: 4 },
    ]);
    const dets = await detector.detect('John is here', {
      types: ['email'],
    });
    expect(dets).toEqual([]);
  });

  // -- Threshold --

  it('should skip detections below confidence threshold', async () => {
    const detector = buildDetector(
      [{ entity_group: 'PER', score: 0.3, word: 'Maybe', start: 0, end: 5 }],
      0.5,
    );
    const dets = await detector.detect('Maybe a name');
    expect(dets).toEqual([]);
  });

  // -- Edge cases --

  it('should return empty for empty text', async () => {
    const detector = buildDetector([]);
    const dets = await detector.detect('');
    expect(dets).toEqual([]);
  });

  it('should skip unknown entity types', async () => {
    const detector = buildDetector([
      { entity_group: 'UNKNOWN', score: 0.99, word: 'test', start: 0, end: 4 },
    ]);
    const dets = await detector.detect('test');
    expect(dets).toEqual([]);
  });

  it('should skip MISC entities by default', async () => {
    const detector = buildDetector([
      { entity_group: 'B-MISC', entity: 'B-MISC', score: 0.90, word: 'FIFA', start: 0, end: 4 },
    ]);
    const dets = await detector.detect('FIFA world cup');
    expect(dets).toEqual([]);
  });

  it('should sort results by start position', async () => {
    const detector = buildDetector([
      { entity_group: 'ORG', score: 0.88, word: 'Acme', start: 20, end: 24 },
      { entity_group: 'PER', score: 0.95, word: 'John', start: 0, end: 4 },
    ]);
    const dets = await detector.detect('John works at Acme Corp');
    expect(dets).toHaveLength(2);
    expect(dets[0].start).toBeLessThan(dets[1].start);
  });

  it('should round confidence to 2 decimal places', async () => {
    const detector = buildDetector([
      { entity_group: 'PER', score: 0.87654321, word: 'John', start: 0, end: 4 },
    ]);
    const dets = await detector.detect('John is here');
    expect(dets[0].confidence).toBe(0.88);
  });

  // -- Multiple detections --

  it('should detect multiple entities in one text', async () => {
    const detector = buildDetector([
      { entity_group: 'PER', score: 0.95, word: 'John Smith', start: 0, end: 10 },
      { entity_group: 'ORG', score: 0.87, word: 'Acme Corp', start: 20, end: 29 },
      { entity_group: 'LOC', score: 0.82, word: 'New York', start: 33, end: 41 },
    ]);
    const dets = await detector.detect('John Smith works at Acme Corp in New York');
    expect(dets).toHaveLength(3);
    expect(dets[0].type).toBe('person_name');
    expect(dets[1].type).toBe('org_name');
    expect(dets[2].type).toBe('us_address');
  });
});
