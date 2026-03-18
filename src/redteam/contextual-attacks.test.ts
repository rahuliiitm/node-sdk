import { generateContextualAttacks } from './contextual-attacks';
import { extractContext, clearContextCache, type ContextProfile } from '../internal/context-engine';

beforeEach(() => clearContextCache());

function makeProfile(overrides: Partial<ContextProfile> = {}): ContextProfile {
  return {
    role: null,
    entity: null,
    allowedTopics: [],
    restrictedTopics: [],
    forbiddenActions: [],
    outputFormat: null,
    groundingMode: 'any',
    constraints: [],
    rawSystemPrompt: '',
    promptHash: '',
    ...overrides,
  };
}

describe('generateContextualAttacks', () => {
  it('returns empty array for empty profile', () => {
    const attacks = generateContextualAttacks(makeProfile());
    expect(attacks).toEqual([]);
  });

  it('generates role attacks when role is set', () => {
    const attacks = generateContextualAttacks(makeProfile({ role: 'customer support agent' }));
    expect(attacks.length).toBeGreaterThanOrEqual(3);
    expect(attacks.some((a) => a.category === 'jailbreak')).toBe(true);
    expect(attacks.some((a) => a.name.includes('customer support agent'))).toBe(true);
  });

  it('generates topic attacks for restricted topics', () => {
    const attacks = generateContextualAttacks(makeProfile({
      restrictedTopics: ['politics', 'religion'],
    }));
    // 3 attacks per restricted topic
    const contentBypasses = attacks.filter((a) => a.category === 'content_bypass');
    expect(contentBypasses.length).toBeGreaterThanOrEqual(6);
    expect(contentBypasses.some((a) => a.name.includes('politics'))).toBe(true);
    expect(contentBypasses.some((a) => a.name.includes('religion'))).toBe(true);
  });

  it('generates topic drift attacks for allowed topics', () => {
    const attacks = generateContextualAttacks(makeProfile({
      allowedTopics: ['cooking'],
    }));
    expect(attacks.some((a) => a.name.includes('Topic drift from cooking'))).toBe(true);
  });

  it('generates forbidden action attacks', () => {
    const attacks = generateContextualAttacks(makeProfile({
      forbiddenActions: ['provide medical advice'],
    }));
    // 3 attacks per forbidden action
    const actionAttacks = attacks.filter((a) => a.name.includes('provide medical advice'));
    expect(actionAttacks.length).toBe(3);
    expect(actionAttacks.some((a) => a.category === 'injection')).toBe(true);
  });

  it('generates entity attacks when entity is set', () => {
    const attacks = generateContextualAttacks(makeProfile({
      entity: 'Acme Corp',
      restrictedTopics: ['competitors'],
    }));
    expect(attacks.some((a) => a.name.includes('Acme Corp'))).toBe(true);
    // Should include competitor comparison attack
    expect(attacks.some((a) => a.name.includes('Compare Acme Corp'))).toBe(true);
  });

  it('generates format attacks when output format is set', () => {
    const attacks = generateContextualAttacks(makeProfile({
      outputFormat: 'JSON',
    }));
    expect(attacks.some((a) => a.name.includes('JSON'))).toBe(true);
  });

  it('generates grounding attacks for documents_only', () => {
    const attacks = generateContextualAttacks(makeProfile({
      groundingMode: 'documents_only',
    }));
    expect(attacks.some((a) => a.name.includes('grounding'))).toBe(true);
    expect(attacks.length).toBe(2);
  });

  it('does NOT generate grounding attacks for "any" mode', () => {
    const attacks = generateContextualAttacks(makeProfile({
      groundingMode: 'any',
    }));
    expect(attacks.filter((a) => a.name.includes('grounding')).length).toBe(0);
  });

  it('all attacks have valid structure', () => {
    const attacks = generateContextualAttacks(makeProfile({
      role: 'banking assistant',
      entity: 'BigBank',
      restrictedTopics: ['politics', 'gambling'],
      forbiddenActions: ['transfer money', 'reveal account numbers'],
      outputFormat: 'JSON',
      groundingMode: 'documents_only',
      allowedTopics: ['account inquiries'],
    }));

    expect(attacks.length).toBeGreaterThan(10);

    for (const attack of attacks) {
      expect(attack.id).toBeTruthy();
      expect(attack.category).toBeTruthy();
      expect(attack.name).toBeTruthy();
      expect(attack.messages.length).toBeGreaterThan(0);
      expect(['blocked', 'redacted', 'warned', 'refused']).toContain(attack.expectedOutcome);
      expect(['critical', 'high', 'medium', 'low']).toContain(attack.severity);
      expect(attack.description.length).toBeGreaterThan(10);
    }
  });

  it('generates attacks from real extracted profile', () => {
    const profile = extractContext(
      'You are a customer support agent for Acme Corp. ' +
      'Only discuss billing and account questions. ' +
      'Never discuss politics or competitors. ' +
      'Do not provide financial advice. ' +
      'Always respond in JSON. ' +
      'Only answer from the provided documents.',
    );
    const attacks = generateContextualAttacks(profile);
    expect(attacks.length).toBeGreaterThan(10);

    // Should have role attacks
    expect(attacks.some((a) => a.category === 'jailbreak')).toBe(true);
    // Should have topic attacks
    expect(attacks.some((a) => a.category === 'content_bypass')).toBe(true);
    // Should have forbidden action attacks
    expect(attacks.some((a) => a.name.includes('financial advice'))).toBe(true);
    // Should have grounding attacks
    expect(attacks.some((a) => a.name.includes('grounding'))).toBe(true);
  });

  it('has unique IDs across all generated attacks', () => {
    const attacks = generateContextualAttacks(makeProfile({
      role: 'helper',
      restrictedTopics: ['politics'],
      forbiddenActions: ['give advice'],
      entity: 'TestCo',
      outputFormat: 'JSON',
      groundingMode: 'documents_only',
      allowedTopics: ['cooking'],
    }));
    const ids = attacks.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
