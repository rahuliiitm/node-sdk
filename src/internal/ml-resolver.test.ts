import { resolveGuardrailList, mergeMLProviders } from './ml-resolver';
import type { ResolvedMLProviders } from './ml-resolver';
import type { SecurityOptions } from '../types';

// ── resolveGuardrailList ────────────────────────────────────────────────────

describe('resolveGuardrailList', () => {
  it('should return all 5 guardrails when useML is true', () => {
    const result = resolveGuardrailList(true);
    expect(result).toEqual(['injection', 'jailbreak', 'pii', 'toxicity', 'hallucination']);
  });

  it('should return empty array when useML is false', () => {
    const result = resolveGuardrailList(false);
    expect(result).toEqual([]);
  });

  it('should return specified guardrails for a valid array', () => {
    const result = resolveGuardrailList(['injection', 'pii']);
    expect(result).toEqual(['injection', 'pii']);
  });

  it('should resolve alias "contentFilter" to "toxicity"', () => {
    const result = resolveGuardrailList(['contentFilter']);
    expect(result).toEqual(['toxicity']);
  });

  it('should deduplicate when alias and canonical name both provided', () => {
    const result = resolveGuardrailList(['toxicity', 'contentFilter']);
    expect(result).toEqual(['toxicity']);
  });

  it('should throw Error for invalid guardrail name', () => {
    expect(() => resolveGuardrailList(['injection', 'nonexistent' as any])).toThrow(
      /Invalid useML guardrail: "nonexistent"/,
    );
  });

  it('should include valid guardrail names in error message', () => {
    expect(() => resolveGuardrailList(['bad' as any])).toThrow(/Valid values:/);
  });

  it('should handle single valid guardrail', () => {
    const result = resolveGuardrailList(['hallucination']);
    expect(result).toEqual(['hallucination']);
  });

  it('should handle all guardrails specified individually', () => {
    const result = resolveGuardrailList(['injection', 'jailbreak', 'pii', 'toxicity', 'hallucination']);
    expect(result).toEqual(['injection', 'jailbreak', 'pii', 'toxicity', 'hallucination']);
  });
});

// ── mergeMLProviders ────────────────────────────────────────────────────────

describe('mergeMLProviders', () => {
  const mockInjectionProvider = { name: 'ml-injection', detect: jest.fn() };
  const mockJailbreakProvider = { name: 'ml-jailbreak', detect: jest.fn() };
  const mockPiiProvider = { name: 'ml-pii', detect: jest.fn(), redact: jest.fn(), supportedTypes: ['email', 'phone'] };
  const mockToxicityProvider = { name: 'ml-toxicity', detect: jest.fn() };
  const mockHallucinationProvider = { name: 'ml-hallucination', detect: jest.fn() };

  it('should append ML providers to existing custom providers', () => {
    const existingProvider = { name: 'custom-injection', detect: jest.fn() };
    const security: SecurityOptions = {
      injection: {
        providers: [existingProvider],
      },
    };
    const mlProviders: ResolvedMLProviders = {
      injection: mockInjectionProvider,
    };

    const result = mergeMLProviders(security, mlProviders);

    expect(result.injection?.providers).toHaveLength(2);
    expect(result.injection?.providers?.[0]).toBe(existingProvider);
    expect(result.injection?.providers?.[1]).toBe(mockInjectionProvider);
  });

  it('should create guardrail options when none exist', () => {
    const security: SecurityOptions = {};
    const mlProviders: ResolvedMLProviders = {
      injection: mockInjectionProvider,
    };

    const result = mergeMLProviders(security, mlProviders);

    expect(result.injection?.providers).toHaveLength(1);
    expect(result.injection?.providers?.[0]).toBe(mockInjectionProvider);
  });

  it('should handle empty mlProviders', () => {
    const security: SecurityOptions = {
      injection: { enabled: true },
    };
    const mlProviders: ResolvedMLProviders = {};

    const result = mergeMLProviders(security, mlProviders);

    expect(result.injection).toEqual({ enabled: true });
    expect(result.injection?.providers).toBeUndefined();
  });

  it('should not mutate the original security object', () => {
    const security: SecurityOptions = {
      injection: { enabled: true },
    };
    const mlProviders: ResolvedMLProviders = {
      injection: mockInjectionProvider,
    };

    const result = mergeMLProviders(security, mlProviders);

    expect(result).not.toBe(security);
    expect(security.injection?.providers).toBeUndefined();
  });

  it('should merge all provider types at once', () => {
    const security: SecurityOptions = {};
    const mlProviders: ResolvedMLProviders = {
      injection: mockInjectionProvider,
      jailbreak: mockJailbreakProvider,
      pii: mockPiiProvider,
      toxicity: mockToxicityProvider,
      hallucination: mockHallucinationProvider,
    };

    const result = mergeMLProviders(security, mlProviders);

    expect(result.injection?.providers).toEqual([mockInjectionProvider]);
    expect(result.jailbreak?.providers).toEqual([mockJailbreakProvider]);
    expect(result.pii?.providers).toEqual([mockPiiProvider]);
    expect(result.contentFilter?.providers).toEqual([mockToxicityProvider]);
    expect(result.hallucination?.providers).toEqual([mockHallucinationProvider]);
  });

  it('should map toxicity provider to contentFilter key', () => {
    const security: SecurityOptions = {};
    const mlProviders: ResolvedMLProviders = {
      toxicity: mockToxicityProvider,
    };

    const result = mergeMLProviders(security, mlProviders);

    expect(result.contentFilter?.providers).toEqual([mockToxicityProvider]);
    // toxicity key should not exist on SecurityOptions
    expect((result as any).toxicity).toBeUndefined();
  });

  it('should preserve existing security options when merging', () => {
    const security: SecurityOptions = {
      injection: {
        enabled: true,
        blockThreshold: 0.8,
      },
    };
    const mlProviders: ResolvedMLProviders = {
      injection: mockInjectionProvider,
    };

    const result = mergeMLProviders(security, mlProviders);

    expect(result.injection?.enabled).toBe(true);
    expect(result.injection?.blockThreshold).toBe(0.8);
    expect(result.injection?.providers).toEqual([mockInjectionProvider]);
  });
});
