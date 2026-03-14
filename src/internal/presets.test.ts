import { resolveSecurityOptions } from './presets';

describe('Sensitivity Presets', () => {
  it('strict preset sets lower block thresholds', () => {
    const resolved = resolveSecurityOptions({ preset: 'strict' });
    expect(resolved.injection?.blockThreshold).toBe(0.5);
    expect(resolved.injection?.blockOnHighRisk).toBe(true);
    expect(resolved.jailbreak?.blockThreshold).toBe(0.5);
    expect(resolved.secretDetection?.action).toBe('block');
    expect(resolved.unicodeSanitizer?.action).toBe('block');
  });

  it('balanced preset uses standard thresholds', () => {
    const resolved = resolveSecurityOptions({ preset: 'balanced' });
    expect(resolved.injection?.blockThreshold).toBe(0.7);
    expect(resolved.jailbreak?.blockThreshold).toBe(0.7);
    expect(resolved.secretDetection?.action).toBe('redact');
    expect(resolved.unicodeSanitizer?.action).toBe('strip');
  });

  it('permissive preset uses higher thresholds', () => {
    const resolved = resolveSecurityOptions({ preset: 'permissive' });
    expect(resolved.injection?.blockThreshold).toBe(0.85);
    expect(resolved.injection?.blockOnHighRisk).toBe(false);
    expect(resolved.jailbreak?.blockOnDetection).toBe(false);
    expect(resolved.contentFilter?.blockOnViolation).toBe(false);
  });

  it('user overrides take priority over preset', () => {
    const resolved = resolveSecurityOptions({
      preset: 'strict',
      injection: { blockThreshold: 0.6 },
    });
    // User set 0.6, even though strict preset says 0.5
    expect(resolved.injection?.blockThreshold).toBe(0.6);
    // blockOnHighRisk from preset still applied (user didn't override it)
    expect(resolved.injection?.blockOnHighRisk).toBe(true);
  });

  it('no preset returns options unchanged', () => {
    const opts = { injection: { blockThreshold: 0.9 } };
    const resolved = resolveSecurityOptions(opts);
    expect(resolved).toBe(opts); // exact same reference
  });

  it('preset fills in modules user did not configure', () => {
    const resolved = resolveSecurityOptions({
      preset: 'balanced',
      injection: { blockOnHighRisk: true },
    });
    // User only set injection — jailbreak, contentFilter, etc. come from preset
    expect(resolved.jailbreak?.blockThreshold).toBe(0.7);
    expect(resolved.contentFilter?.blockOnViolation).toBe(true);
    expect(resolved.pii?.redaction).toBe('placeholder');
  });

  it('preserves mode and other non-preset fields', () => {
    const resolved = resolveSecurityOptions({
      preset: 'strict',
      mode: 'shadow',
    });
    expect(resolved.mode).toBe('shadow');
    expect(resolved.injection?.blockThreshold).toBe(0.5);
  });
});
