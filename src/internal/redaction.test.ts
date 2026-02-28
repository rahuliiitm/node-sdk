import { redactPII, deRedact, type RedactionResult } from './redaction';
import type { PIIDetectorProvider, PIIDetection } from './pii';

describe('PII Redaction', () => {
  // ── Placeholder strategy ──────────────────────────────────────────────────

  describe('placeholder strategy', () => {
    it('replaces email with placeholder', () => {
      const result = redactPII('Contact john@acme.com', { strategy: 'placeholder' });
      expect(result.redactedText).toContain('[EMAIL_');
      expect(result.redactedText).not.toContain('john@acme.com');
      expect(result.detections).toHaveLength(1);
    });

    it('uses incrementing indices for same type', () => {
      const result = redactPII('Email a@b.com and c@d.com', { strategy: 'placeholder' });
      expect(result.redactedText).toContain('[EMAIL_1]');
      expect(result.redactedText).toContain('[EMAIL_2]');
    });

    it('replaces SSN with placeholder', () => {
      const result = redactPII('SSN: 123-45-6789', { strategy: 'placeholder' });
      expect(result.redactedText).toContain('[SSN_');
      expect(result.redactedText).not.toContain('123-45-6789');
    });

    it('replaces multiple PII types', () => {
      const result = redactPII('Email john@acme.com SSN 123-45-6789');
      expect(result.redactedText).toContain('[EMAIL_');
      expect(result.redactedText).toContain('[SSN_');
      expect(result.detections).toHaveLength(2);
    });

    it('is the default strategy', () => {
      const result = redactPII('Email john@acme.com');
      expect(result.redactedText).toContain('[EMAIL_');
    });
  });

  // ── Synthetic strategy ────────────────────────────────────────────────────

  describe('synthetic strategy', () => {
    it('replaces email with synthetic email', () => {
      const result = redactPII('Contact john@acme.com', { strategy: 'synthetic' });
      expect(result.redactedText).not.toContain('john@acme.com');
      expect(result.redactedText).toContain('@example.');
    });

    it('replaces SSN with synthetic SSN', () => {
      const result = redactPII('SSN: 123-45-6789', { strategy: 'synthetic' });
      expect(result.redactedText).not.toContain('123-45-6789');
      expect(result.redactedText).toContain('000-00-');
    });
  });

  // ── Hash strategy ─────────────────────────────────────────────────────────

  describe('hash strategy', () => {
    it('replaces email with hash', () => {
      const result = redactPII('Contact john@acme.com', { strategy: 'hash' });
      expect(result.redactedText).not.toContain('john@acme.com');
      expect(result.redactedText.length).toBeGreaterThan(0);
    });

    it('same input produces same hash (consistent)', () => {
      const r1 = redactPII('john@acme.com', { strategy: 'hash' });
      const r2 = redactPII('john@acme.com', { strategy: 'hash' });
      expect(r1.redactedText).toBe(r2.redactedText);
    });

    it('different inputs produce different hashes', () => {
      const r1 = redactPII('a@b.com', { strategy: 'hash' });
      const r2 = redactPII('c@d.com', { strategy: 'hash' });
      expect(r1.redactedText).not.toBe(r2.redactedText);
    });
  });

  // ── De-redaction ──────────────────────────────────────────────────────────

  describe('deRedact', () => {
    it('restores original values from placeholder', () => {
      const result = redactPII('Email john@acme.com', { strategy: 'placeholder' });
      const restored = deRedact(result.redactedText, result.mapping);
      expect(restored).toBe('Email john@acme.com');
    });

    it('restores original values from synthetic', () => {
      const result = redactPII('Email john@acme.com', { strategy: 'synthetic' });
      const restored = deRedact(result.redactedText, result.mapping);
      expect(restored).toBe('Email john@acme.com');
    });

    it('restores multiple PII values', () => {
      const original = 'Email john@acme.com SSN 123-45-6789';
      const result = redactPII(original, { strategy: 'placeholder' });
      const restored = deRedact(result.redactedText, result.mapping);
      expect(restored).toBe(original);
    });
  });

  // ── Mapping ───────────────────────────────────────────────────────────────

  describe('mapping', () => {
    it('maps replacement to original', () => {
      const result = redactPII('john@acme.com');
      expect(result.mapping.size).toBe(1);
      const [replacement, original] = [...result.mapping.entries()][0];
      expect(original).toBe('john@acme.com');
      expect(replacement).toContain('[EMAIL_');
    });

    it('empty for no PII', () => {
      const result = redactPII('Hello world');
      expect(result.mapping.size).toBe(0);
    });
  });

  // ── Edge cases ────────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('handles empty string', () => {
      const result = redactPII('');
      expect(result.redactedText).toBe('');
      expect(result.detections).toHaveLength(0);
    });

    it('returns original text when no PII found', () => {
      const text = 'Hello world';
      const result = redactPII(text);
      expect(result.redactedText).toBe(text);
    });

    it('type filtering works', () => {
      const text = 'Email a@b.com SSN 123-45-6789';
      const result = redactPII(text, { types: ['email'] });
      expect(result.redactedText).not.toContain('a@b.com');
      expect(result.redactedText).toContain('123-45-6789'); // SSN not redacted
    });
  });

  // ── Mask strategy ──────────────────────────────────────────────────────────

  describe('mask strategy', () => {
    it('masks credit card showing last 4 digits', () => {
      const result = redactPII('Card: 4111-1111-1111-1111', { strategy: 'mask' });
      expect(result.redactedText).toContain('****-****-****-1111');
      expect(result.redactedText).not.toContain('4111-1111-1111-1111');
    });

    it('masks email keeping first char and domain', () => {
      const result = redactPII('Email: john@acme.com', { strategy: 'mask' });
      expect(result.redactedText).toContain('j***@acme.com');
      expect(result.redactedText).not.toContain('john@acme.com');
    });

    it('masks phone showing last 4 digits', () => {
      const result = redactPII('Call (555) 123-4567', { strategy: 'mask' });
      expect(result.redactedText).toContain('***-***-4567');
      expect(result.redactedText).not.toContain('(555) 123-4567');
    });

    it('masks SSN showing last 4 digits', () => {
      const result = redactPII('SSN: 123-45-6789', { strategy: 'mask' });
      expect(result.redactedText).toContain('***-**-6789');
      expect(result.redactedText).not.toContain('123-45-6789');
    });

    it('uses generic masking for other types (shows last 4)', () => {
      const result = redactPII('IP: 203.0.113.42', { strategy: 'mask' });
      // Generic masking: keep last 4 chars of "203.0.113.42" → "3.42"
      expect(result.redactedText).not.toContain('203.0.113.42');
      const maskedVal = result.redactedText.replace('IP: ', '');
      // Last 4 chars of the IP value are "3.42"
      expect(maskedVal).toMatch(/\*+3\.42$/);
    });

    it('uses custom mask character', () => {
      const result = redactPII('SSN: 123-45-6789', {
        strategy: 'mask',
        masking: { char: '#' },
      });
      expect(result.redactedText).toContain('###-##-6789');
    });

    it('populates mapping for de-redaction', () => {
      const result = redactPII('Email: john@acme.com', { strategy: 'mask' });
      expect(result.mapping.size).toBe(1);
      const [replacement, original] = [...result.mapping.entries()][0];
      expect(original).toBe('john@acme.com');
      expect(replacement).toBe('j***@acme.com');
    });
  });

  // ── Provider integration ──────────────────────────────────────────────────

  describe('providers', () => {
    it('merges detections from additional providers', () => {
      const mockProvider: PIIDetectorProvider = {
        name: 'mock',
        supportedTypes: ['email'],
        detect: () => [
          { type: 'email', value: 'hidden@test.com', start: 50, end: 65, confidence: 0.99 },
        ],
      };

      const text = 'Contact john@acme.com' + ' '.repeat(29) + 'hidden@test.com';
      const result = redactPII(text, { providers: [mockProvider] });
      // Should have detections from both built-in and mock provider
      expect(result.detections.length).toBeGreaterThanOrEqual(2);
    });

    it('gracefully handles provider errors', () => {
      const failingProvider: PIIDetectorProvider = {
        name: 'failing',
        supportedTypes: ['email'],
        detect: () => { throw new Error('Provider crashed'); },
      };

      const result = redactPII('john@acme.com', { providers: [failingProvider] });
      // Should still work with built-in detector
      expect(result.detections).toHaveLength(1);
    });
  });
});
