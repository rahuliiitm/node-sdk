import {
  detectPII,
  mergeDetections,
  RegexPIIDetector,
  createCustomDetector,
  applySuppressiveContext,
  filterAllowList,
  filterByConfidence,
  type PIIDetection,
  type CustomPIIPattern,
} from './pii';

describe('PII Detection', () => {
  // ── Email ───────────────────────────────────────────────────────────────────

  describe('email', () => {
    it('detects simple email', () => {
      const result = detectPII('Contact john@acme.com for details');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('email');
      expect(result[0].value).toBe('john@acme.com');
      expect(result[0].confidence).toBeGreaterThan(0.9);
    });

    it('detects multiple emails', () => {
      const result = detectPII('Send to a@b.com and c@d.org');
      expect(result).toHaveLength(2);
      expect(result[0].value).toBe('a@b.com');
      expect(result[1].value).toBe('c@d.org');
    });

    it('detects email with plus and dots', () => {
      const result = detectPII('Email: first.last+tag@sub.domain.co.uk');
      expect(result).toHaveLength(1);
      expect(result[0].value).toBe('first.last+tag@sub.domain.co.uk');
    });

    it('does not false-positive on at-mentions', () => {
      const result = detectPII('Check the code @line 42');
      const emails = result.filter((d) => d.type === 'email');
      expect(emails).toHaveLength(0);
    });
  });

  // ── Phone ─────────────────────────────────────────────────────────────────

  describe('phone', () => {
    it('detects US phone with parens', () => {
      const result = detectPII('Call (555) 123-4567');
      const phones = result.filter((d) => d.type === 'phone');
      expect(phones.length).toBeGreaterThanOrEqual(1);
    });

    it('detects US phone with dashes', () => {
      const result = detectPII('Call 555-123-4567');
      const phones = result.filter((d) => d.type === 'phone');
      expect(phones.length).toBeGreaterThanOrEqual(1);
    });

    it('detects US phone with +1 prefix', () => {
      const result = detectPII('Call +1 555-123-4567');
      const phones = result.filter((d) => d.type === 'phone');
      expect(phones.length).toBeGreaterThanOrEqual(1);
    });

    it('detects international phone (no spaces)', () => {
      const result = detectPII('Call +442079460958');
      const phones = result.filter((d) => d.type === 'phone');
      expect(phones.length).toBeGreaterThanOrEqual(1);
    });

    it('detects international phone with one separator', () => {
      const result = detectPII('Call +44-2079460958');
      const phones = result.filter((d) => d.type === 'phone');
      expect(phones.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── SSN ───────────────────────────────────────────────────────────────────

  describe('ssn', () => {
    it('detects SSN format', () => {
      const result = detectPII('SSN: 123-45-6789');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('ssn');
      expect(result[0].value).toBe('123-45-6789');
    });

    it('detects SSN in context', () => {
      const result = detectPII('My social security number is 078-05-1120');
      const ssns = result.filter((d) => d.type === 'ssn');
      expect(ssns).toHaveLength(1);
    });

    it('detects SSN without separators', () => {
      const result = detectPII('SSN: 123456789');
      const ssns = result.filter((d) => d.type === 'ssn');
      expect(ssns).toHaveLength(1);
      expect(ssns[0].value).toBe('123456789');
    });

    it('detects SSN with spaces', () => {
      const result = detectPII('SSN: 123 45 6789');
      const ssns = result.filter((d) => d.type === 'ssn');
      expect(ssns).toHaveLength(1);
      expect(ssns[0].value).toBe('123 45 6789');
    });

    it('rejects invalid SSN with area 000', () => {
      const result = detectPII('SSN: 000-12-3456');
      const ssns = result.filter((d) => d.type === 'ssn');
      expect(ssns).toHaveLength(0);
    });

    it('rejects invalid SSN with area 666', () => {
      const result = detectPII('SSN: 666-12-3456');
      const ssns = result.filter((d) => d.type === 'ssn');
      expect(ssns).toHaveLength(0);
    });

    it('rejects invalid SSN with area 9xx', () => {
      const result = detectPII('SSN: 900-12-3456');
      const ssns = result.filter((d) => d.type === 'ssn');
      expect(ssns).toHaveLength(0);
    });
  });

  // ── Credit Card ──────────────────────────────────────────────────────────

  describe('credit_card', () => {
    it('detects Visa number', () => {
      const result = detectPII('Card: 4111111111111111');
      const cards = result.filter((d) => d.type === 'credit_card');
      expect(cards).toHaveLength(1);
      expect(cards[0].value.replace(/[\s\-]/g, '')).toBe('4111111111111111');
    });

    it('detects card with dashes', () => {
      const result = detectPII('Card: 4111-1111-1111-1111');
      const cards = result.filter((d) => d.type === 'credit_card');
      expect(cards).toHaveLength(1);
    });

    it('rejects invalid Luhn number', () => {
      const result = detectPII('Number: 1234567890123456');
      const cards = result.filter((d) => d.type === 'credit_card');
      expect(cards).toHaveLength(0);
    });

    it('detects Mastercard', () => {
      const result = detectPII('Card: 5500000000000004');
      const cards = result.filter((d) => d.type === 'credit_card');
      expect(cards).toHaveLength(1);
    });
  });

  // ── IP Address ────────────────────────────────────────────────────────────

  describe('ip_address', () => {
    it('detects valid IP', () => {
      const result = detectPII('Server at 85.12.45.78');
      const ips = result.filter((d) => d.type === 'ip_address');
      expect(ips).toHaveLength(1);
      expect(ips[0].value).toBe('85.12.45.78');
    });

    it('filters out well-known IPs (localhost)', () => {
      const result = detectPII('Connect to 127.0.0.1');
      const ips = result.filter((d) => d.type === 'ip_address');
      expect(ips).toHaveLength(0);
    });

    it('filters out 0.0.0.0', () => {
      const result = detectPII('Bind to 0.0.0.0');
      const ips = result.filter((d) => d.type === 'ip_address');
      expect(ips).toHaveLength(0);
    });

    it('does not match invalid octets', () => {
      const result = detectPII('Version 999.999.999.999');
      const ips = result.filter((d) => d.type === 'ip_address');
      expect(ips).toHaveLength(0);
    });
  });

  // ── API Key ───────────────────────────────────────────────────────────────

  describe('api_key', () => {
    it('detects OpenAI key', () => {
      const result = detectPII('Key: sk-abcdefghijklmnopqrstuvwxyz1234');
      const keys = result.filter((d) => d.type === 'api_key');
      expect(keys).toHaveLength(1);
    });

    it('detects OpenAI project key', () => {
      const result = detectPII('Key: sk-proj-abcdefghijklmnopqrstuvwxyz');
      const keys = result.filter((d) => d.type === 'api_key');
      expect(keys).toHaveLength(1);
    });

    it('detects AWS access key', () => {
      const result = detectPII('AWS key: AKIAIOSFODNN7EXAMPLE');
      const keys = result.filter((d) => d.type === 'api_key');
      expect(keys).toHaveLength(1);
    });

    it('detects GitHub PAT', () => {
      const result = detectPII(
        'Token: ghp_abcdefghijklmnopqrstuvwxyz1234567890',
      );
      const keys = result.filter((d) => d.type === 'api_key');
      expect(keys).toHaveLength(1);
    });

    it('detects Slack token', () => {
      const result = detectPII('Token: xoxb-123456789-abcdef');
      const keys = result.filter((d) => d.type === 'api_key');
      expect(keys).toHaveLength(1);
    });
  });

  // ── Date of Birth ──────────────────────────────────────────────────────────

  describe('date_of_birth', () => {
    it('detects MM/DD/YYYY format', () => {
      const result = detectPII('DOB: 01/15/1990');
      const dobs = result.filter((d) => d.type === 'date_of_birth');
      expect(dobs).toHaveLength(1);
      expect(dobs[0].value).toBe('01/15/1990');
    });

    it('detects MM-DD-YYYY format', () => {
      const result = detectPII('Born on 12-25-2000');
      const dobs = result.filter((d) => d.type === 'date_of_birth');
      expect(dobs).toHaveLength(1);
    });

    it('does not match invalid months', () => {
      const result = detectPII('Date: 13/01/2000');
      const dobs = result.filter((d) => d.type === 'date_of_birth');
      expect(dobs).toHaveLength(0);
    });
  });

  // ── US Address ────────────────────────────────────────────────────────────

  describe('us_address', () => {
    it('detects street address', () => {
      const result = detectPII('Lives at 123 Main Street');
      const addrs = result.filter((d) => d.type === 'us_address');
      expect(addrs).toHaveLength(1);
    });

    it('detects avenue address', () => {
      const result = detectPII('Office at 456 Park Ave');
      const addrs = result.filter((d) => d.type === 'us_address');
      expect(addrs).toHaveLength(1);
    });

    it('detects boulevard address', () => {
      const result = detectPII('Located at 789 Sunset Blvd');
      const addrs = result.filter((d) => d.type === 'us_address');
      expect(addrs).toHaveLength(1);
    });
  });

  // ── Multi-PII ─────────────────────────────────────────────────────────────

  describe('multi-PII detection', () => {
    it('detects multiple PII types in one string', () => {
      const text =
        'Contact john@acme.com, SSN 123-45-6789, call (555) 123-4567';
      const result = detectPII(text);
      const types = new Set(result.map((d) => d.type));
      expect(types.has('email')).toBe(true);
      expect(types.has('ssn')).toBe(true);
      expect(types.has('phone')).toBe(true);
    });

    it('returns detections sorted by start position', () => {
      const text = 'SSN 123-45-6789 and email a@b.com';
      const result = detectPII(text);
      for (let i = 1; i < result.length; i++) {
        expect(result[i].start).toBeGreaterThanOrEqual(result[i - 1].start);
      }
    });
  });

  // ── Filtering by type ─────────────────────────────────────────────────────

  describe('type filtering', () => {
    it('only detects specified types', () => {
      const text = 'Email a@b.com and SSN 123-45-6789';
      const result = detectPII(text, { types: ['email'] });
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('email');
    });

    it('returns empty for non-matching types', () => {
      const text = 'Email a@b.com';
      const result = detectPII(text, { types: ['ssn'] });
      expect(result).toHaveLength(0);
    });
  });

  // ── ReDoS resistance ──────────────────────────────────────────────────────

  describe('ReDoS resistance', () => {
    it('credit card regex does not hang on adversarial input', () => {
      const adversarial = '1234 5678 9012 3456 7890 1234 5678 9012 3456 '.repeat(20);
      const start = performance.now();
      detectPII(adversarial, { types: ['credit_card'] });
      const elapsed = performance.now() - start;
      expect(elapsed).toBeLessThan(100);
    });

    it('credit card regex does not hang on digits-only non-matching input', () => {
      const adversarial = '1'.repeat(1000) + 'X';
      const start = performance.now();
      detectPII(adversarial, { types: ['credit_card'] });
      const elapsed = performance.now() - start;
      expect(elapsed).toBeLessThan(100);
    });

    it('input length is capped to prevent DoS', () => {
      const huge = 'a@b.com '.repeat(200000);
      const start = performance.now();
      const result = detectPII(huge);
      const elapsed = performance.now() - start;
      expect(elapsed).toBeLessThan(5000);
      expect(result.length).toBeGreaterThan(0);
    });
  });

  // ── Edge cases ────────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('returns empty for empty string', () => {
      expect(detectPII('')).toHaveLength(0);
    });

    it('returns empty for text with no PII', () => {
      const result = detectPII('The quick brown fox jumps over the lazy dog');
      expect(result).toHaveLength(0);
    });

    it('handles very long text', () => {
      const text = 'x'.repeat(100000) + ' john@acme.com ' + 'x'.repeat(100000);
      const result = detectPII(text);
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('email');
    });

    it('provides correct start/end positions', () => {
      const text = 'prefix john@acme.com suffix';
      const result = detectPII(text);
      expect(result[0].start).toBe(7);
      expect(result[0].end).toBe(20); // 7 + 'john@acme.com'.length (13)
      expect(text.slice(result[0].start, result[0].end)).toBe('john@acme.com');
    });
  });

  // ── mergeDetections ───────────────────────────────────────────────────────

  describe('mergeDetections', () => {
    it('merges detections from multiple sources', () => {
      const a: PIIDetection[] = [
        { type: 'email', value: 'a@b.com', start: 0, end: 7, confidence: 0.9 },
      ];
      const b: PIIDetection[] = [
        { type: 'ssn', value: '123-45-6789', start: 20, end: 31, confidence: 0.95 },
      ];
      const merged = mergeDetections(a, b);
      expect(merged).toHaveLength(2);
    });

    it('deduplicates overlapping detections keeping higher confidence', () => {
      const a: PIIDetection[] = [
        { type: 'phone', value: '5551234567', start: 5, end: 15, confidence: 0.7 },
      ];
      const b: PIIDetection[] = [
        { type: 'phone', value: '5551234567', start: 5, end: 15, confidence: 0.95 },
      ];
      const merged = mergeDetections(a, b);
      expect(merged).toHaveLength(1);
      expect(merged[0].confidence).toBe(0.95);
    });
  });

  // ── RegexPIIDetector provider ─────────────────────────────────────────────

  describe('RegexPIIDetector', () => {
    it('implements provider interface', () => {
      const detector = new RegexPIIDetector();
      expect(detector.name).toBe('regex');
      expect(detector.supportedTypes.length).toBeGreaterThan(0);
    });

    it('detect() works same as detectPII()', () => {
      const detector = new RegexPIIDetector();
      const result = detector.detect('Email: a@b.com');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('email');
    });
  });

  // ── International PII patterns ─────────────────────────────────────────────

  describe('international PII patterns', () => {
    // ── IBAN ──
    describe('iban', () => {
      it('detects German IBAN', () => {
        const result = detectPII('IBAN: DE89370400440532013000', { types: ['iban'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('iban');
        expect(result[0].confidence).toBe(0.9);
      });

      it('detects UK IBAN', () => {
        const result = detectPII('Pay to GB29NWBK60161331926819', { types: ['iban'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('iban');
      });

      it('does not match lowercase iban', () => {
        const result = detectPII('iban: de89370400440532013000', { types: ['iban'] });
        expect(result).toHaveLength(0);
      });
    });

    // ── NHS Number ──
    describe('nhs_number', () => {
      it('detects NHS number with spaces', () => {
        const result = detectPII('NHS: 943 476 5919', { types: ['nhs_number'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('nhs_number');
        expect(result[0].confidence).toBe(0.8);
      });

      it('detects NHS number without spaces', () => {
        const result = detectPII('NHS: 9434765919', { types: ['nhs_number'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('nhs_number');
      });

      it('rejects number that is not exactly 10 digits', () => {
        const result = detectPII('Code: 12345', { types: ['nhs_number'] });
        expect(result).toHaveLength(0);
      });
    });

    // ── UK NINO ──
    describe('uk_nino', () => {
      it('detects NINO with spaces', () => {
        const result = detectPII('NINO: AB 12 34 56 C', { types: ['uk_nino'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('uk_nino');
        expect(result[0].confidence).toBe(0.9);
      });

      it('detects NINO without spaces', () => {
        const result = detectPII('NINO: AB123456C', { types: ['uk_nino'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('uk_nino');
      });

      it('rejects invalid prefix letters', () => {
        // D and F are not allowed in first position
        const result = detectPII('NINO: DA123456C', { types: ['uk_nino'] });
        expect(result).toHaveLength(0);
      });
    });

    // ── Passport ──
    describe('passport', () => {
      it('detects US passport format', () => {
        const result = detectPII('Passport: C12345678', { types: ['passport'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('passport');
        expect(result[0].confidence).toBe(0.7);
      });

      it('detects UK passport format', () => {
        const result = detectPII('Passport: AB1234567', { types: ['passport'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('passport');
      });

      it('does not match too few digits', () => {
        const result = detectPII('Code: A12345', { types: ['passport'] });
        expect(result).toHaveLength(0);
      });
    });

    // ── Aadhaar ──
    describe('aadhaar', () => {
      it('detects Aadhaar with spaces', () => {
        const result = detectPII('Aadhaar: 2345 6789 0123', { types: ['aadhaar'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('aadhaar');
        expect(result[0].confidence).toBe(0.85);
      });

      it('detects Aadhaar without spaces', () => {
        const result = detectPII('Aadhaar: 234567890123', { types: ['aadhaar'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('aadhaar');
      });

      it('rejects number that is not exactly 12 digits', () => {
        const result = detectPII('Num: 12345678', { types: ['aadhaar'] });
        expect(result).toHaveLength(0);
      });
    });

    // ── EU Phone ──
    describe('eu_phone', () => {
      it('detects German phone', () => {
        const result = detectPII('Call +49 30 12345678', { types: ['eu_phone'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('eu_phone');
        expect(result[0].confidence).toBe(0.8);
      });

      it('detects French phone', () => {
        const result = detectPII('Call +33 1 23456789', { types: ['eu_phone'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('eu_phone');
      });

      it('does not match non-EU prefix', () => {
        const result = detectPII('Call +1 555 1234567', { types: ['eu_phone'] });
        expect(result).toHaveLength(0);
      });
    });

    // ── Medicare (AU) ──
    describe('medicare', () => {
      it('detects Medicare with spaces', () => {
        const result = detectPII('Medicare: 2123 45670 1', { types: ['medicare'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('medicare');
        expect(result[0].confidence).toBe(0.75);
      });

      it('detects Medicare without spaces', () => {
        const result = detectPII('Medicare: 2123456701', { types: ['medicare'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('medicare');
      });

      it('does not match too few digits', () => {
        const result = detectPII('Code: 12345', { types: ['medicare'] });
        expect(result).toHaveLength(0);
      });
    });

    // ── Drivers License (US) ──
    describe('drivers_license', () => {
      it('detects drivers license format', () => {
        const result = detectPII('DL: A123-4567-8901', { types: ['drivers_license'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('drivers_license');
        expect(result[0].confidence).toBe(0.75);
      });

      it('detects another drivers license', () => {
        const result = detectPII('License: B999-0000-1234', { types: ['drivers_license'] });
        expect(result).toHaveLength(1);
        expect(result[0].type).toBe('drivers_license');
      });

      it('does not match lowercase', () => {
        const result = detectPII('DL: a123-4567-8901', { types: ['drivers_license'] });
        expect(result).toHaveLength(0);
      });
    });
  });

  // ── False positive prevention (positive context checks) ─────────────────────

  describe('false positive prevention', () => {
    // ── Phone ──
    describe('phone context', () => {
      it('does NOT detect bare digits without phone context', () => {
        const result = detectPII('order number 5551234567');
        const phones = result.filter((d) => d.type === 'phone');
        expect(phones).toHaveLength(0);
      });

      it('does NOT detect bare digits with generic context', () => {
        const result = detectPII('The code is 5551234567 here');
        const phones = result.filter((d) => d.type === 'phone');
        expect(phones).toHaveLength(0);
      });

      it('DOES detect bare digits with "call" context', () => {
        const result = detectPII('call 5551234567');
        const phones = result.filter((d) => d.type === 'phone');
        expect(phones).toHaveLength(1);
      });

      it('DOES detect bare digits with "phone" context', () => {
        const result = detectPII('my phone 5551234567');
        const phones = result.filter((d) => d.type === 'phone');
        expect(phones).toHaveLength(1);
      });

      it('DOES detect bare digits with "mobile" context', () => {
        const result = detectPII('mobile: 5551234567');
        const phones = result.filter((d) => d.type === 'phone');
        expect(phones).toHaveLength(1);
      });

      it('DOES detect bare digits with "tel" context', () => {
        const result = detectPII('tel: 5551234567');
        const phones = result.filter((d) => d.type === 'phone');
        expect(phones).toHaveLength(1);
      });

      it('DOES detect formatted phone regardless of context', () => {
        const result = detectPII('order 555-123-4567');
        const phones = result.filter((d) => d.type === 'phone');
        expect(phones).toHaveLength(1);
      });

      it('DOES detect phone with parens regardless of context', () => {
        const result = detectPII('ref (555) 123-4567');
        const phones = result.filter((d) => d.type === 'phone');
        expect(phones).toHaveLength(1);
      });

      it('DOES detect phone with dots regardless of context', () => {
        const result = detectPII('number 555.123.4567');
        const phones = result.filter((d) => d.type === 'phone');
        expect(phones).toHaveLength(1);
      });
    });

    // ── SSN ──
    describe('ssn context', () => {
      it('does NOT detect bare 9 digits without SSN context', () => {
        const result = detectPII('reference number 123456789');
        const ssns = result.filter((d) => d.type === 'ssn');
        expect(ssns).toHaveLength(0);
      });

      it('DOES detect bare 9 digits with SSN context', () => {
        const result = detectPII('SSN: 123456789');
        const ssns = result.filter((d) => d.type === 'ssn');
        expect(ssns).toHaveLength(1);
      });

      it('DOES detect bare 9 digits with social security context', () => {
        const result = detectPII('social security 123456789');
        const ssns = result.filter((d) => d.type === 'ssn');
        expect(ssns).toHaveLength(1);
      });

      it('DOES detect SSN with dashes regardless of context', () => {
        const result = detectPII('ref 123-45-6789');
        const ssns = result.filter((d) => d.type === 'ssn');
        expect(ssns).toHaveLength(1);
      });
    });

    // ── Date of Birth ──
    describe('dob context', () => {
      it('does NOT detect date without birth context', () => {
        const result = detectPII('meeting on 03/15/2026');
        const dobs = result.filter((d) => d.type === 'date_of_birth');
        expect(dobs).toHaveLength(0);
      });

      it('does NOT detect date in generic context', () => {
        const result = detectPII('invoice dated 01/15/1990');
        const dobs = result.filter((d) => d.type === 'date_of_birth');
        expect(dobs).toHaveLength(0);
      });

      it('DOES detect date with "born" context', () => {
        const result = detectPII('born 03/15/1990');
        const dobs = result.filter((d) => d.type === 'date_of_birth');
        expect(dobs).toHaveLength(1);
      });

      it('DOES detect date with "DOB" context', () => {
        const result = detectPII('DOB: 03/15/1990');
        const dobs = result.filter((d) => d.type === 'date_of_birth');
        expect(dobs).toHaveLength(1);
      });

      it('DOES detect date with "birthday" context', () => {
        const result = detectPII('birthday: 12-25-2000');
        const dobs = result.filter((d) => d.type === 'date_of_birth');
        expect(dobs).toHaveLength(1);
      });
    });

    // ── Passport ──
    describe('passport context', () => {
      it('does NOT detect alphanumeric code without passport context', () => {
        const result = detectPII('product AB123456');
        const passports = result.filter((d) => d.type === 'passport');
        expect(passports).toHaveLength(0);
      });

      it('does NOT detect model number as passport', () => {
        const result = detectPII('model C12345678');
        const passports = result.filter((d) => d.type === 'passport');
        expect(passports).toHaveLength(0);
      });

      it('DOES detect with passport context', () => {
        const result = detectPII('passport C12345678');
        const passports = result.filter((d) => d.type === 'passport');
        expect(passports).toHaveLength(1);
      });

      it('DOES detect with passport: prefix', () => {
        const result = detectPII('Passport: AB1234567');
        const passports = result.filter((d) => d.type === 'passport');
        expect(passports).toHaveLength(1);
      });
    });

    // ── IP Address ──
    describe('ip context', () => {
      it('does NOT detect version number as IP', () => {
        const result = detectPII('version 1.2.3.4');
        const ips = result.filter((d) => d.type === 'ip_address');
        expect(ips).toHaveLength(0);
      });

      it('does NOT detect semver with v prefix as IP', () => {
        const result = detectPII('v1.2.3.4');
        const ips = result.filter((d) => d.type === 'ip_address');
        expect(ips).toHaveLength(0);
      });

      it('does NOT detect version with @ prefix as IP', () => {
        const result = detectPII('package@1.2.3.4');
        const ips = result.filter((d) => d.type === 'ip_address');
        expect(ips).toHaveLength(0);
      });

      it('does NOT detect version with -beta suffix as IP', () => {
        const result = detectPII('release 2.0.0.1-beta');
        const ips = result.filter((d) => d.type === 'ip_address');
        expect(ips).toHaveLength(0);
      });

      it('filters private range 10.x.x.x', () => {
        const result = detectPII('connect to 10.1.2.3');
        const ips = result.filter((d) => d.type === 'ip_address');
        expect(ips).toHaveLength(0);
      });

      it('filters private range 172.16.x.x', () => {
        const result = detectPII('host 172.16.0.1');
        const ips = result.filter((d) => d.type === 'ip_address');
        expect(ips).toHaveLength(0);
      });

      it('filters documentation range 203.0.113.x', () => {
        const result = detectPII('example 203.0.113.42');
        const ips = result.filter((d) => d.type === 'ip_address');
        expect(ips).toHaveLength(0);
      });

      it('DOES detect public IP without version context', () => {
        const result = detectPII('server at 85.12.45.78');
        const ips = result.filter((d) => d.type === 'ip_address');
        expect(ips).toHaveLength(1);
      });
    });

    // ── NHS Number ──
    describe('nhs context', () => {
      it('does NOT detect bare 10 digits without NHS context', () => {
        const result = detectPII('account 9434765919');
        const nhs = result.filter((d) => d.type === 'nhs_number');
        expect(nhs).toHaveLength(0);
      });

      it('DOES detect with NHS context', () => {
        const result = detectPII('NHS: 9434765919');
        const nhs = result.filter((d) => d.type === 'nhs_number');
        expect(nhs).toHaveLength(1);
      });

      it('DOES detect formatted NHS regardless of context', () => {
        const result = detectPII('ref 943 476 5919', { types: ['nhs_number'] });
        const nhs = result.filter((d) => d.type === 'nhs_number');
        expect(nhs).toHaveLength(1);
      });
    });

    // ── Aadhaar ──
    describe('aadhaar context', () => {
      it('does NOT detect bare 12 digits without Aadhaar context', () => {
        const result = detectPII('serial 234567890123');
        const aadhaar = result.filter((d) => d.type === 'aadhaar');
        expect(aadhaar).toHaveLength(0);
      });

      it('DOES detect with Aadhaar context', () => {
        const result = detectPII('Aadhaar: 234567890123');
        const aadhaar = result.filter((d) => d.type === 'aadhaar');
        expect(aadhaar).toHaveLength(1);
      });

      it('DOES detect formatted Aadhaar regardless of context', () => {
        const result = detectPII('id 2345 6789 0123');
        const aadhaar = result.filter((d) => d.type === 'aadhaar');
        expect(aadhaar).toHaveLength(1);
      });
    });

    // ── Medicare ──
    describe('medicare context', () => {
      it('does NOT detect bare 10 digits without Medicare context', () => {
        const result = detectPII('ref 2123456701');
        const medicare = result.filter((d) => d.type === 'medicare');
        expect(medicare).toHaveLength(0);
      });

      it('DOES detect with Medicare context', () => {
        const result = detectPII('Medicare: 2123456701');
        const medicare = result.filter((d) => d.type === 'medicare');
        expect(medicare).toHaveLength(1);
      });

      it('DOES detect formatted Medicare regardless of context', () => {
        const result = detectPII('ref 2123 45670 1');
        const medicare = result.filter((d) => d.type === 'medicare');
        expect(medicare).toHaveLength(1);
      });
    });
  });

  // ── Custom PII Pattern Registration ─────────────────────────────────────────

  describe('createCustomDetector', () => {
    it('detects custom employee_id pattern', async () => {
      const patterns: CustomPIIPattern[] = [
        {
          name: 'Employee ID',
          type: 'employee_id',
          pattern: /EMP-\d{6}/,
          confidence: 0.9,
        },
      ];
      const detector = createCustomDetector(patterns);
      expect(detector.name).toBe('custom');

      const result = await Promise.resolve(detector.detect('Employee EMP-123456 is on leave'));
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('employee_id');
      expect(result[0].value).toBe('EMP-123456');
      expect(result[0].confidence).toBe(0.9);
    });

    it('uses default confidence when not provided', async () => {
      const patterns: CustomPIIPattern[] = [
        {
          name: 'Internal ID',
          type: 'internal_id',
          pattern: /INT-\d{4}/,
        },
      ];
      const detector = createCustomDetector(patterns);
      const result = await Promise.resolve(detector.detect('Ref INT-9999'));
      expect(result).toHaveLength(1);
      expect(result[0].confidence).toBe(0.8);
    });

    it('detects multiple custom patterns', async () => {
      const patterns: CustomPIIPattern[] = [
        { name: 'Emp ID', type: 'employee_id', pattern: /EMP-\d{6}/, confidence: 0.9 },
        { name: 'Badge', type: 'badge_number', pattern: /BADGE-[A-Z]{2}\d{4}/, confidence: 0.85 },
      ];
      const detector = createCustomDetector(patterns);
      const result = await Promise.resolve(detector.detect('EMP-123456 has BADGE-AB1234'));
      expect(result).toHaveLength(2);
      expect(result[0].type).toBe('employee_id');
      expect(result[1].type).toBe('badge_number');
    });

    it('returns empty for non-matching text', async () => {
      const patterns: CustomPIIPattern[] = [
        { name: 'Emp ID', type: 'employee_id', pattern: /EMP-\d{6}/ },
      ];
      const detector = createCustomDetector(patterns);
      const result = await Promise.resolve(detector.detect('No employee ids here'));
      expect(result).toHaveLength(0);
    });

    it('respects type filtering', async () => {
      const patterns: CustomPIIPattern[] = [
        { name: 'Emp ID', type: 'employee_id', pattern: /EMP-\d{6}/ },
        { name: 'Badge', type: 'badge_number', pattern: /BADGE-[A-Z]{2}\d{4}/ },
      ];
      const detector = createCustomDetector(patterns);
      const result = await Promise.resolve(detector.detect('EMP-123456 has BADGE-AB1234', {
        types: ['employee_id' as any],
      }));
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('employee_id');
    });
  });

  // ── Allow list ──────────────────────────────────────────────────────────

  describe('allow list', () => {
    it('filters out exact matches (normalized)', () => {
      const detections = detectPII('Call us at 555-123-4567');
      const filtered = filterAllowList(detections, ['555-123-4567']);
      expect(filtered).toHaveLength(0);
    });

    it('matches with different formatting', () => {
      const detections = detectPII('Call us at 555-123-4567');
      // Allow list entry without dashes
      const filtered = filterAllowList(detections, ['5551234567']);
      expect(filtered).toHaveLength(0);
    });

    it('keeps detections not in allow list', () => {
      const detections = detectPII('Call 555-123-4567 or 555-987-6543');
      const filtered = filterAllowList(detections, ['5551234567']);
      const phones = filtered.filter((d) => d.type === 'phone');
      expect(phones.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Confidence thresholds ───────────────────────────────────────────────

  describe('confidence thresholds', () => {
    it('filters detections below threshold', () => {
      const detections = detectPII('Call 555-123-4567');
      // Set threshold very high
      const filtered = filterByConfidence(detections, { phone: 0.99 });
      const phones = filtered.filter((d) => d.type === 'phone');
      expect(phones).toHaveLength(0);
    });

    it('keeps detections above threshold', () => {
      const detections = detectPII('test@example.com');
      const filtered = filterByConfidence(detections, { email: 0.5 });
      expect(filtered.filter((d) => d.type === 'email')).toHaveLength(1);
    });

    it('does not affect types without a threshold', () => {
      const detections = detectPII('test@example.com and 555-123-4567');
      // Only set threshold for phone, email should pass through
      const filtered = filterByConfidence(detections, { phone: 0.99 });
      expect(filtered.filter((d) => d.type === 'email')).toHaveLength(1);
    });
  });

  // ── Suppressive context ─────────────────────────────────────────────────

  describe('suppressive context', () => {
    it('reduces phone confidence near business terms', () => {
      const text = 'Order tracking 555-123-4567';
      const detections = detectPII(text);
      const phone = detections.find((d) => d.type === 'phone');
      if (phone) {
        const suppressed = applySuppressiveContext(phone, text);
        expect(suppressed.confidence).toBeLessThan(phone.confidence);
      }
    });

    it('does not reduce confidence without business terms nearby', () => {
      const text = 'My number is 555-123-4567';
      const detections = detectPII(text);
      const phone = detections.find((d) => d.type === 'phone');
      if (phone) {
        const result = applySuppressiveContext(phone, text);
        expect(result.confidence).toBe(phone.confidence);
      }
    });

    it('reduces SSN confidence near order-like terms', () => {
      const text = 'Serial number 123-45-6789';
      const detections = detectPII(text);
      const ssn = detections.find((d) => d.type === 'ssn');
      if (ssn) {
        const suppressed = applySuppressiveContext(ssn, text);
        expect(suppressed.confidence).toBeLessThan(ssn.confidence);
      }
    });

    it('combined: suppressive context + threshold filters out FP', () => {
      const text = 'Order tracking 555-123-4567';
      let detections = detectPII(text);
      detections = detections.map((d) => applySuppressiveContext(d, text));
      detections = filterByConfidence(detections, { phone: 0.7 });
      const phones = detections.filter((d) => d.type === 'phone');
      expect(phones).toHaveLength(0);
    });
  });
});
