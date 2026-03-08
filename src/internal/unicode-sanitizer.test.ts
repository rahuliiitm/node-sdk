import { scanUnicode, MAX_SCAN_LENGTH } from './unicode-sanitizer';

describe('Unicode Sanitizer', () => {
  // ── Zero-width characters ──────────────────────────────────────────────────

  describe('zero_width', () => {
    it('detects zero-width space (U+200B)', () => {
      const result = scanUnicode('hello\u200Bworld');
      expect(result.found).toBe(true);
      expect(result.threats).toHaveLength(1);
      expect(result.threats[0].type).toBe('zero_width');
      expect(result.threats[0].codePoint).toBe('U+200B');
      expect(result.threats[0].position).toBe(5);
    });

    it('detects ZWNJ (U+200C)', () => {
      const result = scanUnicode('test\u200Cvalue');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('zero_width');
      expect(result.threats[0].codePoint).toBe('U+200C');
    });

    it('detects ZWJ (U+200D)', () => {
      const result = scanUnicode('ab\u200Dcd');
      expect(result.found).toBe(true);
      expect(result.threats[0].codePoint).toBe('U+200D');
    });

    it('detects BOM (U+FEFF)', () => {
      const result = scanUnicode('\uFEFFsome text');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('zero_width');
      expect(result.threats[0].codePoint).toBe('U+FEFF');
    });

    it('detects word joiner (U+2060)', () => {
      const result = scanUnicode('word\u2060joiner');
      expect(result.found).toBe(true);
      expect(result.threats[0].codePoint).toBe('U+2060');
    });

    it('detects soft hyphen (U+00AD)', () => {
      const result = scanUnicode('soft\u00ADhyphen');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('zero_width');
      expect(result.threats[0].codePoint).toBe('U+00AD');
    });

    it('strips zero-width characters with action=strip', () => {
      const result = scanUnicode('he\u200Bl\u200Clo', { action: 'strip' });
      expect(result.found).toBe(true);
      expect(result.sanitizedText).toBe('hello');
    });

    it('detects multiple zero-width chars in same input', () => {
      const result = scanUnicode('\u200B\u200C\u200D');
      expect(result.threats).toHaveLength(3);
      expect(result.threats.every((t) => t.type === 'zero_width')).toBe(true);
    });
  });

  // ── Bidi overrides ─────────────────────────────────────────────────────────

  describe('bidi_override', () => {
    it('detects LRE (U+202A)', () => {
      const result = scanUnicode('text\u202Awith bidi');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('bidi_override');
      expect(result.threats[0].codePoint).toBe('U+202A');
    });

    it('detects RLO (U+202E)', () => {
      const result = scanUnicode('reversed\u202E text');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('bidi_override');
      expect(result.threats[0].codePoint).toBe('U+202E');
    });

    it('detects LRI (U+2066)', () => {
      const result = scanUnicode('isolated\u2066lri');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('bidi_override');
      expect(result.threats[0].codePoint).toBe('U+2066');
    });

    it('detects PDI (U+2069)', () => {
      const result = scanUnicode('pop\u2069direction');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('bidi_override');
      expect(result.threats[0].codePoint).toBe('U+2069');
    });

    it('strips bidi overrides with action=strip', () => {
      const result = scanUnicode('ab\u202Ecd\u2066ef', { action: 'strip' });
      expect(result.sanitizedText).toBe('abcdef');
    });
  });

  // ── Tag characters ─────────────────────────────────────────────────────────

  describe('tag_char', () => {
    it('detects tag characters (U+E0001)', () => {
      const tagChar = String.fromCodePoint(0xE0001);
      const result = scanUnicode('text' + tagChar + 'more');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('tag_char');
      expect(result.threats[0].codePoint).toBe('U+E0001');
    });

    it('detects tag character U+E0041 (TAG LATIN CAPITAL LETTER A)', () => {
      const tagA = String.fromCodePoint(0xE0041);
      const result = scanUnicode('hello' + tagA + 'world');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('tag_char');
      expect(result.threats[0].codePoint).toBe('U+E0041');
    });

    it('strips tag characters with action=strip', () => {
      const tag = String.fromCodePoint(0xE0020);
      const result = scanUnicode('ab' + tag + 'cd', { action: 'strip' });
      expect(result.found).toBe(true);
      expect(result.sanitizedText).toBe('abcd');
    });
  });

  // ── Homoglyphs (mixed Cyrillic/Latin) ──────────────────────────────────────

  describe('homoglyph', () => {
    it('detects Cyrillic "а" (U+0430) mixed with Latin in same word', () => {
      // "hello" with Cyrillic 'а' replacing Latin 'a' → "hеllo" won't work, use "c\u0430t" (cat with Cyrillic а)
      const result = scanUnicode('c\u0430t');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('homoglyph');
      expect(result.threats[0].codePoint).toBe('U+0430');
    });

    it('detects Cyrillic "е" (U+0435) mixed with Latin', () => {
      const result = scanUnicode('h\u0435llo');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('homoglyph');
      expect(result.threats[0].codePoint).toBe('U+0435');
    });

    it('detects Cyrillic "о" (U+043E) mixed with Latin', () => {
      const result = scanUnicode('w\u043Erld');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('homoglyph');
      expect(result.threats[0].codePoint).toBe('U+043E');
    });

    it('detects multiple Cyrillic chars in single word', () => {
      // "hello" with Cyrillic е and о
      const result = scanUnicode('h\u0435ll\u043E');
      expect(result.found).toBe(true);
      expect(result.threats).toHaveLength(2);
      expect(result.threats[0].type).toBe('homoglyph');
      expect(result.threats[1].type).toBe('homoglyph');
    });

    it('does NOT flag purely Cyrillic words', () => {
      // "привет" is entirely Cyrillic, no Latin mixed in
      const result = scanUnicode('привет мир');
      expect(result.found).toBe(false);
    });

    it('does NOT flag purely Latin words', () => {
      const result = scanUnicode('hello world');
      expect(result.found).toBe(false);
    });

    it('replaces homoglyphs with Latin equivalents when stripping', () => {
      const result = scanUnicode('c\u0430t', { action: 'strip' });
      expect(result.sanitizedText).toBe('cat');
    });
  });

  // ── Variation selectors ────────────────────────────────────────────────────

  describe('variation_selector', () => {
    it('detects VS1 (U+FE00)', () => {
      const result = scanUnicode('text\uFE00here');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('variation_selector');
      expect(result.threats[0].codePoint).toBe('U+FE00');
    });

    it('detects VS16 (U+FE0F)', () => {
      const result = scanUnicode('emoji\uFE0Ftest');
      expect(result.found).toBe(true);
      expect(result.threats[0].type).toBe('variation_selector');
      expect(result.threats[0].codePoint).toBe('U+FE0F');
    });

    it('strips variation selectors with action=strip', () => {
      const result = scanUnicode('ab\uFE0Fcd', { action: 'strip' });
      expect(result.sanitizedText).toBe('abcd');
    });
  });

  // ── Clean text ─────────────────────────────────────────────────────────────

  describe('clean text', () => {
    it('returns found=false for normal ASCII text', () => {
      const result = scanUnicode('Hello, this is perfectly normal text.');
      expect(result.found).toBe(false);
      expect(result.threats).toHaveLength(0);
    });

    it('returns found=false for accented characters', () => {
      const result = scanUnicode('The café serves résumé reviews');
      expect(result.found).toBe(false);
    });

    it('returns found=false for CJK text', () => {
      const result = scanUnicode('こんにちは世界');
      expect(result.found).toBe(false);
    });
  });

  // ── Action modes ───────────────────────────────────────────────────────────

  describe('action modes', () => {
    it('strip action removes chars and provides sanitizedText', () => {
      const result = scanUnicode('he\u200Bllo\u200C world', { action: 'strip' });
      expect(result.found).toBe(true);
      expect(result.sanitizedText).toBe('hello world');
    });

    it('warn action keeps text unchanged (no sanitizedText)', () => {
      const result = scanUnicode('he\u200Bllo', { action: 'warn' });
      expect(result.found).toBe(true);
      expect(result.sanitizedText).toBeUndefined();
    });

    it('block action keeps text unchanged (no sanitizedText)', () => {
      const result = scanUnicode('he\u200Bllo', { action: 'block' });
      expect(result.found).toBe(true);
      expect(result.sanitizedText).toBeUndefined();
    });

    it('defaults to strip action', () => {
      const result = scanUnicode('he\u200Bllo');
      expect(result.sanitizedText).toBe('hello');
    });
  });

  // ── Multiple threat types ──────────────────────────────────────────────────

  describe('multiple threat types', () => {
    it('detects multiple threat types in single input', () => {
      // Zero-width + bidi + homoglyph
      const input = '\u200Bh\u0435llo\u202E world';
      const result = scanUnicode(input);
      expect(result.found).toBe(true);

      const types = new Set(result.threats.map((t) => t.type));
      expect(types.has('zero_width')).toBe(true);
      expect(types.has('homoglyph')).toBe(true);
      expect(types.has('bidi_override')).toBe(true);
    });

    it('strips all threat types simultaneously', () => {
      const input = '\u200Bh\u0435llo\u202E';
      const result = scanUnicode(input, { action: 'strip' });
      expect(result.sanitizedText).toBe('hello');
    });
  });

  // ── detectHomoglyphs option ────────────────────────────────────────────────

  describe('detectHomoglyphs option', () => {
    it('skips homoglyph detection when disabled', () => {
      const result = scanUnicode('c\u0430t', { detectHomoglyphs: false });
      expect(result.found).toBe(false);
      expect(result.threats).toHaveLength(0);
    });

    it('still detects other threats when homoglyphs disabled', () => {
      const result = scanUnicode('c\u0430t\u200B', { detectHomoglyphs: false });
      expect(result.found).toBe(true);
      expect(result.threats).toHaveLength(1);
      expect(result.threats[0].type).toBe('zero_width');
    });
  });

  // ── Edge cases ─────────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('handles empty string', () => {
      const result = scanUnicode('');
      expect(result.found).toBe(false);
      expect(result.threats).toHaveLength(0);
    });

    it('handles input exceeding MAX_SCAN_LENGTH', () => {
      const huge = 'a'.repeat(MAX_SCAN_LENGTH + 1000) + '\u200B';
      const result = scanUnicode(huge);
      // The zero-width char is beyond the truncation point, so not detected
      expect(result.found).toBe(false);
    });

    it('threats are sorted by position', () => {
      const result = scanUnicode('\u200Bhello\u200C world\u200D');
      expect(result.threats).toHaveLength(3);
      for (let i = 1; i < result.threats.length; i++) {
        expect(result.threats[i].position).toBeGreaterThan(result.threats[i - 1].position);
      }
    });

    it('handles input with only threat characters', () => {
      const result = scanUnicode('\u200B\u200C\u200D');
      expect(result.found).toBe(true);
      expect(result.threats).toHaveLength(3);
      expect(result.sanitizedText).toBe('');
    });

    it('handles large input without hanging (DoS prevention)', () => {
      const large = ('normal text \u200B ').repeat(10000);
      const start = performance.now();
      const result = scanUnicode(large);
      const elapsed = performance.now() - start;
      expect(elapsed).toBeLessThan(5000);
      expect(result.found).toBe(true);
    });
  });
});
