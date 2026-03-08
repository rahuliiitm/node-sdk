/**
 * Invisible Unicode & encoding attack detection module.
 * Detects and optionally strips malicious Unicode characters used in LLM attacks.
 * @internal
 */

// ── Interfaces ───────────────────────────────────────────────────────────────

export const MAX_SCAN_LENGTH = 1024 * 1024; // 1MB

export interface UnicodeSanitizeOptions {
  /** Action to take when threats are found (default: 'strip') */
  action?: 'strip' | 'warn' | 'block';
  /** Whether to detect mixed-script homoglyphs (default: true) */
  detectHomoglyphs?: boolean;
}

export interface UnicodeScanResult {
  found: boolean;
  threats: UnicodeThreat[];
  sanitizedText?: string;
}

export interface UnicodeThreat {
  type: 'zero_width' | 'bidi_override' | 'tag_char' | 'homoglyph' | 'variation_selector';
  position: number;
  char: string;
  codePoint: string; // e.g. "U+200B"
}

// ── Cyrillic → Latin homoglyph map ──────────────────────────────────────────

const CYRILLIC_TO_LATIN: Record<string, string> = {
  '\u0430': 'a', // а → a
  '\u0435': 'e', // е → e
  '\u043E': 'o', // о → o
  '\u0441': 'c', // с → c
  '\u0440': 'p', // р → p
  '\u0443': 'y', // у → y
  '\u0445': 'x', // х → x
  '\u0412': 'B', // В → B
  '\u041D': 'H', // Н → H
  '\u041A': 'K', // К → K
  '\u041C': 'M', // М → M
  '\u0422': 'T', // Т → T
  '\u0410': 'A', // А → A
  '\u0415': 'E', // Е → E
  '\u041E': 'O', // О → O
  '\u0421': 'C', // С → C
  '\u0420': 'P', // Р → P
};

// ── Regex patterns for threat categories ────────────────────────────────────

const ZERO_WIDTH_RE = /[\u200B\u200C\u200D\uFEFF\u2060\u00AD]/;
const BIDI_OVERRIDE_RE = /[\u202A-\u202E\u2066-\u2069]/;
const TAG_CHAR_RE = /[\u{E0001}-\u{E007F}]/u;
const VARIATION_SELECTOR_RE = /[\uFE00-\uFE0F]/;

const LATIN_RE = /[a-zA-Z]/;
const CYRILLIC_RE = /[\u0400-\u04FF]/;

// ── Helpers ─────────────────────────────────────────────────────────────────

function toCodePoint(char: string): string {
  const cp = char.codePointAt(0)!;
  return 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');
}

// ── Detection ───────────────────────────────────────────────────────────────

/**
 * Scan text for malicious Unicode characters.
 * Returns detected threats and optionally a sanitized version of the text.
 * Text longer than 1MB is truncated before scanning.
 */
export function scanUnicode(
  text: string,
  options?: UnicodeSanitizeOptions,
): UnicodeScanResult {
  const action = options?.action ?? 'strip';
  const detectHomoglyphs = options?.detectHomoglyphs ?? true;

  if (!text) {
    return { found: false, threats: [] };
  }

  // Cap input length to prevent DoS
  const scanText = text.length > MAX_SCAN_LENGTH ? text.slice(0, MAX_SCAN_LENGTH) : text;

  const threats: UnicodeThreat[] = [];

  // Single-character threat detection: iterate through every code point
  for (let i = 0; i < scanText.length; i++) {
    const char = scanText[i];

    // Handle surrogate pairs for tag characters (astral plane)
    if (i < scanText.length - 1) {
      const cp = scanText.codePointAt(i)!;
      if (cp >= 0xE0001 && cp <= 0xE007F) {
        const fullChar = String.fromCodePoint(cp);
        threats.push({ type: 'tag_char', position: i, char: fullChar, codePoint: toCodePoint(fullChar) });
        i++; // skip surrogate pair low half
        continue;
      }
    }

    if (ZERO_WIDTH_RE.test(char)) {
      threats.push({ type: 'zero_width', position: i, char, codePoint: toCodePoint(char) });
    } else if (BIDI_OVERRIDE_RE.test(char)) {
      threats.push({ type: 'bidi_override', position: i, char, codePoint: toCodePoint(char) });
    } else if (VARIATION_SELECTOR_RE.test(char)) {
      threats.push({ type: 'variation_selector', position: i, char, codePoint: toCodePoint(char) });
    }
  }

  // Homoglyph detection: check each word for mixed Cyrillic + Latin
  if (detectHomoglyphs) {
    const words = scanText.split(/\s+/);
    let pos = 0;
    for (const word of words) {
      // Find actual position of this word in the scan text
      const wordStart = scanText.indexOf(word, pos);
      if (wordStart === -1) {
        pos += word.length + 1;
        continue;
      }

      const hasLatin = LATIN_RE.test(word);
      const hasCyrillic = CYRILLIC_RE.test(word);

      if (hasLatin && hasCyrillic) {
        // Flag each Cyrillic char within this mixed-script word
        for (let j = 0; j < word.length; j++) {
          const ch = word[j];
          if (CYRILLIC_RE.test(ch)) {
            threats.push({
              type: 'homoglyph',
              position: wordStart + j,
              char: ch,
              codePoint: toCodePoint(ch),
            });
          }
        }
      }

      pos = wordStart + word.length;
    }
  }

  // Sort threats by position for deterministic output
  threats.sort((a, b) => a.position - b.position);

  const found = threats.length > 0;

  // Build sanitized text only for 'strip' action
  let sanitizedText: string | undefined;
  if (action === 'strip' && found) {
    // Build a set of positions to remove (non-homoglyph threats)
    const removePositions = new Set<number>();
    const homoglyphReplacements = new Map<number, string>();

    for (const threat of threats) {
      if (threat.type === 'homoglyph') {
        const replacement = CYRILLIC_TO_LATIN[threat.char];
        if (replacement) {
          homoglyphReplacements.set(threat.position, replacement);
        }
      } else if (threat.type === 'tag_char') {
        // Tag chars are surrogate pairs — mark both positions
        removePositions.add(threat.position);
        removePositions.add(threat.position + 1);
      } else {
        removePositions.add(threat.position);
      }
    }

    const chars: string[] = [];
    for (let i = 0; i < scanText.length; i++) {
      if (removePositions.has(i)) {
        continue;
      }
      const replacement = homoglyphReplacements.get(i);
      if (replacement !== undefined) {
        chars.push(replacement);
      } else {
        chars.push(scanText[i]);
      }
    }
    sanitizedText = chars.join('');
  }

  return { found, threats, sanitizedText };
}
