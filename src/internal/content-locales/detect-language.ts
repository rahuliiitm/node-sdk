/**
 * Lightweight language detection — zero dependencies.
 * Uses Unicode script ranges and stop-word frequency for Latin scripts.
 * @internal
 */

export interface LanguageDetection {
  language: string;
  confidence: number;
}

// ── Script-based detection (CJK, Arabic, Devanagari, Cyrillic, Hangul) ─────

const SCRIPT_RANGES: Array<{ regex: RegExp; language: string }> = [
  { regex: /[\u3040-\u309f]/g, language: 'ja' },   // Hiragana → Japanese
  { regex: /[\u30a0-\u30ff]/g, language: 'ja' },   // Katakana → Japanese
  { regex: /[\uac00-\ud7af]/g, language: 'ko' },   // Hangul → Korean
  { regex: /[\u0600-\u06ff]/g, language: 'ar' },   // Arabic
  { regex: /[\u0900-\u097f]/g, language: 'hi' },   // Devanagari → Hindi
  { regex: /[\u0400-\u04ff]/g, language: 'ru' },   // Cyrillic → Russian
  { regex: /[\u4e00-\u9fff]/g, language: 'zh' },   // CJK Unified → Chinese
];

// ── Stop-word frequency for Latin-script languages ─────────────────────────

const STOP_WORDS: Record<string, Set<string>> = {
  en: new Set(['the', 'is', 'at', 'which', 'on', 'and', 'or', 'but', 'this', 'that', 'with', 'for', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one']),
  es: new Set(['el', 'la', 'los', 'las', 'un', 'una', 'es', 'en', 'por', 'con', 'del', 'que', 'para', 'como', 'pero', 'más', 'este', 'esta', 'son', 'no']),
  pt: new Set(['o', 'a', 'os', 'as', 'um', 'uma', 'em', 'de', 'do', 'da', 'que', 'com', 'para', 'por', 'não', 'mais', 'como', 'seu', 'sua', 'dos']),
  de: new Set(['der', 'die', 'das', 'ein', 'eine', 'ist', 'und', 'oder', 'aber', 'mit', 'für', 'auf', 'von', 'den', 'dem', 'des', 'sich', 'nicht', 'aus', 'auch']),
  fr: new Set(['le', 'la', 'les', 'un', 'une', 'est', 'et', 'ou', 'mais', 'avec', 'pour', 'dans', 'sur', 'par', 'pas', 'que', 'qui', 'son', 'ses', 'des']),
};

/**
 * Detect the dominant language of a text.
 * Returns 'unknown' for text under 10 chars.
 */
export function detectLanguage(text: string): LanguageDetection {
  if (!text || text.length < 10) {
    return { language: 'unknown', confidence: 0 };
  }

  // Try script-based detection first
  let bestScript = '';
  let bestCount = 0;
  const totalChars = text.replace(/\s/g, '').length;

  for (const { regex, language } of SCRIPT_RANGES) {
    regex.lastIndex = 0;
    const matches = text.match(regex);
    const count = matches ? matches.length : 0;
    if (count > bestCount) {
      bestCount = count;
      bestScript = language;
    }
  }

  // If >30% of non-whitespace chars are in a script, it's that language
  if (bestCount > 0 && totalChars > 0 && bestCount / totalChars > 0.3) {
    return {
      language: bestScript,
      confidence: Math.min(bestCount / totalChars, 1),
    };
  }

  // Fall back to stop-word frequency for Latin scripts
  const words = text.toLowerCase().split(/\s+/).filter((w) => w.length > 0);
  if (words.length < 3) return { language: 'unknown', confidence: 0 };

  let bestLang = 'en';
  let bestHits = 0;

  for (const [lang, stopWords] of Object.entries(STOP_WORDS)) {
    const hits = words.filter((w) => stopWords.has(w)).length;
    if (hits > bestHits) {
      bestHits = hits;
      bestLang = lang;
    }
  }

  const confidence = words.length > 0 ? Math.min(bestHits / words.length, 1) : 0;
  return {
    language: confidence > 0.05 ? bestLang : 'unknown',
    confidence,
  };
}
