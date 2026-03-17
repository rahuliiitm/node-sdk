/**
 * PII locale registry — lazy loading of country-specific patterns.
 * @internal
 */

import type { LocalePIIPattern, PIILocale } from './types';
export type { LocalePIIPattern, PIILocale } from './types';
export { ALL_LOCALES } from './types';

// Lazy-loaded locale pattern cache
const _cache = new Map<string, LocalePIIPattern[]>();

function loadLocale(locale: PIILocale): LocalePIIPattern[] {
  if (_cache.has(locale)) return _cache.get(locale)!;

  let patterns: LocalePIIPattern[];
  switch (locale) {
    case 'ca': {
      const { CA_PII_PATTERNS } = require('./ca');
      patterns = CA_PII_PATTERNS;
      break;
    }
    case 'br': {
      const { BR_PII_PATTERNS } = require('./br');
      patterns = BR_PII_PATTERNS;
      break;
    }
    case 'cn': {
      const { CN_PII_PATTERNS } = require('./cn');
      patterns = CN_PII_PATTERNS;
      break;
    }
    case 'jp': {
      const { JP_PII_PATTERNS } = require('./jp');
      patterns = JP_PII_PATTERNS;
      break;
    }
    case 'kr': {
      const { KR_PII_PATTERNS } = require('./kr');
      patterns = KR_PII_PATTERNS;
      break;
    }
    case 'de': {
      const { DE_PII_PATTERNS } = require('./de');
      patterns = DE_PII_PATTERNS;
      break;
    }
    case 'mx': {
      const { MX_PII_PATTERNS } = require('./mx');
      patterns = MX_PII_PATTERNS;
      break;
    }
    case 'fr': {
      const { FR_PII_PATTERNS } = require('./fr');
      patterns = FR_PII_PATTERNS;
      break;
    }
    default:
      patterns = [];
  }

  _cache.set(locale, patterns);
  return patterns;
}

/**
 * Get PII patterns for specified locales.
 * @param locales - Array of locale codes, or 'all' for all supported locales.
 */
export function getLocalePatterns(locales: PIILocale[] | 'all'): LocalePIIPattern[] {
  const { ALL_LOCALES: all } = require('./types');
  const codes: PIILocale[] = locales === 'all' ? all : locales;
  const result: LocalePIIPattern[] = [];
  for (const code of codes) {
    result.push(...loadLocale(code));
  }
  return result;
}
