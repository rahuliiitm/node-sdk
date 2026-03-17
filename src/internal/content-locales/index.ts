/**
 * Content filter locale support — language detection + locale patterns.
 * @internal
 */

export { detectLanguage } from './detect-language';
export type { LanguageDetection } from './detect-language';
export type { LocaleContentPattern, ContentLocale } from './types';
export { ALL_CONTENT_LOCALES } from './types';
export { LOCALE_PATTERNS } from './locales';

import { detectLanguage } from './detect-language';
import { LOCALE_PATTERNS } from './locales';
import type { ContentLocale, LocaleContentPattern } from './types';

/**
 * Get content filter patterns for a specific locale or auto-detect language.
 */
export function getContentLocalePatterns(
  text: string,
  options?: { locale?: ContentLocale; autoDetectLanguage?: boolean },
): LocaleContentPattern[] {
  // Explicit locale
  if (options?.locale && LOCALE_PATTERNS[options.locale]) {
    return LOCALE_PATTERNS[options.locale];
  }

  // Auto-detect
  if (options?.autoDetectLanguage) {
    const detection = detectLanguage(text);
    if (detection.confidence > 0.1 && detection.language !== 'en' && detection.language !== 'unknown') {
      const patterns = LOCALE_PATTERNS[detection.language as ContentLocale];
      if (patterns) return patterns;
    }
  }

  return [];
}
