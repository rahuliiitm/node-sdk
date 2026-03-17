/**
 * Shared types for PII locale patterns.
 * @internal
 */

export interface LocalePIIPattern {
  type: string;
  label: string;
  regex: RegExp;
  confidence: number;
  validate?: (match: string, fullText?: string, matchIndex?: number) => boolean;
}

/** All supported locale codes. */
export type PIILocale = 'ca' | 'br' | 'cn' | 'jp' | 'kr' | 'de' | 'mx' | 'fr';

export const ALL_LOCALES: PIILocale[] = ['ca', 'br', 'cn', 'jp', 'kr', 'de', 'mx', 'fr'];
