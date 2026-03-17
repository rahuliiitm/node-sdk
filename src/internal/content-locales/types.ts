/**
 * Shared types for content filter locale patterns.
 * @internal
 */

export interface LocaleContentPattern {
  category: string;
  patterns: RegExp[];
  severity: 'warn' | 'block';
}

export type ContentLocale = 'es' | 'pt' | 'zh' | 'ja' | 'ko' | 'de' | 'fr' | 'ar' | 'hi' | 'ru';

export const ALL_CONTENT_LOCALES: ContentLocale[] = [
  'es', 'pt', 'zh', 'ja', 'ko', 'de', 'fr', 'ar', 'hi', 'ru',
];
