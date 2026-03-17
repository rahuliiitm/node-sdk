/**
 * China PII patterns: National ID (18-digit), phone.
 * @internal
 */

import type { LocalePIIPattern } from './types';

const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
const CHECK_CHARS = '10X98765432';

function cnIdCheckDigit(digits: string): boolean {
  const id = digits.replace(/\s/g, '').toUpperCase();
  if (id.length !== 18) return false;
  // Validate region (first 2 digits: 11-65)
  const region = parseInt(id.slice(0, 2), 10);
  if (region < 11 || region > 65) return false;
  // Validate birth date (digits 6-13: YYYYMMDD)
  const year = parseInt(id.slice(6, 10), 10);
  const month = parseInt(id.slice(10, 12), 10);
  const day = parseInt(id.slice(12, 14), 10);
  if (year < 1900 || year > new Date().getFullYear()) return false;
  if (month < 1 || month > 12) return false;
  if (day < 1 || day > 31) return false;
  // Check digit
  let sum = 0;
  for (let i = 0; i < 17; i++) {
    const d = parseInt(id[i], 10);
    if (isNaN(d)) return false;
    sum += d * ID_WEIGHTS[i];
  }
  const expected = CHECK_CHARS[sum % 11];
  return id[17] === expected;
}

const CN_ID_CONTEXT = /(?:身份证|id\s*card|national\s*id|citizen\s*id)/i;

function cnIdValidate(match: string, fullText?: string, matchIndex?: number): boolean {
  if (!cnIdCheckDigit(match)) return false;
  // If text contains Chinese characters or ID context, high confidence
  if (fullText) {
    const preceding = fullText.slice(Math.max(0, (matchIndex ?? 0) - 60), matchIndex ?? 0);
    if (CN_ID_CONTEXT.test(preceding)) return true;
    // Check for Chinese characters anywhere in preceding text
    if (/[\u4e00-\u9fff]/.test(preceding)) return true;
  }
  // Standalone 18-digit number with valid check digit is still likely an ID
  return true;
}

// Chinese national ID: 18 digits, last may be X
const CN_ID_RE = /\b[1-6]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g;
// Chinese phone: +86 or 1XX XXXX XXXX
const CN_PHONE_RE = /(?:\+86\s?)?1[3-9]\d[\s-]?\d{4}[\s-]?\d{4}\b/g;

export const CN_PII_PATTERNS: LocalePIIPattern[] = [
  {
    type: 'cn_national_id',
    label: 'Chinese National ID',
    regex: CN_ID_RE,
    confidence: 0.9,
    validate: cnIdValidate,
  },
  {
    type: 'cn_phone',
    label: 'Chinese Phone',
    regex: CN_PHONE_RE,
    confidence: 0.8,
  },
];
