/**
 * South Korea PII patterns: Resident Registration Number (RRN), phone.
 * @internal
 */

import type { LocalePIIPattern } from './types';

/** RRN check digit validation (13 digits, weighted sum mod 11). */
function rrnCheckDigit(digits: string): boolean {
  const nums = digits.replace(/[\s-]/g, '');
  if (nums.length !== 13 || !/^\d{13}$/.test(nums)) return false;
  // Birth date check (first 6 digits: YYMMDD)
  const month = parseInt(nums.slice(2, 4), 10);
  const day = parseInt(nums.slice(4, 6), 10);
  if (month < 1 || month > 12) return false;
  if (day < 1 || day > 31) return false;
  // Gender digit (7th): 1-4 for Korean citizens, 5-8 for foreign nationals
  const gender = parseInt(nums[6], 10);
  if (gender < 1 || gender > 8) return false;
  // Check digit
  const weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += parseInt(nums[i], 10) * weights[i];
  const expected = (11 - (sum % 11)) % 10;
  return expected === parseInt(nums[12], 10);
}

const RRN_CONTEXT = /(?:주민등록|resident\s*registration|rrn)/i;

function rrnValidate(match: string, fullText?: string, matchIndex?: number): boolean {
  if (!rrnCheckDigit(match)) return false;
  // Formatted RRN (with dash) is high confidence
  if (/\d{6}-\d{7}/.test(match)) return true;
  if (fullText) {
    const preceding = fullText.slice(Math.max(0, (matchIndex ?? 0) - 60), matchIndex ?? 0);
    if (RRN_CONTEXT.test(preceding)) return true;
    if (/[\uac00-\ud7af]/.test(preceding)) return true; // Korean characters
  }
  return false;
}

// RRN: YYMMDD-GXXXXXX (13 digits, optionally with dash)
const RRN_RE = /\b\d{6}-?\d{7}\b/g;
// Korean phone: +82 or 01X-XXXX-XXXX
const KR_PHONE_RE = /(?:\+82\s?)?0?1[016-9][\s-]?\d{3,4}[\s-]?\d{4}\b/g;

export const KR_PII_PATTERNS: LocalePIIPattern[] = [
  {
    type: 'kr_rrn',
    label: 'South Korean RRN',
    regex: RRN_RE,
    confidence: 0.85,
    validate: rrnValidate,
  },
  {
    type: 'kr_phone',
    label: 'South Korean Phone',
    regex: KR_PHONE_RE,
    confidence: 0.8,
  },
];
