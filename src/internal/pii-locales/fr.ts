/**
 * France PII patterns: NIR (INSEE number, 15 digits).
 * @internal
 */

import type { LocalePIIPattern } from './types';

/** NIR check: 13 digits + 2-digit key, key = 97 - (first_13 % 97). */
function nirCheckDigit(digits: string): boolean {
  const nums = digits.replace(/[\s-]/g, '');
  if (nums.length !== 15 || !/^\d{15}$/.test(nums)) return false;
  // Gender (first digit: 1 or 2)
  const gender = parseInt(nums[0], 10);
  if (gender !== 1 && gender !== 2) return false;
  // Birth year (digits 1-2)
  const yy = parseInt(nums.slice(1, 3), 10);
  // Birth month (digits 3-4: 01-12 or 20 for overseas)
  const month = parseInt(nums.slice(3, 5), 10);
  if (month < 1 || (month > 12 && month !== 20)) return false;
  // Check key
  const base = parseInt(nums.slice(0, 13), 10);
  const key = parseInt(nums.slice(13, 15), 10);
  return key === 97 - (base % 97);
}

const NIR_CONTEXT = /(?:nir|insee|s[eé]curit[eé]\s*sociale|num[eé]ro\s*de\s*s[eé]curit[eé]|social\s*security)/i;

function nirValidate(match: string, fullText?: string, matchIndex?: number): boolean {
  if (!nirCheckDigit(match)) return false;
  if (fullText && matchIndex != null) {
    const preceding = fullText.slice(Math.max(0, matchIndex - 80), matchIndex);
    if (NIR_CONTEXT.test(preceding)) return true;
  }
  // Valid NIR with correct check digit is high confidence even without context
  return true;
}

// NIR: 15 digits, optionally formatted as X XX XX XXXXX XXX XX
const NIR_RE = /\b[12]\s?\d{2}\s?\d{2}\s?\d{5}\s?\d{3}\s?\d{2}\b/g;

export const FR_PII_PATTERNS: LocalePIIPattern[] = [
  {
    type: 'fr_nir',
    label: 'French NIR/INSEE',
    regex: NIR_RE,
    confidence: 0.85,
    validate: nirValidate,
  },
];
