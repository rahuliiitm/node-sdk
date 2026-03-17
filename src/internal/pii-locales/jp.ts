/**
 * Japan PII patterns: My Number (12-digit), phone.
 * @internal
 */

import type { LocalePIIPattern } from './types';

/** My Number check digit (modulo 11 variant). */
function myNumberCheckDigit(digits: string): boolean {
  const nums = digits.replace(/\s/g, '');
  if (nums.length !== 12 || !/^\d{12}$/.test(nums)) return false;
  const q = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 11; i++) {
    sum += parseInt(nums[i], 10) * q[i];
  }
  const remainder = sum % 11;
  const expected = remainder <= 1 ? 0 : 11 - remainder;
  return expected === parseInt(nums[11], 10);
}

const MY_NUMBER_CONTEXT = /(?:マイナンバー|my\s*number|個人番号)/i;

function myNumberValidate(match: string, fullText?: string, matchIndex?: number): boolean {
  if (!myNumberCheckDigit(match)) return false;
  if (fullText) {
    const preceding = fullText.slice(Math.max(0, (matchIndex ?? 0) - 60), matchIndex ?? 0);
    if (MY_NUMBER_CONTEXT.test(preceding)) return true;
    if (/[\u3040-\u309f\u30a0-\u30ff\u4e00-\u9fff]/.test(preceding)) return true;
  }
  return false; // Bare 12-digit number without context is too ambiguous
}

// My Number: 12 digits
const MY_NUMBER_RE = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g;
// Japanese phone: +81 or 0X0-XXXX-XXXX
const JP_PHONE_RE = /(?:\+81\s?|0)[789]0[\s-]?\d{4}[\s-]?\d{4}\b/g;

export const JP_PII_PATTERNS: LocalePIIPattern[] = [
  {
    type: 'jp_my_number',
    label: 'Japanese My Number',
    regex: MY_NUMBER_RE,
    confidence: 0.85,
    validate: myNumberValidate,
  },
  {
    type: 'jp_phone',
    label: 'Japanese Phone',
    regex: JP_PHONE_RE,
    confidence: 0.8,
  },
];
