/**
 * Germany PII patterns: Steueridentifikationsnummer (Tax ID, 11 digits).
 * @internal
 */

import type { LocalePIIPattern } from './types';

/** German tax ID validation: 11 digits, one digit appears 2-3 times, others once. */
function taxIdCheck(digits: string): boolean {
  const nums = digits.replace(/[\s-]/g, '');
  if (nums.length !== 11 || !/^\d{11}$/.test(nums)) return false;
  // First digit must not be 0
  if (nums[0] === '0') return false;
  // Count digit frequencies in first 10 digits
  const counts = new Array(10).fill(0);
  for (let i = 0; i < 10; i++) counts[parseInt(nums[i], 10)]++;
  // Exactly one digit appears 2 or 3 times, rest appear once or zero
  let doubles = 0;
  for (const c of counts) {
    if (c === 2 || c === 3) doubles++;
    else if (c > 3) return false;
  }
  if (doubles !== 1) return false;
  return true;
}

const DE_TAX_CONTEXT = /(?:steuer(?:identifikationsnummer|nummer|id|ident)|tin|tax\s*id|steuernummer)/i;

function taxIdValidate(match: string, fullText?: string, matchIndex?: number): boolean {
  if (!taxIdCheck(match)) return false;
  if (!fullText || matchIndex == null) return false;
  const preceding = fullText.slice(Math.max(0, matchIndex - 80), matchIndex);
  return DE_TAX_CONTEXT.test(preceding);
}

// German tax ID: 11 digits
const DE_TAX_ID_RE = /\b[1-9]\d{10}\b/g;

export const DE_PII_PATTERNS: LocalePIIPattern[] = [
  {
    type: 'de_tax_id',
    label: 'German Tax ID',
    regex: DE_TAX_ID_RE,
    confidence: 0.8,
    validate: taxIdValidate,
  },
];
