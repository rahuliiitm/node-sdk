/**
 * Canada PII patterns: SIN (Social Insurance Number).
 * @internal
 */

import type { LocalePIIPattern } from './types';

/** Standard Luhn algorithm check. */
function luhnCheck(digits: string): boolean {
  const nums = digits.replace(/[\s-]/g, '');
  if (nums.length !== 9 || !/^\d{9}$/.test(nums)) return false;
  let sum = 0;
  for (let i = 0; i < nums.length; i++) {
    let d = parseInt(nums[i], 10);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

const SIN_CONTEXT = /\b(?:sin|social\s*insurance|social\s*ins)\b/i;

function sinContextCheck(match: string, fullText?: string, matchIndex?: number): boolean {
  // Formatted SINs (with dashes/spaces) are high confidence without context
  if (/\d{3}[\s-]\d{3}[\s-]\d{3}/.test(match)) {
    const digits = match.replace(/[\s-]/g, '');
    return luhnCheck(digits);
  }
  // Bare digits need context
  if (!fullText || matchIndex == null) return false;
  const preceding = fullText.slice(Math.max(0, matchIndex - 60), matchIndex);
  if (!SIN_CONTEXT.test(preceding)) return false;
  return luhnCheck(match);
}

// SIN: 9 digits, optionally separated by dashes or spaces
const SIN_RE = /\b(\d{3})[\s-]?(\d{3})[\s-]?(\d{3})\b/g;

export const CA_PII_PATTERNS: LocalePIIPattern[] = [
  {
    type: 'ca_sin',
    label: 'Canadian SIN',
    regex: SIN_RE,
    confidence: 0.85,
    validate: sinContextCheck,
  },
];
