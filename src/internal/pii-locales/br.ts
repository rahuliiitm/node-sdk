/**
 * Brazil PII patterns: CPF, CNPJ, phone.
 * @internal
 */

import type { LocalePIIPattern } from './types';

/** CPF check digit validation. */
function cpfCheckDigits(digits: string): boolean {
  const nums = digits.replace(/\D/g, '');
  if (nums.length !== 11) return false;
  // Reject all-same-digit CPFs
  if (/^(\d)\1{10}$/.test(nums)) return false;
  // First check digit
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += parseInt(nums[i], 10) * (10 - i);
  let check = 11 - (sum % 11);
  if (check >= 10) check = 0;
  if (check !== parseInt(nums[9], 10)) return false;
  // Second check digit
  sum = 0;
  for (let i = 0; i < 10; i++) sum += parseInt(nums[i], 10) * (11 - i);
  check = 11 - (sum % 11);
  if (check >= 10) check = 0;
  return check === parseInt(nums[10], 10);
}

/** CNPJ check digit validation. */
function cnpjCheckDigits(digits: string): boolean {
  const nums = digits.replace(/\D/g, '');
  if (nums.length !== 14) return false;
  // First check digit
  const w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += parseInt(nums[i], 10) * w1[i];
  let check = 11 - (sum % 11);
  if (check >= 10) check = 0;
  if (check !== parseInt(nums[12], 10)) return false;
  // Second check digit
  const w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  sum = 0;
  for (let i = 0; i < 13; i++) sum += parseInt(nums[i], 10) * w2[i];
  check = 11 - (sum % 11);
  if (check >= 10) check = 0;
  return check === parseInt(nums[13], 10);
}

const CPF_CONTEXT = /\b(?:cpf|cadastro\s*de\s*pessoa)\b/i;

function cpfValidate(match: string, fullText?: string, matchIndex?: number): boolean {
  const digits = match.replace(/\D/g, '');
  if (!cpfCheckDigits(digits)) return false;
  // Formatted CPFs are high confidence
  if (/\d{3}\.\d{3}\.\d{3}-\d{2}/.test(match)) return true;
  // Bare digits need context
  if (!fullText || matchIndex == null) return false;
  const preceding = fullText.slice(Math.max(0, matchIndex - 60), matchIndex);
  return CPF_CONTEXT.test(preceding);
}

const CNPJ_CONTEXT = /\b(?:cnpj|cadastro\s*nacional)\b/i;

function cnpjValidate(match: string, fullText?: string, matchIndex?: number): boolean {
  const digits = match.replace(/\D/g, '');
  if (!cnpjCheckDigits(digits)) return false;
  if (/\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}/.test(match)) return true;
  if (!fullText || matchIndex == null) return false;
  const preceding = fullText.slice(Math.max(0, matchIndex - 60), matchIndex);
  return CNPJ_CONTEXT.test(preceding);
}

// CPF: 000.000.000-00 or 00000000000
const CPF_RE = /\b(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})\b/g;
// CNPJ: 00.000.000/0000-00
const CNPJ_RE = /\b(\d{2})\.?(\d{3})\.?(\d{3})\/?(\d{4})-?(\d{2})\b/g;
// Brazilian phone: +55 or (XX) XXXXX-XXXX
const BR_PHONE_RE = /(?:\+55\s?)?(?:\(?[1-9]\d\)?\s?)(?:9\s?\d{4})[\s-]?\d{4}\b/g;

export const BR_PII_PATTERNS: LocalePIIPattern[] = [
  {
    type: 'br_cpf',
    label: 'Brazilian CPF',
    regex: CPF_RE,
    confidence: 0.9,
    validate: cpfValidate,
  },
  {
    type: 'br_cnpj',
    label: 'Brazilian CNPJ',
    regex: CNPJ_RE,
    confidence: 0.9,
    validate: cnpjValidate,
  },
  {
    type: 'br_phone',
    label: 'Brazilian Phone',
    regex: BR_PHONE_RE,
    confidence: 0.8,
  },
];
