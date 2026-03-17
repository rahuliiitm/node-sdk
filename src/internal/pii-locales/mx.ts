/**
 * Mexico PII patterns: RFC, CURP, phone.
 * @internal
 */

import type { LocalePIIPattern } from './types';

const RFC_CONTEXT = /\b(?:rfc|registro\s*federal|contribuyente)\b/i;

function rfcValidate(match: string, fullText?: string, matchIndex?: number): boolean {
  // RFC is 13 chars for individuals (4 letters + 6 digits + 3 alphanum)
  // or 12 chars for companies (3 letters + 6 digits + 3 alphanum)
  const clean = match.replace(/[\s-]/g, '');
  if (clean.length !== 12 && clean.length !== 13) return false;
  // Birth/creation date check (positions 4-9 for individuals, 3-8 for companies)
  const dateStart = clean.length === 13 ? 4 : 3;
  const yy = parseInt(clean.slice(dateStart, dateStart + 2), 10);
  const mm = parseInt(clean.slice(dateStart + 2, dateStart + 4), 10);
  const dd = parseInt(clean.slice(dateStart + 4, dateStart + 6), 10);
  if (mm < 1 || mm > 12) return false;
  if (dd < 1 || dd > 31) return false;
  // Context check
  if (fullText && matchIndex != null) {
    const preceding = fullText.slice(Math.max(0, matchIndex - 60), matchIndex);
    if (RFC_CONTEXT.test(preceding)) return true;
  }
  // RFC format is specific enough to be high-confidence without context
  return true;
}

const CURP_CONTEXT = /\b(?:curp|clave\s*(?:unica|de\s*registro)|registro\s*de\s*poblaci[oó]n)\b/i;

function curpValidate(match: string, fullText?: string, matchIndex?: number): boolean {
  if (match.length !== 18) return false;
  // Date check (positions 4-9: YYMMDD)
  const mm = parseInt(match.slice(6, 8), 10);
  const dd = parseInt(match.slice(8, 10), 10);
  if (mm < 1 || mm > 12) return false;
  if (dd < 1 || dd > 31) return false;
  // Gender (position 10: H or M)
  const gender = match[10];
  if (gender !== 'H' && gender !== 'M') return false;
  // State code (positions 11-12: valid Mexican state codes)
  const validStates = [
    'AS', 'BC', 'BS', 'CC', 'CL', 'CM', 'CS', 'CH', 'DF', 'DG',
    'GT', 'GR', 'HG', 'JC', 'MC', 'MN', 'MS', 'NT', 'NL', 'OC',
    'PL', 'QT', 'QR', 'SP', 'SL', 'SR', 'TC', 'TS', 'TL', 'VZ',
    'YN', 'ZS', 'NE',
  ];
  const state = match.slice(11, 13);
  if (!validStates.includes(state)) return false;
  if (fullText && matchIndex != null) {
    const preceding = fullText.slice(Math.max(0, matchIndex - 60), matchIndex);
    if (CURP_CONTEXT.test(preceding)) return true;
  }
  return true;
}

// RFC: 4 letters + 6 digits + 3 alphanum (individual) or 3+6+3 (company)
const RFC_RE = /\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b/g;
// CURP: 4 letters + 6 digits + H/M + 2-letter state + 3 consonants + 1 digit/letter
const CURP_RE = /\b[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d\b/g;
// Mexican phone: +52 or (XX) XXXX-XXXX
const MX_PHONE_RE = /(?:\+52\s?)?(?:\(?[1-9]\d{1,2}\)?\s?)\d{3,4}[\s-]?\d{4}\b/g;

export const MX_PII_PATTERNS: LocalePIIPattern[] = [
  {
    type: 'mx_rfc',
    label: 'Mexican RFC',
    regex: RFC_RE,
    confidence: 0.8,
    validate: rfcValidate,
  },
  {
    type: 'mx_curp',
    label: 'Mexican CURP',
    regex: CURP_RE,
    confidence: 0.9,
    validate: curpValidate,
  },
  {
    type: 'mx_phone',
    label: 'Mexican Phone',
    regex: MX_PHONE_RE,
    confidence: 0.8,
  },
];
