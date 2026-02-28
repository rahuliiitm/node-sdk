/**
 * PII (Personally Identifiable Information) detection module.
 * Zero-dependency, regex-based scanner for common PII patterns.
 * @internal
 */

export type PIIType =
  | 'email'
  | 'phone'
  | 'ssn'
  | 'credit_card'
  | 'ip_address'
  | 'api_key'
  | 'date_of_birth'
  | 'us_address'
  | 'iban'
  | 'nhs_number'
  | 'uk_nino'
  | 'passport'
  | 'aadhaar'
  | 'eu_phone'
  | 'medicare'
  | 'drivers_license';

export interface PIIDetection {
  type: PIIType;
  value: string;
  start: number;
  end: number;
  confidence: number;
}

export interface PIIDetectOptions {
  types?: PIIType[];
}

/** Provider interface for pluggable PII detectors (e.g., ML plugin). */
export interface PIIDetectorProvider {
  detect(text: string, options?: PIIDetectOptions): PIIDetection[];
  readonly name: string;
  readonly supportedTypes: PIIType[];
}

// ── Regex patterns ──────────────────────────────────────────────────────────

const EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;

const PHONE_US_RE =
  /\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;

const PHONE_INTL_RE = /(?<=^|[\s(])\+\d{1,3}[-.\s]?\d{4,14}(?:[-.\s]\d{1,6})*\b/g;

const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;

const CREDIT_CARD_RE = /\b(?:\d[ \-]*?){13,19}\b/g;

const IP_V4_RE = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;

// Common API key / secret patterns
const API_KEY_RE =
  /\b(?:sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9\-_]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-_]{20,}|xox[bsapr]-[a-zA-Z0-9\-]{10,})\b/g;

const DATE_OF_BIRTH_RE = /\b(?:0[1-9]|1[0-2])[\/\-](?:0[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b/g;

const US_ADDRESS_RE =
  /\b\d{1,6}\s+[A-Za-z][A-Za-z\s]{1,30}\s+(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Ln|Lane|Rd|Road|Way|Ct|Court|Pl(?:ace)?|Cir(?:cle)?|Pkwy|Parkway)\b/gi;

// ── International PII patterns ──────────────────────────────────────────────

const IBAN_RE = /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b/g;

const NHS_NUMBER_RE = /(?<!\+)\b\d{3}\s?\d{3}\s?\d{4}\b/g;

const UK_NINO_RE = /\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/g;

const PASSPORT_RE = /\b[A-Z]{1,2}\d{6,9}\b/g;

const AADHAAR_RE = /(?<!\+)\b\d{4}\s?\d{4}\s?\d{4}\b/g;

const EU_PHONE_RE = /(?<=^|[\s(])\+(?:33|49|34|39|31|32|43|41|46|47|48|45|358|351|353|30|36)\s?\d[\d\s]{7,12}\b/g;

const MEDICARE_AU_RE = /(?<!\+)\b\d{4}\s?\d{5}\s?\d{1}\b/g;

const DRIVERS_LICENSE_US_RE = /\b[A-Z]\d{3}-\d{4}-\d{4}\b/g;

// ── Luhn check for credit cards ─────────────────────────────────────────────

function luhnCheck(digits: string): boolean {
  const nums = digits.replace(/[\s\-]/g, '');
  if (!/^\d{13,19}$/.test(nums)) return false;

  let sum = 0;
  let alternate = false;
  for (let i = nums.length - 1; i >= 0; i--) {
    let n = parseInt(nums[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

// ── NHS Number validation (must be exactly 10 digits) ───────────────────────

function nhsNumberCheck(match: string): boolean {
  const digits = match.replace(/\s/g, '');
  return /^\d{10}$/.test(digits);
}

// ── Aadhaar validation (must be exactly 12 digits, starting with 2-9) ───────

function aadhaarCheck(this: void, match: string, fullText?: string, matchIndex?: number): boolean {
  const digits = match.replace(/\s/g, '');
  if (!/^\d{12}$/.test(digits)) return false;
  // Aadhaar numbers start with 2-9 (never 0 or 1)
  if (digits[0] === '0' || digits[0] === '1') return false;
  return true;
}

// ── Well-known non-PII IP addresses (reduce false positives) ────────────────

const WELL_KNOWN_IPS = new Set([
  '0.0.0.0',
  '127.0.0.1',
  '255.255.255.255',
  '255.255.255.0',
  '192.168.0.1',
  '192.168.1.1',
  '10.0.0.1',
]);

// ── Pattern registry ────────────────────────────────────────────────────────

interface PatternEntry {
  type: PIIType;
  regex: RegExp;
  confidence: number;
  validate?: (match: string) => boolean;
}

const PATTERNS: PatternEntry[] = [
  { type: 'email', regex: EMAIL_RE, confidence: 0.95 },
  { type: 'phone', regex: PHONE_US_RE, confidence: 0.85 },
  { type: 'phone', regex: PHONE_INTL_RE, confidence: 0.8 },
  { type: 'ssn', regex: SSN_RE, confidence: 0.95 },
  {
    type: 'credit_card',
    regex: CREDIT_CARD_RE,
    confidence: 0.9,
    validate: luhnCheck,
  },
  {
    type: 'ip_address',
    regex: IP_V4_RE,
    confidence: 0.8,
    validate: (ip) => !WELL_KNOWN_IPS.has(ip),
  },
  { type: 'api_key', regex: API_KEY_RE, confidence: 0.95 },
  { type: 'date_of_birth', regex: DATE_OF_BIRTH_RE, confidence: 0.7 },
  { type: 'us_address', regex: US_ADDRESS_RE, confidence: 0.7 },
  { type: 'iban', regex: IBAN_RE, confidence: 0.9 },
  {
    type: 'nhs_number',
    regex: NHS_NUMBER_RE,
    confidence: 0.8,
    validate: nhsNumberCheck,
  },
  { type: 'uk_nino', regex: UK_NINO_RE, confidence: 0.9 },
  { type: 'passport', regex: PASSPORT_RE, confidence: 0.7 },
  {
    type: 'aadhaar',
    regex: AADHAAR_RE,
    confidence: 0.85,
    validate: aadhaarCheck,
  },
  { type: 'eu_phone', regex: EU_PHONE_RE, confidence: 0.8 },
  { type: 'medicare', regex: MEDICARE_AU_RE, confidence: 0.75 },
  { type: 'drivers_license', regex: DRIVERS_LICENSE_US_RE, confidence: 0.75 },
];

// ── Detection ───────────────────────────────────────────────────────────────

/**
 * Detect PII entities in text using regex patterns.
 * Returns an array of detections sorted by start position.
 */
export function detectPII(
  text: string,
  options?: PIIDetectOptions,
): PIIDetection[] {
  if (!text) return [];

  const allowedTypes = options?.types ? new Set(options.types) : null;
  const detections: PIIDetection[] = [];

  for (const pattern of PATTERNS) {
    if (allowedTypes && !allowedTypes.has(pattern.type)) continue;

    // Reset regex state for global patterns
    pattern.regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(text)) !== null) {
      const value = match[0];

      // Run optional validation (e.g., Luhn for credit cards)
      if (pattern.validate && !pattern.validate(value)) continue;

      detections.push({
        type: pattern.type,
        value,
        start: match.index,
        end: match.index + value.length,
        confidence: pattern.confidence,
      });
    }
  }

  // Sort by start position, then by confidence descending for overlaps
  detections.sort((a, b) => a.start - b.start || b.confidence - a.confidence);

  // Remove overlapping detections (keep highest confidence)
  return deduplicateDetections(detections);
}

/**
 * Merge detections from multiple providers, deduplicating overlapping spans.
 */
export function mergeDetections(
  ...detectionArrays: PIIDetection[][]
): PIIDetection[] {
  const all = detectionArrays.flat();
  all.sort((a, b) => a.start - b.start || b.confidence - a.confidence);
  return deduplicateDetections(all);
}

function deduplicateDetections(sorted: PIIDetection[]): PIIDetection[] {
  if (sorted.length === 0) return sorted;

  const result: PIIDetection[] = [sorted[0]];

  for (let i = 1; i < sorted.length; i++) {
    const prev = result[result.length - 1];
    const curr = sorted[i];

    // If current overlaps with previous, keep the one with higher confidence
    if (curr.start < prev.end) {
      if (curr.confidence > prev.confidence) {
        result[result.length - 1] = curr;
      }
      // else skip current (lower or equal confidence)
    } else {
      result.push(curr);
    }
  }

  return result;
}

// ── Custom PII Pattern Registration ─────────────────────────────────────────

/** Interface for registering custom PII patterns. */
export interface CustomPIIPattern {
  name: string;
  type: string;
  pattern: RegExp;
  confidence?: number;
}

/**
 * Create a PIIDetectorProvider from custom regex patterns.
 * Allows users to register domain-specific PII types (e.g., employee IDs).
 */
export function createCustomDetector(patterns: CustomPIIPattern[]): PIIDetectorProvider {
  const supportedTypes = [...new Set(patterns.map((p) => p.type))] as PIIType[];

  return {
    name: 'custom',
    supportedTypes,
    detect(text: string, options?: PIIDetectOptions): PIIDetection[] {
      if (!text) return [];

      const allowedTypes = options?.types ? new Set(options.types) : null;
      const detections: PIIDetection[] = [];

      for (const pattern of patterns) {
        if (allowedTypes && !allowedTypes.has(pattern.type as PIIType)) continue;

        // Create a fresh regex with global flag to iterate matches
        const flags = pattern.pattern.flags.includes('g')
          ? pattern.pattern.flags
          : pattern.pattern.flags + 'g';
        const regex = new RegExp(pattern.pattern.source, flags);

        let match: RegExpExecArray | null;
        while ((match = regex.exec(text)) !== null) {
          detections.push({
            type: pattern.type as PIIType,
            value: match[0],
            start: match.index,
            end: match.index + match[0].length,
            confidence: pattern.confidence ?? 0.8,
          });
        }
      }

      detections.sort((a, b) => a.start - b.start || b.confidence - a.confidence);
      return deduplicateDetections(detections);
    },
  };
}

/**
 * Built-in regex PII detector implementing the provider interface.
 */
export class RegexPIIDetector implements PIIDetectorProvider {
  readonly name = 'regex';
  readonly supportedTypes: PIIType[] = [
    'email',
    'phone',
    'ssn',
    'credit_card',
    'ip_address',
    'api_key',
    'date_of_birth',
    'us_address',
    'iban',
    'nhs_number',
    'uk_nino',
    'passport',
    'aadhaar',
    'eu_phone',
    'medicare',
    'drivers_license',
  ];

  detect(text: string, options?: PIIDetectOptions): PIIDetection[] {
    return detectPII(text, options);
  }
}
