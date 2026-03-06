/**
 * PII redaction module — replaces detected PII with safe substitutes.
 * Supports three strategies: placeholder, synthetic, and hash.
 * @internal
 */

import { createHash } from 'crypto';
import { detectPII, mergeDetections, type PIIDetection, type PIIDetectOptions, type PIIDetectorProvider } from './pii';

export type RedactionStrategy = 'placeholder' | 'synthetic' | 'hash' | 'mask' | 'none';

export interface MaskingOptions {
  char?: string;
  visibleSuffix?: number;
  visiblePrefix?: number;
}

export interface RedactionOptions extends PIIDetectOptions {
  strategy?: RedactionStrategy;
  /** Additional PII detector providers (e.g., ML plugin). */
  providers?: PIIDetectorProvider[];
  /** Options for 'mask' redaction strategy. */
  masking?: MaskingOptions;
}

export interface RedactionResult {
  redactedText: string;
  detections: PIIDetection[];
  /** Map from placeholder/replacement → original value. Use for de-redaction. */
  mapping: Map<string, string>;
}

// ── Synthetic data generators ───────────────────────────────────────────────

const SYNTHETIC_EMAILS = [
  'alex@example.net',
  'sam@example.org',
  'pat@example.com',
  'jordan@example.net',
  'taylor@example.org',
  'morgan@example.com',
  'casey@example.net',
  'drew@example.org',
];

const SYNTHETIC_PHONES = [
  '(555) 100-0001',
  '(555) 100-0002',
  '(555) 100-0003',
  '(555) 100-0004',
  '(555) 100-0005',
];

const SYNTHETIC_SSNS = [
  '000-00-0001',
  '000-00-0002',
  '000-00-0003',
  '000-00-0004',
];

const SYNTHETIC_CARDS = [
  '4000-0000-0000-0001',
  '4000-0000-0000-0002',
  '4000-0000-0000-0003',
];

const SYNTHETIC_IPS = [
  '198.51.100.1',
  '198.51.100.2',
  '198.51.100.3',
  '198.51.100.4',
];

const SYNTHETIC_MAP: Record<string, string[]> = {
  email: SYNTHETIC_EMAILS,
  phone: SYNTHETIC_PHONES,
  ssn: SYNTHETIC_SSNS,
  credit_card: SYNTHETIC_CARDS,
  ip_address: SYNTHETIC_IPS,
  api_key: ['sk-REDACTED-0001', 'sk-REDACTED-0002', 'sk-REDACTED-0003'],
  date_of_birth: ['01/01/2000', '06/15/1985', '12/25/1970'],
  us_address: ['100 Example St', '200 Sample Ave', '300 Test Blvd'],
};

// ── Counters per type (for placeholder indexing) ────────────────────────────

function makeCounters(): Record<string, number> {
  return {};
}

function nextIndex(counters: Record<string, number>, type: string): number {
  counters[type] = (counters[type] ?? 0) + 1;
  return counters[type];
}

// ── Replacement generators ──────────────────────────────────────────────────

function placeholderReplacement(
  type: string,
  counters: Record<string, number>,
): string {
  const idx = nextIndex(counters, type);
  return `[${type.toUpperCase()}_${idx}]`;
}

function syntheticReplacement(
  type: string,
  counters: Record<string, number>,
): string {
  const idx = nextIndex(counters, type);
  const pool = SYNTHETIC_MAP[type];
  if (!pool || pool.length === 0) {
    return placeholderReplacement(type, counters);
  }
  return pool[(idx - 1) % pool.length];
}

function hashReplacement(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 16);
}

function maskReplacement(
  type: string,
  value: string,
  maskingOptions?: MaskingOptions,
): string {
  const maskChar = maskingOptions?.char ?? '*';

  switch (type) {
    case 'credit_card': {
      // Show last 4 digits → ****-****-****-1234
      const digits = value.replace(/[\s\-]/g, '');
      const last4 = digits.slice(-4);
      return `${maskChar.repeat(4)}-${maskChar.repeat(4)}-${maskChar.repeat(4)}-${last4}`;
    }
    case 'email': {
      // Mask before @, keep first char and domain → j***@acme.com
      const atIdx = value.indexOf('@');
      if (atIdx <= 0) return maskChar.repeat(value.length);
      const local = value.slice(0, atIdx);
      const domain = value.slice(atIdx);
      const firstChar = local[0];
      return `${firstChar}${maskChar.repeat(Math.max(local.length - 1, 1))}${domain}`;
    }
    case 'phone': {
      // Show last 4 digits → ***-***-4567
      const phoneDigits = value.replace(/[^\d]/g, '');
      const lastFour = phoneDigits.slice(-4);
      return `${maskChar.repeat(3)}-${maskChar.repeat(3)}-${lastFour}`;
    }
    case 'ssn': {
      // Show last 4 → ***-**-6789
      const ssnDigits = value.replace(/[^\d]/g, '');
      const ssnLast4 = ssnDigits.slice(-4);
      return `${maskChar.repeat(3)}-${maskChar.repeat(2)}-${ssnLast4}`;
    }
    default: {
      // Generic: replace all but last N chars with mask char
      const visibleSuffix = maskingOptions?.visibleSuffix ?? 4;
      const visiblePrefix = maskingOptions?.visiblePrefix ?? 0;
      if (value.length <= visiblePrefix + visibleSuffix) {
        return maskChar.repeat(value.length);
      }
      const prefix = value.slice(0, visiblePrefix);
      const suffix = value.slice(-visibleSuffix);
      const maskedLen = value.length - visiblePrefix - visibleSuffix;
      return `${prefix}${maskChar.repeat(maskedLen)}${suffix}`;
    }
  }
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Detect and redact PII in text.
 * Returns the redacted text, a list of detections, and a mapping for de-redaction.
 *
 * Pass `sharedCounters` to share placeholder indices across multiple calls
 * (e.g., when redacting multiple messages in a conversation).
 * This prevents placeholder collisions like two different emails both becoming [EMAIL_1].
 */
export async function redactPII(
  text: string,
  options?: RedactionOptions,
  sharedCounters?: Record<string, number>,
): Promise<RedactionResult> {
  if (!text) {
    return { redactedText: '', detections: [], mapping: new Map() };
  }

  const strategy = options?.strategy ?? 'placeholder';

  // Run built-in regex detection
  let detections = detectPII(text, options);

  // Run additional providers and merge (supports async ML providers)
  if (options?.providers && options.providers.length > 0) {
    const providerDetections = await Promise.all(options.providers.map(async (p) => {
      try {
        return await Promise.resolve(p.detect(text, options));
      } catch {
        return [] as PIIDetection[]; // Plugin isolation: failures don't crash core
      }
    }));
    detections = mergeDetections(detections, ...providerDetections);
  }

  if (detections.length === 0) {
    return { redactedText: text, detections: [], mapping: new Map() };
  }

  const mapping = new Map<string, string>();
  const counters = sharedCounters ?? makeCounters();

  // Build redacted text by replacing from end to start (preserves positions)
  let redacted = text;
  // Process in reverse order so replacements don't shift positions
  const reversed = [...detections].reverse();

  for (const det of reversed) {
    let replacement: string;

    switch (strategy) {
      case 'synthetic':
        replacement = syntheticReplacement(det.type, counters);
        break;
      case 'hash':
        replacement = hashReplacement(det.value);
        break;
      case 'mask':
        replacement = maskReplacement(det.type, det.value, options?.masking);
        break;
      case 'placeholder':
      default:
        replacement = placeholderReplacement(det.type, counters);
        break;
    }

    redacted = redacted.slice(0, det.start) + replacement + redacted.slice(det.end);
    // mapping: replacement → original (for de-redaction)
    mapping.set(replacement, det.value);
  }

  return { redactedText: redacted, detections, mapping };
}

/**
 * Restore original values in text using the redaction mapping.
 * Only works with placeholder and synthetic strategies (hash is one-way).
 */
export function deRedact(
  text: string,
  mapping: Map<string, string>,
): string {
  let result = text;
  for (const [replacement, original] of mapping) {
    // Replace all occurrences of the replacement
    result = result.split(replacement).join(original);
  }
  return result;
}
