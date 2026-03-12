/**
 * Secret / credential detection module.
 * Detects API keys, tokens, private keys, connection strings, and other
 * credentials in text.  Separate from PII (which covers personal data).
 * Zero-dependency, regex-based scanner.
 * @internal
 */

// ── Public interfaces ────────────────────────────────────────────────────────

/** Maximum text length for secret scanning to prevent DoS. */
export const MAX_SCAN_LENGTH = 1024 * 1024; // 1 MB

export interface SecretDetectionOptions {
  /** Whether to run the built-in patterns (default: true). */
  builtInPatterns?: boolean;
  /** Additional user-supplied patterns. */
  customPatterns?: CustomSecretPattern[];
}

export interface CustomSecretPattern {
  /** Human-readable name for the pattern. */
  name: string;
  /** Regular-expression source string (compiled internally with global flag). */
  pattern: string;
  /** Confidence score 0-1 (default: 0.9). */
  confidence?: number;
}

export interface SecretDetection {
  /** Pattern name, or 'custom:<name>' for user-supplied patterns. */
  type: string;
  /** The matched text. */
  value: string;
  /** Start index in the (possibly truncated) input. */
  start: number;
  /** End index in the (possibly truncated) input. */
  end: number;
  /** Confidence score 0-1. */
  confidence: number;
}

/** Provider interface for pluggable secret detectors (e.g., ML plugin). */
export interface SecretDetectorProvider {
  detect(text: string, options?: SecretDetectionOptions): SecretDetection[] | Promise<SecretDetection[]>;
  readonly name: string;
}

// ── Built-in patterns ────────────────────────────────────────────────────────

interface PatternEntry {
  name: string;
  pattern: RegExp;
  confidence: number;
}

const PATTERNS: PatternEntry[] = [
  { name: 'aws_access_key', pattern: /\bAKIA[0-9A-Z]{16}\b/g, confidence: 0.95 },
  { name: 'github_pat', pattern: /\bghp_[A-Za-z0-9]{36}\b/g, confidence: 0.95 },
  { name: 'github_oauth', pattern: /\bgho_[A-Za-z0-9]{36}\b/g, confidence: 0.95 },
  { name: 'gitlab_pat', pattern: /\bglpat-[A-Za-z0-9\-]{20,}\b/g, confidence: 0.95 },
  { name: 'slack_token', pattern: /\bxox[bpas]-[A-Za-z0-9\-]+\b/g, confidence: 0.90 },
  { name: 'stripe_secret', pattern: /\bsk_live_[A-Za-z0-9]{24,}\b/g, confidence: 0.95 },
  { name: 'stripe_publishable', pattern: /\bpk_live_[A-Za-z0-9]{24,}\b/g, confidence: 0.85 },
  { name: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, confidence: 0.90 },
  { name: 'private_key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, confidence: 0.99 },
  { name: 'connection_string', pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s"']+/g, confidence: 0.90 },
  { name: 'webhook_url', pattern: /https?:\/\/hooks\.(?:slack|discord)\.com\/[^\s]+/g, confidence: 0.85 },
  { name: 'gcp_api_key', pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g, confidence: 0.95 },
  { name: 'npm_token', pattern: /\bnpm_[A-Za-z0-9]{36}\b/g, confidence: 0.95 },
  { name: 'docker_pat', pattern: /\bdckr_pat_[A-Za-z0-9_\-]{30,}\b/g, confidence: 0.95 },
  { name: 'basic_auth', pattern: /\bBasic\s+[A-Za-z0-9+\/]{20,}={0,2}\b/g, confidence: 0.80 },
  { name: 'credential_assignment', pattern: /(?:^|[\s;,{(])[A-Za-z_]*(?:PASSWORD|SECRET|CREDENTIAL|PASSPHRASE|AUTH_TOKEN|PRIVATE_KEY)[A-Za-z_0-9]*\s*[=:]\s*['"`]([^'"`\n]{1,200})['"`]/gim, confidence: 0.85 },
  { name: 'generic_high_entropy', pattern: /(?:secret|key|token|password|api_key|apikey)[\s:="']*[A-Za-z0-9\/+=\-_]{32,}/gi, confidence: 0.70 },
];

// ── Detection ────────────────────────────────────────────────────────────────

/**
 * Detect secrets, credentials, and tokens in text using regex patterns.
 * Returns an array of detections sorted by start position.
 * Text longer than 1 MB is truncated before scanning.
 */
export function detectSecrets(
  text: string,
  options?: SecretDetectionOptions,
): SecretDetection[] {
  if (!text) return [];

  // Cap input length to prevent DoS via regex scanning
  const scanText =
    text.length > MAX_SCAN_LENGTH ? text.slice(0, MAX_SCAN_LENGTH) : text;

  const useBuiltIn = options?.builtInPatterns !== false;
  const detections: SecretDetection[] = [];

  // ── Built-in patterns ──────────────────────────────────────────────────────
  if (useBuiltIn) {
    for (const entry of PATTERNS) {
      // Reset regex state for global patterns
      entry.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = entry.pattern.exec(scanText)) !== null) {
        detections.push({
          type: entry.name,
          value: match[0],
          start: match.index,
          end: match.index + match[0].length,
          confidence: entry.confidence,
        });
      }
    }
  }

  // ── Custom patterns ────────────────────────────────────────────────────────
  if (options?.customPatterns) {
    for (const custom of options.customPatterns) {
      let regex: RegExp;
      try {
        regex = new RegExp(custom.pattern, 'g');
      } catch {
        // Skip invalid regex strings silently
        continue;
      }

      let match: RegExpExecArray | null;
      while ((match = regex.exec(scanText)) !== null) {
        detections.push({
          type: `custom:${custom.name}`,
          value: match[0],
          start: match.index,
          end: match.index + match[0].length,
          confidence: custom.confidence ?? 0.9,
        });

        // Prevent infinite loop on zero-length matches
        if (match[0].length === 0) {
          regex.lastIndex++;
        }
      }
    }
  }

  // Sort by start position, then by confidence descending for overlaps
  detections.sort((a, b) => a.start - b.start || b.confidence - a.confidence);

  // Remove overlapping detections (keep highest confidence)
  return deduplicateDetections(detections);
}

// ── Deduplication ────────────────────────────────────────────────────────────

/**
 * Merge secret detections from multiple sources (built-in + providers).
 * Concatenates, sorts by start, and deduplicates overlapping detections.
 */
export function mergeSecretDetections(...arrays: SecretDetection[][]): SecretDetection[] {
  const all = arrays.flat();
  if (all.length === 0) return [];
  all.sort((a, b) => a.start - b.start || b.confidence - a.confidence);
  return deduplicateDetections(all);
}

function deduplicateDetections(sorted: SecretDetection[]): SecretDetection[] {
  if (sorted.length === 0) return sorted;

  const result: SecretDetection[] = [sorted[0]];

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
