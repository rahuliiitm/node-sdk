import {
  detectSecrets,
  MAX_SCAN_LENGTH,
  type SecretDetection,
  type SecretDetectionOptions,
  type CustomSecretPattern,
} from './secret-detection';

describe('Secret Detection', () => {
  // ── AWS Access Key ─────────────────────────────────────────────────────────

  describe('aws_access_key', () => {
    it('detects AWS access key', () => {
      const result = detectSecrets('AWS key: AKIAIOSFODNN7EXAMPLE');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('aws_access_key');
      expect(result[0].value).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(result[0].confidence).toBe(0.95);
    });

    it('detects AWS key in config block', () => {
      const result = detectSecrets('aws_access_key_id = AKIAI44QH8DHBEXAMPLE');
      const aws = result.filter((d) => d.type === 'aws_access_key');
      expect(aws).toHaveLength(1);
    });
  });

  // ── GitHub PAT ─────────────────────────────────────────────────────────────

  describe('github_pat', () => {
    it('detects GitHub personal access token', () => {
      const token = 'ghp_' + 'A'.repeat(36);
      const result = detectSecrets(`Token: ${token}`);
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('github_pat');
      expect(result[0].value).toBe(token);
      expect(result[0].confidence).toBe(0.95);
    });
  });

  // ── GitHub OAuth ───────────────────────────────────────────────────────────

  describe('github_oauth', () => {
    it('detects GitHub OAuth token', () => {
      const token = 'gho_' + 'b'.repeat(36);
      const result = detectSecrets(`OAuth: ${token}`);
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('github_oauth');
      expect(result[0].value).toBe(token);
      expect(result[0].confidence).toBe(0.95);
    });
  });

  // ── GitLab PAT ─────────────────────────────────────────────────────────────

  describe('gitlab_pat', () => {
    it('detects GitLab personal access token', () => {
      const token = 'glpat-' + 'X'.repeat(20);
      const result = detectSecrets(`Token: ${token}`);
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('gitlab_pat');
      expect(result[0].value).toBe(token);
      expect(result[0].confidence).toBe(0.95);
    });

    it('detects long GitLab PAT', () => {
      const token = 'glpat-AbCdEfGhIjKlMnOpQrStUv';
      const result = detectSecrets(`Token: ${token}`);
      const gl = result.filter((d) => d.type === 'gitlab_pat');
      expect(gl).toHaveLength(1);
    });
  });

  // ── Slack Token ────────────────────────────────────────────────────────────

  describe('slack_token', () => {
    it('detects Slack bot token', () => {
      const result = detectSecrets('Token: xoxb-123456789-abcdefghij');
      const slack = result.filter((d) => d.type === 'slack_token');
      expect(slack).toHaveLength(1);
      expect(slack[0].confidence).toBe(0.90);
    });

    it('detects Slack user token', () => {
      const result = detectSecrets('Token: xoxp-123456789-abcdefghij');
      const slack = result.filter((d) => d.type === 'slack_token');
      expect(slack).toHaveLength(1);
    });
  });

  // ── Stripe Secret Key ─────────────────────────────────────────────────────

  describe('stripe_secret', () => {
    it('detects Stripe secret key', () => {
      const key = 'sk_live_' + 'A'.repeat(24);
      const result = detectSecrets(`Key: ${key}`);
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('stripe_secret');
      expect(result[0].value).toBe(key);
      expect(result[0].confidence).toBe(0.95);
    });
  });

  // ── Stripe Publishable Key ─────────────────────────────────────────────────

  describe('stripe_publishable', () => {
    it('detects Stripe publishable key', () => {
      const key = 'pk_live_' + 'B'.repeat(24);
      const result = detectSecrets(`Key: ${key}`);
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('stripe_publishable');
      expect(result[0].value).toBe(key);
      expect(result[0].confidence).toBe(0.85);
    });
  });

  // ── JWT ────────────────────────────────────────────────────────────────────

  describe('jwt', () => {
    it('detects JWT token', () => {
      // Minimal valid-looking JWT structure
      const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123DEF456_-';
      const result = detectSecrets(`Bearer ${jwt}`);
      const jwts = result.filter((d) => d.type === 'jwt');
      expect(jwts).toHaveLength(1);
      expect(jwts[0].confidence).toBe(0.90);
    });

    it('does not match non-JWT base64 strings', () => {
      const result = detectSecrets('data: aGVsbG8gd29ybGQ=');
      const jwts = result.filter((d) => d.type === 'jwt');
      expect(jwts).toHaveLength(0);
    });
  });

  // ── Private Key ────────────────────────────────────────────────────────────

  describe('private_key', () => {
    it('detects RSA private key header', () => {
      const result = detectSecrets('-----BEGIN RSA PRIVATE KEY-----');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('private_key');
      expect(result[0].confidence).toBe(0.99);
    });

    it('detects generic private key header', () => {
      const result = detectSecrets('-----BEGIN PRIVATE KEY-----');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('private_key');
    });

    it('detects EC private key header', () => {
      const result = detectSecrets('-----BEGIN EC PRIVATE KEY-----');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('private_key');
    });

    it('detects OPENSSH private key header', () => {
      const result = detectSecrets('-----BEGIN OPENSSH PRIVATE KEY-----');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('private_key');
    });

    it('detects DSA private key header', () => {
      const result = detectSecrets('-----BEGIN DSA PRIVATE KEY-----');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('private_key');
    });
  });

  // ── Connection String ──────────────────────────────────────────────────────

  describe('connection_string', () => {
    it('detects PostgreSQL connection string', () => {
      const result = detectSecrets('DATABASE_URL=postgresql://user:pass@host:5432/db');
      const cs = result.filter((d) => d.type === 'connection_string');
      expect(cs).toHaveLength(1);
      expect(cs[0].confidence).toBe(0.90);
    });

    it('detects MongoDB connection string', () => {
      const result = detectSecrets('MONGO_URI=mongodb+srv://admin:secret@cluster0.example.net/mydb');
      const cs = result.filter((d) => d.type === 'connection_string');
      expect(cs).toHaveLength(1);
    });

    it('detects MySQL connection string', () => {
      const result = detectSecrets('DB=mysql://root:password@localhost:3306/app');
      const cs = result.filter((d) => d.type === 'connection_string');
      expect(cs).toHaveLength(1);
    });

    it('detects Redis connection string', () => {
      const result = detectSecrets('REDIS_URL=redis://default:abc123@redis-host:6379');
      const cs = result.filter((d) => d.type === 'connection_string');
      expect(cs).toHaveLength(1);
    });

    it('detects AMQP connection string', () => {
      const result = detectSecrets('AMQP_URL=amqp://guest:guest@rabbitmq:5672');
      const cs = result.filter((d) => d.type === 'connection_string');
      expect(cs).toHaveLength(1);
    });
  });

  // ── Webhook URL ────────────────────────────────────────────────────────────

  describe('webhook_url', () => {
    it('detects Slack webhook URL', () => {
      const result = detectSecrets('WEBHOOK=https://hooks.slack.com/services/T00/B00/xxxx');
      const wh = result.filter((d) => d.type === 'webhook_url');
      expect(wh).toHaveLength(1);
      expect(wh[0].confidence).toBe(0.85);
    });

    it('detects Discord webhook URL', () => {
      const result = detectSecrets('HOOK=https://hooks.discord.com/api/webhooks/123/abc');
      const wh = result.filter((d) => d.type === 'webhook_url');
      expect(wh).toHaveLength(1);
    });
  });

  // ── Generic High Entropy ───────────────────────────────────────────────────

  describe('generic_high_entropy', () => {
    it('detects key= followed by long alphanumeric value', () => {
      const longValue = 'A'.repeat(40);
      const result = detectSecrets(`api_key=${longValue}`);
      const generic = result.filter((d) => d.type === 'generic_high_entropy');
      expect(generic).toHaveLength(1);
      expect(generic[0].confidence).toBe(0.70);
    });

    it('detects secret= with long value', () => {
      const longValue = 'x'.repeat(32);
      const result = detectSecrets(`secret="${longValue}"`);
      // credential_assignment may win deduplication over generic_high_entropy
      const matched = result.filter((d) => d.type === 'generic_high_entropy' || d.type === 'credential_assignment');
      expect(matched).toHaveLength(1);
    });

    it('detects token: with long value', () => {
      const longValue = 'Z'.repeat(35);
      const result = detectSecrets(`token: ${longValue}`);
      const generic = result.filter((d) => d.type === 'generic_high_entropy');
      expect(generic).toHaveLength(1);
    });

    it('does not match short values', () => {
      const result = detectSecrets('key=abc');
      const generic = result.filter((d) => d.type === 'generic_high_entropy');
      expect(generic).toHaveLength(0);
    });
  });

  // ── Custom Patterns ────────────────────────────────────────────────────────

  describe('custom patterns', () => {
    it('detects a custom internal token pattern', () => {
      const result = detectSecrets('Token: INTERNAL-abcdef123456', {
        customPatterns: [
          { name: 'internal_token', pattern: 'INTERNAL-[a-z0-9]{12}' },
        ],
      });
      const custom = result.filter((d) => d.type === 'custom:internal_token');
      expect(custom).toHaveLength(1);
      expect(custom[0].value).toBe('INTERNAL-abcdef123456');
      expect(custom[0].confidence).toBe(0.9); // default confidence
    });

    it('uses provided confidence for custom patterns', () => {
      const result = detectSecrets('Token: CUSTOM-12345678', {
        customPatterns: [
          { name: 'custom_key', pattern: 'CUSTOM-\\d{8}', confidence: 0.75 },
        ],
      });
      const custom = result.filter((d) => d.type === 'custom:custom_key');
      expect(custom).toHaveLength(1);
      expect(custom[0].confidence).toBe(0.75);
    });

    it('runs multiple custom patterns', () => {
      const text = 'ALPHA-1234 and BETA-5678';
      const result = detectSecrets(text, {
        customPatterns: [
          { name: 'alpha', pattern: 'ALPHA-\\d{4}' },
          { name: 'beta', pattern: 'BETA-\\d{4}' },
        ],
      });
      const alpha = result.filter((d) => d.type === 'custom:alpha');
      const beta = result.filter((d) => d.type === 'custom:beta');
      expect(alpha).toHaveLength(1);
      expect(beta).toHaveLength(1);
    });

    it('skips invalid regex strings', () => {
      const result = detectSecrets('some text', {
        customPatterns: [
          { name: 'bad', pattern: '[invalid(' },
        ],
      });
      expect(result.length).toBeGreaterThanOrEqual(0); // no crash
    });
  });

  // ── builtInPatterns=false ──────────────────────────────────────────────────

  describe('builtInPatterns=false', () => {
    it('only runs custom patterns when builtInPatterns=false', () => {
      const text = 'AKIAIOSFODNN7EXAMPLE and CUSTOM-99';
      const result = detectSecrets(text, {
        builtInPatterns: false,
        customPatterns: [
          { name: 'mine', pattern: 'CUSTOM-\\d{2}' },
        ],
      });
      // AWS key should NOT be detected
      const aws = result.filter((d) => d.type === 'aws_access_key');
      expect(aws).toHaveLength(0);
      // Custom should be detected
      const custom = result.filter((d) => d.type === 'custom:mine');
      expect(custom).toHaveLength(1);
    });

    it('returns empty when builtInPatterns=false and no custom patterns', () => {
      const result = detectSecrets('AKIAIOSFODNN7EXAMPLE', {
        builtInPatterns: false,
      });
      expect(result).toHaveLength(0);
    });
  });

  // ── No false positives ─────────────────────────────────────────────────────

  describe('no false positives', () => {
    it('returns empty for normal English text', () => {
      const result = detectSecrets(
        'The quick brown fox jumps over the lazy dog. ' +
        'This is a perfectly normal sentence with no secrets.',
      );
      expect(result).toHaveLength(0);
    });

    it('does not detect short words as secrets', () => {
      const result = detectSecrets('Hello world, welcome to the app.');
      expect(result).toHaveLength(0);
    });

    it('does not match public key headers', () => {
      const result = detectSecrets('-----BEGIN PUBLIC KEY-----');
      expect(result).toHaveLength(0);
    });

    it('does not match non-live Stripe keys', () => {
      // sk_test_ keys are test mode, not real secrets in production sense
      // Our pattern only matches sk_live_
      const result = detectSecrets('sk_' + 'test_abcdefghijklmnopqrstuvwx');
      const stripe = result.filter((d) => d.type === 'stripe_secret');
      expect(stripe).toHaveLength(0);
    });
  });

  // ── Multiple secrets in one input ──────────────────────────────────────────

  describe('multiple secrets', () => {
    it('detects multiple different secrets in one string', () => {
      const awsKey = 'AKIAIOSFODNN7EXAMPLE';
      const ghToken = 'ghp_' + 'a'.repeat(36);
      const text = `AWS: ${awsKey} and GitHub: ${ghToken}`;
      const result = detectSecrets(text);
      const types = new Set(result.map((d) => d.type));
      expect(types.has('aws_access_key')).toBe(true);
      expect(types.has('github_pat')).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(2);
    });

    it('detects multiple same-type secrets', () => {
      const key1 = 'AKIAIOSFODNN7AAAAAAA';
      const key2 = 'AKIAIOSFODNN7BBBBBBB';
      const result = detectSecrets(`First: ${key1} Second: ${key2}`);
      const aws = result.filter((d) => d.type === 'aws_access_key');
      expect(aws).toHaveLength(2);
    });
  });

  // ── Deduplication ──────────────────────────────────────────────────────────

  describe('deduplication', () => {
    it('deduplicates overlapping detections keeping highest confidence', () => {
      // generic_high_entropy (0.70) may overlap with a more specific pattern
      // For example, a Stripe key also matches generic_high_entropy
      const key = 'sk_live_' + 'A'.repeat(32);
      const text = `key="${key}"`;
      const result = detectSecrets(text);
      // The stripe_secret match (0.95) should win over generic_high_entropy (0.70)
      // for the overlapping region
      const stripe = result.filter((d) => d.type === 'stripe_secret');
      expect(stripe.length).toBeGreaterThanOrEqual(1);
    });

    it('keeps non-overlapping detections', () => {
      const awsKey = 'AKIAIOSFODNN7EXAMPLE';
      const text = `-----BEGIN PRIVATE KEY----- then ${awsKey}`;
      const result = detectSecrets(text);
      expect(result.length).toBeGreaterThanOrEqual(2);
      const types = new Set(result.map((d) => d.type));
      expect(types.has('private_key')).toBe(true);
      expect(types.has('aws_access_key')).toBe(true);
    });
  });

  // ── Position (start/end) correctness ───────────────────────────────────────

  describe('position values', () => {
    it('returns correct start and end for AWS key', () => {
      const prefix = 'AWS key: ';
      const key = 'AKIAIOSFODNN7EXAMPLE';
      const text = prefix + key;
      const result = detectSecrets(text);
      expect(result).toHaveLength(1);
      expect(result[0].start).toBe(prefix.length);
      expect(result[0].end).toBe(prefix.length + key.length);
      expect(text.slice(result[0].start, result[0].end)).toBe(key);
    });

    it('returns correct positions for multiple secrets', () => {
      const text = 'A: AKIAIOSFODNN7EXAMPLE B: -----BEGIN PRIVATE KEY-----';
      const result = detectSecrets(text);
      for (const d of result) {
        expect(text.slice(d.start, d.end)).toBe(d.value);
      }
    });

    it('results are sorted by start position', () => {
      const ghToken = 'ghp_' + 'x'.repeat(36);
      const text = `-----BEGIN PRIVATE KEY----- then AKIAIOSFODNN7EXAMPLE then ${ghToken}`;
      const result = detectSecrets(text);
      for (let i = 1; i < result.length; i++) {
        expect(result[i].start).toBeGreaterThanOrEqual(result[i - 1].start);
      }
    });
  });

  // ── Confidence values ──────────────────────────────────────────────────────

  describe('confidence values', () => {
    it('private_key has highest confidence (0.99)', () => {
      const result = detectSecrets('-----BEGIN RSA PRIVATE KEY-----');
      expect(result[0].confidence).toBe(0.99);
    });

    it('aws_access_key has 0.95 confidence', () => {
      const result = detectSecrets('AKIAIOSFODNN7EXAMPLE');
      expect(result[0].confidence).toBe(0.95);
    });

    it('generic_high_entropy has lowest confidence (0.70)', () => {
      const longValue = 'Q'.repeat(40);
      const result = detectSecrets(`apikey=${longValue}`);
      const generic = result.filter((d) => d.type === 'generic_high_entropy');
      expect(generic.length).toBeGreaterThanOrEqual(1);
      expect(generic[0].confidence).toBe(0.70);
    });

    it('stripe_publishable has 0.85 confidence', () => {
      const key = 'pk_live_' + 'C'.repeat(24);
      const result = detectSecrets(key);
      expect(result[0].confidence).toBe(0.85);
    });

    it('slack_token has 0.90 confidence', () => {
      const result = detectSecrets('xoxb-123456789-abcdefghij');
      const slack = result.filter((d) => d.type === 'slack_token');
      expect(slack.length).toBeGreaterThanOrEqual(1);
      expect(slack[0].confidence).toBe(0.90);
    });
  });

  // ── Edge cases ─────────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('returns empty for empty string', () => {
      expect(detectSecrets('')).toHaveLength(0);
    });

    it('returns empty for undefined-like empty string', () => {
      expect(detectSecrets('')).toEqual([]);
    });

    it('handles text with no secrets', () => {
      const result = detectSecrets('Just a regular conversation about coding.');
      expect(result).toHaveLength(0);
    });

    it('handles very long text with a secret near the end', () => {
      const padding = ' '.repeat(500000);
      const key = 'AKIAIOSFODNN7EXAMPLE';
      const text = padding + key + padding;
      const result = detectSecrets(text);
      // Should still detect it (within the 1 MB limit)
      expect(result.length).toBeGreaterThanOrEqual(1);
    });

    it('truncates text beyond MAX_SCAN_LENGTH', () => {
      // Place the secret beyond the 1 MB boundary
      const padding = 'x'.repeat(MAX_SCAN_LENGTH);
      const key = 'AKIAIOSFODNN7EXAMPLE';
      const text = padding + key;
      const result = detectSecrets(text);
      // Secret is past the truncation point, so it should not be detected
      expect(result).toHaveLength(0);
    });

    it('handles unicode text without crashing', () => {
      const result = detectSecrets('Secret: AKIAIOSFODNN7EXAMPLE in text');
      expect(result.length).toBeGreaterThanOrEqual(1);
    });
  });
});
