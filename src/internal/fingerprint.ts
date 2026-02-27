import { createHash } from 'crypto';

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const ISO_DATE_RE = /\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?/g;
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const LONG_NUMBER_RE = /\b\d{4,}\b/g;
const URL_RE = /https?:\/\/[^\s]+/g;

function normalizePrompt(text: string): string {
  return text
    .replace(UUID_RE, '<UUID>')
    .replace(ISO_DATE_RE, '<DATE>')
    .replace(EMAIL_RE, '<EMAIL>')
    .replace(URL_RE, '<URL>')
    .replace(LONG_NUMBER_RE, '<NUM>')
    .replace(/\s+/g, ' ')
    .trim();
}

function hashPrompt(normalizedText: string): string {
  return createHash('sha256').update(normalizedText).digest('hex');
}

export interface PromptFingerprint {
  systemHash: string | null;
  fullHash: string;
  normalizedSystem: string | null;
  promptPreview: string;
}

/**
 * Fingerprint a set of chat messages for deduplication and tracking.
 * @internal
 */
export function fingerprintMessages(
  messages: Array<{ role: string; content: string }>,
  systemPrompt?: string,
): PromptFingerprint {
  const fullText = messages.map((m) => `${m.role}:${m.content}`).join('\n');
  const normalizedFull = normalizePrompt(fullText);
  const fullHash = hashPrompt(normalizedFull);

  let systemHash: string | null = null;
  let normalizedSystem: string | null = null;

  if (systemPrompt) {
    normalizedSystem = normalizePrompt(systemPrompt);
    systemHash = hashPrompt(normalizedSystem);
  }

  const promptPreview = fullText.slice(0, 200);

  return { systemHash, fullHash, normalizedSystem, promptPreview };
}
