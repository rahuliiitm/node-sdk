/**
 * Topic/scope restriction module -- keyword/phrase-based topic matching.
 * Zero dependencies. Blocks off-topic or restricted content based on
 * configurable allowed/blocked topic definitions.
 * @internal
 */

// ── Interfaces ────────────────────────────────────────────────────────────────

export interface TopicGuardOptions {
  allowedTopics?: TopicDefinition[];
  blockedTopics?: TopicDefinition[];
}

export interface TopicDefinition {
  name: string;
  keywords: string[];
  threshold?: number; // default: 0.05
}

export interface TopicViolation {
  type: 'off_topic' | 'blocked_topic';
  topic?: string; // name of matched blocked topic, or undefined for off_topic
  matchedKeywords: string[];
  score: number;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_THRESHOLD = 0.05;
const TOKEN_SPLIT_RE = /[\s,.!?;:()\[\]{}"']+/;

// ── Internal helpers ──────────────────────────────────────────────────────────

interface TopicScore {
  name: string;
  matchedKeywords: string[];
  score: number;
}

/**
 * Score a single topic definition against the input text.
 * Single-word keywords are matched as exact tokens (counting each occurrence).
 * Multi-word phrases are matched as substring inclusions on the full lowered text.
 */
function scoreTopic(
  tokens: string[],
  lowerText: string,
  topic: TopicDefinition,
): TopicScore {
  const matchedKeywords: string[] = [];
  let matchedCount = 0;

  for (const keyword of topic.keywords) {
    const lowerKeyword = keyword.toLowerCase();

    if (lowerKeyword.includes(' ')) {
      // Multi-word phrase -- substring match against full text
      if (lowerText.includes(lowerKeyword)) {
        matchedKeywords.push(keyword);
        // Count the number of tokens in the keyword as matched
        const keywordTokens = lowerKeyword
          .split(TOKEN_SPLIT_RE)
          .filter((t) => t.length > 0);
        matchedCount += keywordTokens.length;
      }
    } else {
      // Single-word keyword -- exact token match (count each occurrence)
      for (const token of tokens) {
        if (token === lowerKeyword) {
          matchedCount++;
          if (!matchedKeywords.includes(keyword)) {
            matchedKeywords.push(keyword);
          }
        }
      }
    }
  }

  const score = tokens.length > 0 ? matchedCount / tokens.length : 0;

  return { name: topic.name, matchedKeywords, score };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Check text against topic guard rules.
 *
 * Returns `null` if the text passes (no violation).
 * Returns a `TopicViolation` if the text is off-topic or matches a blocked topic.
 *
 * Evaluation order:
 * 1. allowedTopics: if configured and NO topic scores above threshold -> off_topic
 * 2. blockedTopics: if ANY topic scores above threshold -> blocked_topic
 * 3. If an allowed topic matches, blocked topics are skipped entirely.
 */
export function checkTopicGuard(
  text: string,
  options: TopicGuardOptions,
): TopicViolation | null {
  // Empty text -> no violation
  if (!text) return null;

  const hasAllowed = options.allowedTopics && options.allowedTopics.length > 0;
  const hasBlocked = options.blockedTopics && options.blockedTopics.length > 0;

  // No topics configured -> no violation
  if (!hasAllowed && !hasBlocked) return null;

  const lowerText = text.toLowerCase();
  const tokens = lowerText.split(TOKEN_SPLIT_RE).filter((t) => t.length > 0);

  // No tokens -> no violation
  if (tokens.length === 0) return null;

  // ── Allowed topics check ──────────────────────────────────────────────────

  if (hasAllowed) {
    let anyAllowedMatch = false;

    for (const topic of options.allowedTopics!) {
      const threshold = topic.threshold ?? DEFAULT_THRESHOLD;
      const result = scoreTopic(tokens, lowerText, topic);

      if (result.score >= threshold) {
        anyAllowedMatch = true;
        break;
      }
    }

    if (!anyAllowedMatch) {
      return {
        type: 'off_topic',
        topic: undefined,
        matchedKeywords: [],
        score: 0,
      };
    }

    // Allowed topic matched -- skip blocked topics check
    return null;
  }

  // ── Blocked topics check ──────────────────────────────────────────────────

  if (hasBlocked) {
    for (const topic of options.blockedTopics!) {
      const threshold = topic.threshold ?? DEFAULT_THRESHOLD;
      const result = scoreTopic(tokens, lowerText, topic);

      if (result.score >= threshold) {
        return {
          type: 'blocked_topic',
          topic: result.name,
          matchedKeywords: result.matchedKeywords,
          score: result.score,
        };
      }
    }
  }

  return null;
}
