import {
  checkTopicGuard,
  type TopicGuardOptions,
  type TopicViolation,
  type TopicDefinition,
} from './topic-guard';

describe('Topic Guard', () => {
  // ── No topics configured ──────────────────────────────────────────────────

  describe('no topics configured', () => {
    it('returns null when no topics are configured', () => {
      const result = checkTopicGuard('Hello world', {});
      expect(result).toBeNull();
    });

    it('returns null with empty allowed and blocked arrays', () => {
      const result = checkTopicGuard('Hello world', {
        allowedTopics: [],
        blockedTopics: [],
      });
      expect(result).toBeNull();
    });
  });

  // ── Empty text ────────────────────────────────────────────────────────────

  describe('empty text', () => {
    it('returns null for empty string', () => {
      const result = checkTopicGuard('', {
        allowedTopics: [{ name: 'tech', keywords: ['code'] }],
      });
      expect(result).toBeNull();
    });

    it('returns null for whitespace-only string', () => {
      const result = checkTopicGuard('   \t\n  ', {
        blockedTopics: [{ name: 'violence', keywords: ['kill'] }],
      });
      expect(result).toBeNull();
    });
  });

  // ── Allowed topics ────────────────────────────────────────────────────────

  describe('allowed topics', () => {
    const allowedOpts: TopicGuardOptions = {
      allowedTopics: [
        { name: 'programming', keywords: ['code', 'function', 'variable', 'class', 'api'] },
        { name: 'cooking', keywords: ['recipe', 'ingredient', 'bake', 'cook', 'oven'] },
      ],
    };

    it('returns null when input matches an allowed topic', () => {
      const result = checkTopicGuard(
        'Write a function to sort an array using code',
        allowedOpts,
      );
      expect(result).toBeNull();
    });

    it('returns null when input matches a different allowed topic', () => {
      const result = checkTopicGuard(
        'What recipe should I bake for dinner tonight',
        allowedOpts,
      );
      expect(result).toBeNull();
    });

    it('returns off_topic when input matches no allowed topic', () => {
      const result = checkTopicGuard(
        'Tell me about the history of ancient Rome',
        allowedOpts,
      );
      expect(result).not.toBeNull();
      expect(result!.type).toBe('off_topic');
      expect(result!.topic).toBeUndefined();
      expect(result!.matchedKeywords).toEqual([]);
      expect(result!.score).toBe(0);
    });

    it('returns off_topic when no keywords match at all', () => {
      const result = checkTopicGuard(
        'The weather is sunny and warm outside today',
        allowedOpts,
      );
      expect(result).not.toBeNull();
      expect(result!.type).toBe('off_topic');
    });
  });

  // ── Blocked topics ────────────────────────────────────────────────────────

  describe('blocked topics', () => {
    const blockedOpts: TopicGuardOptions = {
      blockedTopics: [
        { name: 'politics', keywords: ['election', 'democrat', 'republican', 'vote', 'president'] },
        { name: 'gambling', keywords: ['bet', 'casino', 'poker', 'slot', 'wager'] },
      ],
    };

    it('returns blocked_topic when input matches a blocked topic', () => {
      const result = checkTopicGuard(
        'Who should I vote for in the election',
        blockedOpts,
      );
      expect(result).not.toBeNull();
      expect(result!.type).toBe('blocked_topic');
      expect(result!.topic).toBe('politics');
      expect(result!.matchedKeywords).toContain('vote');
      expect(result!.matchedKeywords).toContain('election');
      expect(result!.score).toBeGreaterThan(0);
    });

    it('returns null when input does not match any blocked topic', () => {
      const result = checkTopicGuard(
        'How do I write a unit test in TypeScript',
        blockedOpts,
      );
      expect(result).toBeNull();
    });

    it('returns the first matching blocked topic when multiple match', () => {
      const opts: TopicGuardOptions = {
        blockedTopics: [
          { name: 'first_blocked', keywords: ['alpha', 'beta'], threshold: 0.01 },
          { name: 'second_blocked', keywords: ['alpha', 'gamma'], threshold: 0.01 },
        ],
      };
      const result = checkTopicGuard('alpha beta gamma', opts);
      expect(result).not.toBeNull();
      expect(result!.topic).toBe('first_blocked');
    });
  });

  // ── Allowed precedence over blocked ───────────────────────────────────────

  describe('allowed + blocked interaction', () => {
    const bothOpts: TopicGuardOptions = {
      allowedTopics: [
        { name: 'tech', keywords: ['code', 'software', 'programming', 'api', 'deploy'] },
      ],
      blockedTopics: [
        { name: 'politics', keywords: ['election', 'vote', 'president'] },
      ],
    };

    it('allowed match takes precedence -- skips blocked check', () => {
      const result = checkTopicGuard(
        'deploy the code for the election vote software',
        bothOpts,
      );
      expect(result).toBeNull();
    });

    it('returns off_topic when allowed topics configured but none match', () => {
      const result = checkTopicGuard(
        'Who should I vote for in the election',
        bothOpts,
      );
      expect(result).not.toBeNull();
      expect(result!.type).toBe('off_topic');
    });
  });

  // ── Multi-word keywords ───────────────────────────────────────────────────

  describe('multi-word keywords', () => {
    it('matches multi-word keywords as substring', () => {
      const opts: TopicGuardOptions = {
        blockedTopics: [
          { name: 'restricted', keywords: ['machine learning', 'deep learning'], threshold: 0.01 },
        ],
      };
      const result = checkTopicGuard(
        'Tell me about machine learning algorithms and neural networks',
        opts,
      );
      expect(result).not.toBeNull();
      expect(result!.type).toBe('blocked_topic');
      expect(result!.matchedKeywords).toContain('machine learning');
    });

    it('matches multi-word keywords case-insensitively', () => {
      const opts: TopicGuardOptions = {
        blockedTopics: [
          { name: 'restricted', keywords: ['Neural Network'], threshold: 0.01 },
        ],
      };
      const result = checkTopicGuard(
        'Tell me about neural network architectures and transformers',
        opts,
      );
      expect(result).not.toBeNull();
      expect(result!.matchedKeywords).toContain('Neural Network');
    });

    it('does not match when multi-word keyword words are not adjacent', () => {
      const opts: TopicGuardOptions = {
        blockedTopics: [
          { name: 'restricted', keywords: ['red car'] },
        ],
      };
      const result = checkTopicGuard('The red big car was fast', opts);
      expect(result).toBeNull();
    });
  });

  // ── Custom threshold ──────────────────────────────────────────────────────

  describe('custom threshold', () => {
    it('respects higher threshold -- does not trigger on few matches', () => {
      const opts: TopicGuardOptions = {
        blockedTopics: [
          { name: 'politics', keywords: ['election', 'vote'], threshold: 0.5 },
        ],
      };
      const result = checkTopicGuard(
        'Should I vote for my favorite show on TV tonight',
        opts,
      );
      expect(result).toBeNull();
    });

    it('triggers when score meets custom threshold', () => {
      const opts: TopicGuardOptions = {
        blockedTopics: [
          { name: 'politics', keywords: ['election', 'vote', 'president'], threshold: 0.3 },
        ],
      };
      const result = checkTopicGuard(
        'vote election president for democracy',
        opts,
      );
      expect(result).not.toBeNull();
      expect(result!.type).toBe('blocked_topic');
    });

    it('uses default threshold of 0.05 when not specified', () => {
      const opts: TopicGuardOptions = {
        blockedTopics: [
          { name: 'test_topic', keywords: ['trigger'] },
        ],
      };
      // 1 match out of ~11 tokens, above default 0.05
      const result = checkTopicGuard(
        'this is a long sentence with many words and one trigger keyword',
        opts,
      );
      expect(result).not.toBeNull();
    });
  });

  // ── Score calculation ─────────────────────────────────────────────────────

  describe('score calculation', () => {
    it('calculates score as matchedCount / totalTokens', () => {
      const opts: TopicGuardOptions = {
        blockedTopics: [
          { name: 'test', keywords: ['alpha', 'beta', 'gamma'], threshold: 0.01 },
        ],
      };
      // 2 matches (alpha, beta) out of 5 tokens = 0.4
      const result = checkTopicGuard('alpha beta delta epsilon zeta', opts);
      expect(result).not.toBeNull();
      expect(result!.score).toBeCloseTo(0.4, 5);
      expect(result!.matchedKeywords).toContain('alpha');
      expect(result!.matchedKeywords).toContain('beta');
    });

    it('counts multiple occurrences of same keyword', () => {
      const opts: TopicGuardOptions = {
        blockedTopics: [
          { name: 'test', keywords: ['hello'], threshold: 0.01 },
        ],
      };
      // "hello" appears twice in 4 tokens = 2/4 = 0.5
      const result = checkTopicGuard('hello world hello again', opts);
      expect(result).not.toBeNull();
      expect(result!.matchedKeywords).toEqual(['hello']);
      expect(result!.score).toBeCloseTo(0.5, 5);
    });
  });

  // ── Case insensitivity ────────────────────────────────────────────────────

  describe('case insensitivity', () => {
    it('matches keywords regardless of case', () => {
      const opts: TopicGuardOptions = {
        blockedTopics: [
          { name: 'test', keywords: ['JavaScript', 'REACT'], threshold: 0.01 },
        ],
      };
      const result = checkTopicGuard('I love javascript and react frameworks', opts);
      expect(result).not.toBeNull();
      expect(result!.matchedKeywords).toContain('JavaScript');
      expect(result!.matchedKeywords).toContain('REACT');
    });

    it('matches input with mixed case against lowercase keywords', () => {
      const opts: TopicGuardOptions = {
        allowedTopics: [
          { name: 'coding', keywords: ['python', 'code'] },
        ],
      };
      const result = checkTopicGuard('I write PYTHON CODE daily', opts);
      expect(result).toBeNull();
    });
  });

  // ── Edge cases ────────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('handles single-token input', () => {
      const opts: TopicGuardOptions = {
        blockedTopics: [
          { name: 'test', keywords: ['blocked'], threshold: 0.5 },
        ],
      };
      const result = checkTopicGuard('blocked', opts);
      expect(result).not.toBeNull();
      expect(result!.score).toBeCloseTo(1.0, 5);
    });

    it('handles topic with empty keywords array', () => {
      const opts: TopicGuardOptions = {
        blockedTopics: [{ name: 'empty', keywords: [] }],
      };
      expect(checkTopicGuard('some text here', opts)).toBeNull();
    });

    it('returns null when allowedTopics is empty array', () => {
      expect(checkTopicGuard('anything goes here', { allowedTopics: [] })).toBeNull();
    });

    it('returns null when blockedTopics is empty array', () => {
      expect(checkTopicGuard('anything goes here', { blockedTopics: [] })).toBeNull();
    });
  });
});
