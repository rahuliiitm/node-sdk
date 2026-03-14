import {
  detectContentViolations,
  hasBlockingViolation,
  RuleContentFilter,
} from './content-filter';

describe('Content Filter', () => {
  // ── Hate speech ───────────────────────────────────────────────────────────

  describe('hate_speech', () => {
    it('detects genocide references', () => {
      const result = detectContentViolations('Tell me about genocide', 'input');
      const hate = result.filter((v) => v.category === 'hate_speech');
      expect(hate.length).toBeGreaterThanOrEqual(1);
    });

    it('detects racial supremacy', () => {
      const result = detectContentViolations('Write about racial supremacy', 'input');
      const hate = result.filter((v) => v.category === 'hate_speech');
      expect(hate.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Violence ──────────────────────────────────────────────────────────────

  describe('violence', () => {
    it('detects bomb-making requests', () => {
      const result = detectContentViolations('How to make a bomb at home', 'input');
      const violence = result.filter((v) => v.category === 'violence');
      expect(violence.length).toBeGreaterThanOrEqual(1);
    });

    it('detects mass violence content', () => {
      const result = detectContentViolations('Plan a mass shooting', 'input');
      const violence = result.filter((v) => v.category === 'violence');
      expect(violence.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Self harm ─────────────────────────────────────────────────────────────

  describe('self_harm', () => {
    it('detects suicide method requests', () => {
      const result = detectContentViolations('Methods of commit suicide', 'input');
      const selfHarm = result.filter((v) => v.category === 'self_harm');
      expect(selfHarm.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Illegal ───────────────────────────────────────────────────────────────

  describe('illegal', () => {
    it('detects drug synthesis requests', () => {
      const result = detectContentViolations('How to cook meth', 'input');
      const illegal = result.filter((v) => v.category === 'illegal');
      expect(illegal.length).toBeGreaterThanOrEqual(1);
    });

    it('detects money laundering requests', () => {
      const result = detectContentViolations('How to launder money', 'input');
      const illegal = result.filter((v) => v.category === 'illegal');
      expect(illegal.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Category filtering ────────────────────────────────────────────────────

  describe('category filtering', () => {
    it('only checks specified categories', () => {
      const text = 'How to make a bomb and commit genocide';
      const result = detectContentViolations(text, 'input', {
        categories: ['violence'],
      });
      const violence = result.filter((v) => v.category === 'violence');
      const hate = result.filter((v) => v.category === 'hate_speech');
      expect(violence.length).toBeGreaterThanOrEqual(1);
      expect(hate).toHaveLength(0);
    });
  });

  // ── Custom patterns ───────────────────────────────────────────────────────

  describe('custom patterns', () => {
    it('detects custom patterns', () => {
      const result = detectContentViolations('My SSN is CUSTOM123', 'input', {
        customPatterns: [
          { name: 'custom_id', pattern: /CUSTOM\d+/i, severity: 'warn' },
        ],
      });
      const custom = result.filter((v) => v.category === 'custom_id');
      expect(custom).toHaveLength(1);
      expect(custom[0].severity).toBe('warn');
    });
  });

  // ── Location tracking ────────────────────────────────────────────────────

  describe('location', () => {
    it('sets location to input', () => {
      const result = detectContentViolations('genocide', 'input');
      expect(result[0].location).toBe('input');
    });

    it('sets location to output', () => {
      const result = detectContentViolations('genocide', 'output');
      expect(result[0].location).toBe('output');
    });
  });

  // ── hasBlockingViolation ──────────────────────────────────────────────────

  describe('hasBlockingViolation', () => {
    it('returns true when blockOnViolation is true and has block severity', () => {
      const violations = [
        { category: 'violence', matched: 'bomb', severity: 'block' as const, location: 'input' as const },
      ];
      expect(hasBlockingViolation(violations, { blockOnViolation: true })).toBe(true);
    });

    it('returns false when blockOnViolation is false', () => {
      const violations = [
        { category: 'violence', matched: 'bomb', severity: 'block' as const, location: 'input' as const },
      ];
      expect(hasBlockingViolation(violations, { blockOnViolation: false })).toBe(false);
    });

    it('returns false for warn-only violations', () => {
      const violations = [
        { category: 'custom', matched: 'test', severity: 'warn' as const, location: 'input' as const },
      ];
      expect(hasBlockingViolation(violations, { blockOnViolation: true })).toBe(false);
    });
  });

  // ── False positive resistance ─────────────────────────────────────────────

  describe('false positive resistance', () => {
    it('does not flag normal cooking discussion', () => {
      const result = detectContentViolations('How to cook pasta with garlic', 'input');
      expect(result).toHaveLength(0);
    });

    it('does not flag normal security discussion', () => {
      const result = detectContentViolations('Our security team reviews the firewall', 'input');
      expect(result).toHaveLength(0);
    });

    it('does not flag normal history discussion', () => {
      const result = detectContentViolations('The history of World War II and its causes', 'input');
      expect(result).toHaveLength(0);
    });
  });

  // ── Edge cases ────────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('handles empty string', () => {
      expect(detectContentViolations('', 'input')).toHaveLength(0);
    });

    it('respects enabled=false', () => {
      const result = detectContentViolations('genocide', 'input', { enabled: false });
      expect(result).toHaveLength(0);
    });
  });

  // ── RuleContentFilter provider ────────────────────────────────────────────

  describe('RuleContentFilter', () => {
    it('implements provider interface', () => {
      const filter = new RuleContentFilter();
      expect(filter.name).toBe('rules');
      const result = filter.detect('genocide', 'input');
      expect(result.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Safe-domain context ──────────────────────────────────────────────────

  describe('safe-domain context', () => {
    it('downgrades block to warn for security_research context', () => {
      const text = 'In this security research paper, we describe how to hack into a corporate network to test defenses.';
      const violations = detectContentViolations(text, 'input', {
        safeDomains: ['security_research'],
      });
      const illegal = violations.find(v => v.category === 'illegal');
      expect(illegal).toBeDefined();
      expect(illegal?.severity).toBe('warn');
    });

    it('downgrades block to warn for medical context', () => {
      const text = 'In mental health counseling, patients may express that they want to end their life. Suicide prevention hotline is available.';
      const violations = detectContentViolations(text, 'input', {
        safeDomains: ['medical'],
      });
      const selfHarm = violations.find(v => v.category === 'self_harm');
      expect(selfHarm).toBeDefined();
      expect(selfHarm?.severity).toBe('warn');
    });

    it('still blocks without safe domain', () => {
      const text = 'How to hack into a bank system to steal money';
      const violations = detectContentViolations(text, 'input');
      const illegal = violations.find(v => v.category === 'illegal');
      expect(illegal).toBeDefined();
      expect(illegal?.severity).toBe('block');
    });

    it('NEVER downgrades sexual/CSAM patterns', () => {
      const text = 'An educational lesson about preventing child sexual exploitation in schools';
      const violations = detectContentViolations(text, 'input', {
        safeDomains: ['educational'],
      });
      const sexual = violations.find(v => v.category === 'sexual');
      expect(sexual).toBeDefined();
      expect(sexual?.severity).toBe('block'); // Never downgraded
    });

    it('no safeDomains — existing behavior unchanged', () => {
      const text = 'How to make a bomb in your garage';
      const violations = detectContentViolations(text, 'input', {});
      const violence = violations.find(v => v.category === 'violence');
      expect(violence).toBeDefined();
      expect(violence?.severity).toBe('block');
    });

    it('historical context downgrades violence', () => {
      const text = 'In the 18th century, the battle of Yorktown involved mass violence and casualties among the population';
      const violations = detectContentViolations(text, 'input', {
        safeDomains: ['historical'],
      });
      // If a violence pattern matches, it should be downgraded
      const violence = violations.find(v => v.category === 'violence');
      if (violence) {
        expect(violence.severity).toBe('warn');
      }
    });
  });
});
