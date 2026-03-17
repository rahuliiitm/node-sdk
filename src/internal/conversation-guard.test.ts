import { ConversationGuard } from './conversation-guard';

describe('ConversationGuard', () => {
  // ── Turn limits ─────────────────────────────────────────────────────────────

  describe('turn limits', () => {
    it('returns null when under maxTurns', async () => {
      const guard = new ConversationGuard({ maxTurns: 3 });
      await guard.recordTurn({ userMessage: 'hi', responseText: 'hello', toolCallCount: 0 });
      expect(guard.checkPreCall()).toBeNull();
    });

    it('returns violation at maxTurns', async () => {
      const guard = new ConversationGuard({ maxTurns: 2 });
      await guard.recordTurn({ userMessage: 'q1', responseText: 'a1', toolCallCount: 0 });
      await guard.recordTurn({ userMessage: 'q2', responseText: 'a2', toolCallCount: 0 });
      const violation = guard.checkPreCall();
      expect(violation).not.toBeNull();
      expect(violation!.type).toBe('max_turns');
      expect(violation!.currentTurn).toBe(2);
    });

    it('returns violation over maxTurns', async () => {
      const guard = new ConversationGuard({ maxTurns: 1 });
      await guard.recordTurn({ userMessage: 'hi', responseText: 'yo', toolCallCount: 0 });
      await guard.recordTurn({ userMessage: 'again', responseText: 'yep', toolCallCount: 0 });
      const violation = guard.checkPreCall();
      expect(violation).not.toBeNull();
      expect(violation!.type).toBe('max_turns');
    });

    it('turn counter increments correctly', async () => {
      const guard = new ConversationGuard({ maxTurns: 10 });
      expect(guard.turnCount).toBe(0);
      await guard.recordTurn({ userMessage: 'a', responseText: 'b', toolCallCount: 0 });
      expect(guard.turnCount).toBe(1);
      await guard.recordTurn({ userMessage: 'c', responseText: 'd', toolCallCount: 0 });
      expect(guard.turnCount).toBe(2);
    });

    it('reset() resets turn counter', async () => {
      const guard = new ConversationGuard({ maxTurns: 5 });
      await guard.recordTurn({ userMessage: 'a', responseText: 'b', toolCallCount: 0 });
      await guard.recordTurn({ userMessage: 'c', responseText: 'd', toolCallCount: 0 });
      expect(guard.turnCount).toBe(2);
      guard.reset();
      expect(guard.turnCount).toBe(0);
      expect(guard.checkPreCall()).toBeNull();
    });

    it('no maxTurns allows unlimited turns', async () => {
      const guard = new ConversationGuard({});
      for (let i = 0; i < 50; i++) {
        await guard.recordTurn({ userMessage: `q${i}`, responseText: `a${i}`, toolCallCount: 0 });
      }
      expect(guard.checkPreCall()).toBeNull();
    });

    it('maxTurns = 1 allows exactly one call', async () => {
      const guard = new ConversationGuard({ maxTurns: 1 });
      expect(guard.checkPreCall()).toBeNull(); // First call allowed
      await guard.recordTurn({ userMessage: 'hi', responseText: 'hello', toolCallCount: 0 });
      const violation = guard.checkPreCall();
      expect(violation).not.toBeNull();
      expect(violation!.type).toBe('max_turns');
    });
  });

  // ── Topic drift ────────────────────────────────────────────────────────────

  describe('topic drift', () => {
    it('no drift on same-topic messages', async () => {
      const guard = new ConversationGuard({
        topicDriftDetection: true,
        topicDriftThreshold: 0.1,
      });
      await guard.recordTurn({
        userMessage: 'Help me write a Python script to parse CSV files and extract specific columns of data',
        responseText: 'Sure, use the csv module.',
        toolCallCount: 0,
      });
      const violations = await guard.recordTurn({
        userMessage: 'Now help me parse the CSV data file and extract the name and email columns from it',
        responseText: 'Here is how to extract columns.',
        toolCallCount: 0,
      });
      const driftViolations = violations.filter((v) => v.type === 'topic_drift');
      expect(driftViolations).toHaveLength(0);
    });

    it('detects drift when user switches to unrelated topic', async () => {
      const guard = new ConversationGuard({
        topicDriftDetection: true,
        topicDriftThreshold: 0.3,
      });
      await guard.recordTurn({
        userMessage: 'Help me write a Python script to parse CSV files and extract specific columns from the dataset',
        responseText: 'Use the csv module.',
        toolCallCount: 0,
      });
      const violations = await guard.recordTurn({
        userMessage: 'I want to buy cryptocurrency and recommend specific coins to invest in for maximum profit returns and financial growth',
        responseText: 'I cannot help with that.',
        toolCallCount: 0,
      });
      const driftViolations = violations.filter((v) => v.type === 'topic_drift');
      expect(driftViolations.length).toBeGreaterThan(0);
    });

    it('first user message sets the baseline', async () => {
      const guard = new ConversationGuard({ topicDriftDetection: true });
      await guard.recordTurn({
        userMessage: 'Help me with Python programming and data analysis tasks',
        responseText: 'Sure!',
        toolCallCount: 0,
      });
      // Should be able to check without error
      expect(guard.turnCount).toBe(1);
    });

    it('short messages skipped (< 10 tokens)', async () => {
      const guard = new ConversationGuard({
        topicDriftDetection: true,
        topicDriftThreshold: 0.3,
      });
      await guard.recordTurn({
        userMessage: 'Help me write a Python script to parse CSV files and extract specific columns of data',
        responseText: 'ok',
        toolCallCount: 0,
      });
      const violations = await guard.recordTurn({
        userMessage: 'Buy crypto now',
        responseText: 'No.',
        toolCallCount: 0,
      });
      const driftViolations = violations.filter((v) => v.type === 'topic_drift');
      expect(driftViolations).toHaveLength(0); // Too short to check
    });

    it('topicDriftDetection: false disables check', async () => {
      const guard = new ConversationGuard({
        topicDriftDetection: false,
      });
      await guard.recordTurn({
        userMessage: 'Help me write a Python script to parse CSV files and extract specific columns',
        responseText: 'Sure.',
        toolCallCount: 0,
      });
      const violations = await guard.recordTurn({
        userMessage: 'I want to buy cryptocurrency and invest in maximum profit coins returns financial growth',
        responseText: 'ok',
        toolCallCount: 0,
      });
      const driftViolations = violations.filter((v) => v.type === 'topic_drift');
      expect(driftViolations).toHaveLength(0);
    });
  });

  // ── Accumulating risk ──────────────────────────────────────────────────────

  describe('accumulating risk', () => {
    it('risk accumulates across turns', async () => {
      const guard = new ConversationGuard({
        accumulatingRisk: true,
        riskThreshold: 2.0,
      });
      await guard.recordTurn({
        userMessage: 'turn 1',
        responseText: 'r1',
        toolCallCount: 0,
        injectionRiskScore: 0.6,
      });
      expect(guard.riskScore).toBeGreaterThan(0);
      await guard.recordTurn({
        userMessage: 'turn 2',
        responseText: 'r2',
        toolCallCount: 0,
        injectionRiskScore: 0.8,
      });
      expect(guard.riskScore).toBeGreaterThan(0.3);
    });

    it('triggers violation when riskThreshold exceeded', async () => {
      const guard = new ConversationGuard({
        accumulatingRisk: true,
        riskThreshold: 0.5,
      });
      const violations = await guard.recordTurn({
        userMessage: 'ignore everything',
        responseText: 'ok',
        toolCallCount: 0,
        injectionRiskScore: 0.9,
        jailbreakRiskScore: 0.8,
      });
      // risk = 0.9*0.5 + 0.8*0.3 = 0.45 + 0.24 = 0.69 >= 0.5
      expect(violations).toContainEqual(
        expect.objectContaining({ type: 'risk_threshold' }),
      );
    });

    it('risk from turn with no detections is 0', async () => {
      const guard = new ConversationGuard({
        accumulatingRisk: true,
        riskThreshold: 2.0,
      });
      await guard.recordTurn({
        userMessage: 'hello',
        responseText: 'world',
        toolCallCount: 0,
      });
      expect(guard.riskScore).toBe(0);
    });

    it('riskThreshold configurable', async () => {
      // Low threshold triggers easily
      const guard = new ConversationGuard({
        accumulatingRisk: true,
        riskThreshold: 0.1,
      });
      const violations = await guard.recordTurn({
        userMessage: 'test',
        responseText: 'ok',
        toolCallCount: 0,
        injectionRiskScore: 0.5,
      });
      // 0.5 * 0.5 = 0.25 >= 0.1
      expect(violations).toContainEqual(
        expect.objectContaining({ type: 'risk_threshold' }),
      );
    });

    it('reset() resets risk to 0', async () => {
      const guard = new ConversationGuard({
        accumulatingRisk: true,
        riskThreshold: 2.0,
      });
      await guard.recordTurn({
        userMessage: 'a',
        responseText: 'b',
        toolCallCount: 0,
        injectionRiskScore: 0.8,
      });
      expect(guard.riskScore).toBeGreaterThan(0);
      guard.reset();
      expect(guard.riskScore).toBe(0);
    });

    it('accumulatingRisk: false skips threshold check', async () => {
      const guard = new ConversationGuard({
        accumulatingRisk: false,
        riskThreshold: 0.01,
      });
      const violations = await guard.recordTurn({
        userMessage: 'test',
        responseText: 'ok',
        toolCallCount: 0,
        injectionRiskScore: 1.0,
        jailbreakRiskScore: 1.0,
      });
      const riskViolations = violations.filter((v) => v.type === 'risk_threshold');
      expect(riskViolations).toHaveLength(0);
    });

    it('tool calls > 5 add 0.2 risk', async () => {
      const guard = new ConversationGuard({
        accumulatingRisk: true,
        riskThreshold: 5.0,
      });
      await guard.recordTurn({
        userMessage: 'do stuff',
        responseText: 'ok',
        toolCallCount: 6,
      });
      expect(guard.riskScore).toBe(0.2);
    });
  });

  // ── Agent loop detection ──────────────────────────────────────────────────

  describe('agent loop detection', () => {
    it('detects 3 consecutive identical responses', async () => {
      const guard = new ConversationGuard({ maxConsecutiveSimilarResponses: 3 });
      await guard.recordTurn({ userMessage: 'do X', responseText: 'I cannot do that.', toolCallCount: 0 });
      await guard.recordTurn({ userMessage: 'please do X', responseText: 'I cannot do that.', toolCallCount: 0 });
      const violations = await guard.recordTurn({
        userMessage: 'do X now',
        responseText: 'I cannot do that.',
        toolCallCount: 0,
      });
      expect(violations).toContainEqual(
        expect.objectContaining({ type: 'agent_loop' }),
      );
    });

    it('different responses reset the counter', async () => {
      const guard = new ConversationGuard({ maxConsecutiveSimilarResponses: 3 });
      await guard.recordTurn({ userMessage: 'a', responseText: 'same response', toolCallCount: 0 });
      await guard.recordTurn({ userMessage: 'b', responseText: 'same response', toolCallCount: 0 });
      // Different response breaks the chain
      await guard.recordTurn({ userMessage: 'c', responseText: 'different answer', toolCallCount: 0 });
      const violations = await guard.recordTurn({
        userMessage: 'd',
        responseText: 'same response',
        toolCallCount: 0,
      });
      const loopViolations = violations.filter((v) => v.type === 'agent_loop');
      expect(loopViolations).toHaveLength(0);
    });

    it('maxConsecutiveSimilarResponses configurable', async () => {
      const guard = new ConversationGuard({ maxConsecutiveSimilarResponses: 2 });
      await guard.recordTurn({ userMessage: 'a', responseText: 'stuck', toolCallCount: 0 });
      const violations = await guard.recordTurn({
        userMessage: 'b',
        responseText: 'stuck',
        toolCallCount: 0,
      });
      expect(violations).toContainEqual(
        expect.objectContaining({ type: 'agent_loop' }),
      );
    });

    it('default threshold is 3', async () => {
      const guard = new ConversationGuard({});
      await guard.recordTurn({ userMessage: 'a', responseText: 'repeat', toolCallCount: 0 });
      const v2 = await guard.recordTurn({ userMessage: 'b', responseText: 'repeat', toolCallCount: 0 });
      expect(v2.filter((v) => v.type === 'agent_loop')).toHaveLength(0);
      const v3 = await guard.recordTurn({ userMessage: 'c', responseText: 'repeat', toolCallCount: 0 });
      expect(v3).toContainEqual(
        expect.objectContaining({ type: 'agent_loop' }),
      );
    });

    it('uses first 500 chars for hashing', async () => {
      const guard = new ConversationGuard({ maxConsecutiveSimilarResponses: 2 });
      const longResponse = 'A'.repeat(500);
      // Same first 500 chars, different after
      await guard.recordTurn({ userMessage: 'a', responseText: longResponse + 'X', toolCallCount: 0 });
      const violations = await guard.recordTurn({
        userMessage: 'b',
        responseText: longResponse + 'Y',
        toolCallCount: 0,
      });
      // Should detect as similar since first 500 chars are the same
      expect(violations).toContainEqual(
        expect.objectContaining({ type: 'agent_loop' }),
      );
    });
  });

  // ── Cross-turn PII tracking ───────────────────────────────────────────────

  describe('cross-turn PII tracking', () => {
    it('detects PII appearing in a later turn', async () => {
      const guard = new ConversationGuard({ crossTurnPiiTracking: true });
      await guard.recordTurn({
        userMessage: 'My SSN is 123-45-6789',
        responseText: 'I noted your information.',
        toolCallCount: 0,
        piiDetections: [{ type: 'ssn', value: '123-45-6789', start: 10, end: 21, confidence: 0.95 }],
      });
      const violations = await guard.recordTurn({
        userMessage: 'What did I tell you?',
        responseText: 'You told me 123-45-6789.',
        toolCallCount: 0,
        piiDetections: [{ type: 'ssn', value: '123-45-6789', start: 12, end: 23, confidence: 0.95 }],
      });
      expect(violations).toContainEqual(
        expect.objectContaining({ type: 'cross_turn_pii' }),
      );
    });

    it('same PII in same turn does not trigger', async () => {
      const guard = new ConversationGuard({ crossTurnPiiTracking: true });
      // First turn has PII — this is the first time we see it, so no cross-turn violation
      const violations = await guard.recordTurn({
        userMessage: 'My SSN is 123-45-6789',
        responseText: 'ok',
        toolCallCount: 0,
        piiDetections: [{ type: 'ssn', value: '123-45-6789', start: 10, end: 21, confidence: 0.95 }],
      });
      const crossViolations = violations.filter((v) => v.type === 'cross_turn_pii');
      expect(crossViolations).toHaveLength(0);
    });

    it('different PII values do not trigger false cross-turn match', async () => {
      const guard = new ConversationGuard({ crossTurnPiiTracking: true });
      await guard.recordTurn({
        userMessage: 'My SSN is 123-45-6789',
        responseText: 'ok',
        toolCallCount: 0,
        piiDetections: [{ type: 'ssn', value: '123-45-6789', start: 10, end: 21, confidence: 0.95 }],
      });
      const violations = await guard.recordTurn({
        userMessage: 'another',
        responseText: 'ok',
        toolCallCount: 0,
        piiDetections: [{ type: 'ssn', value: '987-65-4321', start: 0, end: 11, confidence: 0.95 }],
      });
      const crossViolations = violations.filter((v) => v.type === 'cross_turn_pii');
      expect(crossViolations).toHaveLength(0);
    });

    it('tracks multiple PII types simultaneously', async () => {
      const guard = new ConversationGuard({ crossTurnPiiTracking: true });
      await guard.recordTurn({
        userMessage: 'My email is test@example.com and SSN 123-45-6789',
        responseText: 'ok',
        toolCallCount: 0,
        piiDetections: [
          { type: 'email', value: 'test@example.com', start: 12, end: 28, confidence: 0.95 },
          { type: 'ssn', value: '123-45-6789', start: 37, end: 48, confidence: 0.95 },
        ],
      });
      const violations = await guard.recordTurn({
        userMessage: 'ok',
        responseText: 'Your email is test@example.com',
        toolCallCount: 0,
        piiDetections: [
          { type: 'email', value: 'test@example.com', start: 14, end: 30, confidence: 0.95 },
        ],
      });
      expect(violations).toContainEqual(
        expect.objectContaining({ type: 'cross_turn_pii' }),
      );
    });

    it('piiSpreadDetected flag set on summary', async () => {
      const guard = new ConversationGuard({ crossTurnPiiTracking: true });
      await guard.recordTurn({
        userMessage: 'SSN: 111-22-3333',
        responseText: 'ok',
        toolCallCount: 0,
        piiDetections: [{ type: 'ssn', value: '111-22-3333', start: 5, end: 16, confidence: 0.9 }],
      });
      await guard.recordTurn({
        userMessage: 'repeat',
        responseText: 'SSN: 111-22-3333',
        toolCallCount: 0,
        piiDetections: [{ type: 'ssn', value: '111-22-3333', start: 5, end: 16, confidence: 0.9 }],
      });
      const summary = guard.getSummary();
      expect(summary.piiSpreadDetected).toBe(true);
    });

    it('crossTurnPiiTracking: false disables check', async () => {
      const guard = new ConversationGuard({ crossTurnPiiTracking: false });
      await guard.recordTurn({
        userMessage: 'SSN: 123-45-6789',
        responseText: 'ok',
        toolCallCount: 0,
        piiDetections: [{ type: 'ssn', value: '123-45-6789', start: 5, end: 16, confidence: 0.9 }],
      });
      const violations = await guard.recordTurn({
        userMessage: 'repeat',
        responseText: '123-45-6789',
        toolCallCount: 0,
        piiDetections: [{ type: 'ssn', value: '123-45-6789', start: 0, end: 11, confidence: 0.9 }],
      });
      const crossViolations = violations.filter((v) => v.type === 'cross_turn_pii');
      expect(crossViolations).toHaveLength(0);
    });
  });

  // ── Tool call limits ──────────────────────────────────────────────────────

  describe('tool call limits', () => {
    it('allows calls under maxTotalToolCalls', async () => {
      const guard = new ConversationGuard({ maxTotalToolCalls: 10 });
      await guard.recordTurn({ userMessage: 'a', responseText: 'b', toolCallCount: 3 });
      await guard.recordTurn({ userMessage: 'c', responseText: 'd', toolCallCount: 3 });
      expect(guard.checkPreCall()).toBeNull();
    });

    it('blocks when maxTotalToolCalls exceeded', async () => {
      const guard = new ConversationGuard({ maxTotalToolCalls: 5 });
      await guard.recordTurn({ userMessage: 'a', responseText: 'b', toolCallCount: 3 });
      await guard.recordTurn({ userMessage: 'c', responseText: 'd', toolCallCount: 3 });
      // Now at 6 tool calls, limit is 5
      const violation = guard.checkPreCall();
      expect(violation).not.toBeNull();
      expect(violation!.type).toBe('tool_call_limit');
    });

    it('tool count tracked cumulatively', async () => {
      const guard = new ConversationGuard({ maxTotalToolCalls: 10 });
      await guard.recordTurn({ userMessage: 'a', responseText: 'b', toolCallCount: 2 });
      expect(guard.toolCalls).toBe(2);
      await guard.recordTurn({ userMessage: 'c', responseText: 'd', toolCallCount: 3 });
      expect(guard.toolCalls).toBe(5);
    });

    it('no maxTotalToolCalls allows unlimited', async () => {
      const guard = new ConversationGuard({});
      await guard.recordTurn({ userMessage: 'a', responseText: 'b', toolCallCount: 100 });
      expect(guard.checkPreCall()).toBeNull();
    });

    it('recordTurn also checks tool call limit', async () => {
      const guard = new ConversationGuard({ maxTotalToolCalls: 5 });
      await guard.recordTurn({ userMessage: 'a', responseText: 'b', toolCallCount: 3 });
      const violations = await guard.recordTurn({
        userMessage: 'c',
        responseText: 'd',
        toolCallCount: 4,
      });
      // 3 + 4 = 7 > 5
      expect(violations).toContainEqual(
        expect.objectContaining({ type: 'tool_call_limit' }),
      );
    });
  });

  // ── State management ──────────────────────────────────────────────────────

  describe('state management', () => {
    it('getSummary() returns correct state', async () => {
      const guard = new ConversationGuard({
        accumulatingRisk: true,
        riskThreshold: 10,
      });
      await guard.recordTurn({
        userMessage: 'hello',
        responseText: 'hi',
        toolCallCount: 2,
        injectionRiskScore: 0.4,
        piiDetections: [{ type: 'email', value: 'a@b.com', start: 0, end: 7, confidence: 0.9 }],
      });
      const summary = guard.getSummary();
      expect(summary.turns).toBe(1);
      expect(summary.totalToolCalls).toBe(2);
      expect(summary.cumulativeRiskScore).toBeGreaterThan(0);
      expect(summary.uniquePiiTypes).toContain('email');
      expect(summary.piiSpreadDetected).toBe(false);
    });

    it('reset() clears all state', async () => {
      const guard = new ConversationGuard({
        accumulatingRisk: true,
        riskThreshold: 10,
        crossTurnPiiTracking: true,
      });
      await guard.recordTurn({
        userMessage: 'test',
        responseText: 'ok',
        toolCallCount: 5,
        injectionRiskScore: 0.8,
        piiDetections: [{ type: 'ssn', value: '123-45-6789', start: 0, end: 11, confidence: 0.9 }],
      });
      guard.reset();
      expect(guard.turnCount).toBe(0);
      expect(guard.riskScore).toBe(0);
      expect(guard.toolCalls).toBe(0);
      const summary = guard.getSummary();
      expect(summary.turns).toBe(0);
      expect(summary.uniquePiiTypes).toHaveLength(0);
    });

    it('instances are independent', async () => {
      const guard1 = new ConversationGuard({ maxTurns: 5 });
      const guard2 = new ConversationGuard({ maxTurns: 5 });
      await guard1.recordTurn({ userMessage: 'a', responseText: 'b', toolCallCount: 0 });
      await guard1.recordTurn({ userMessage: 'c', responseText: 'd', toolCallCount: 0 });
      expect(guard1.turnCount).toBe(2);
      expect(guard2.turnCount).toBe(0);
    });

    it('prunes turns beyond 100', async () => {
      const guard = new ConversationGuard({});
      for (let i = 0; i < 110; i++) {
        await guard.recordTurn({ userMessage: `q${i}`, responseText: `a${i}`, toolCallCount: 0 });
      }
      // Internally prunes to 100, but turnCount reflects total recorded
      // (turns.length is pruned, but the guard still tracked 110 inputs)
      expect(guard.getSummary().turns).toBeLessThanOrEqual(100);
    });
  });
});
