import { CostGuard } from './cost-guard';

describe('CostGuard', () => {
  // ── Max tokens per request ────────────────────────────────────────────────

  describe('maxTokensPerRequest', () => {
    it('blocks when max tokens exceeded', () => {
      const guard = new CostGuard({ maxTokensPerRequest: 4000 });
      const violation = guard.checkPreCall({ model: 'gpt-4o', maxTokens: 8000 });
      expect(violation).not.toBeNull();
      expect(violation!.type).toBe('max_tokens');
      expect(violation!.limit).toBe(4000);
    });

    it('allows when under max tokens', () => {
      const guard = new CostGuard({ maxTokensPerRequest: 4000 });
      const violation = guard.checkPreCall({ model: 'gpt-4o', maxTokens: 2000 });
      expect(violation).toBeNull();
    });
  });

  // ── Max cost per request ──────────────────────────────────────────────────

  describe('maxCostPerRequest', () => {
    it('blocks expensive requests', () => {
      const guard = new CostGuard({ maxCostPerRequest: 0.01 });
      // gpt-4 with 10k tokens each way should be expensive
      const violation = guard.checkPreCall({ model: 'gpt-4', maxTokens: 10000 });
      expect(violation).not.toBeNull();
      expect(violation!.type).toBe('per_request');
    });

    it('allows cheap requests', () => {
      const guard = new CostGuard({ maxCostPerRequest: 1.0 });
      const violation = guard.checkPreCall({ model: 'gpt-4o-mini', maxTokens: 100 });
      expect(violation).toBeNull();
    });
  });

  // ── Per-minute spending ───────────────────────────────────────────────────

  describe('maxCostPerMinute', () => {
    it('blocks after exceeding minute budget', () => {
      const guard = new CostGuard({ maxCostPerMinute: 0.1 });

      // Record some costs
      guard.recordCost(0.05);
      guard.recordCost(0.06);

      const violation = guard.checkPreCall({ model: 'gpt-4o' });
      expect(violation).not.toBeNull();
      expect(violation!.type).toBe('per_minute');
    });

    it('allows when under minute budget', () => {
      const guard = new CostGuard({ maxCostPerMinute: 1.0 });
      guard.recordCost(0.01);

      const violation = guard.checkPreCall({ model: 'gpt-4o' });
      expect(violation).toBeNull();
    });
  });

  // ── Per-hour spending ─────────────────────────────────────────────────────

  describe('maxCostPerHour', () => {
    it('blocks after exceeding hour budget', () => {
      const guard = new CostGuard({ maxCostPerHour: 0.5 });

      for (let i = 0; i < 10; i++) {
        guard.recordCost(0.06);
      }

      const violation = guard.checkPreCall({ model: 'gpt-4o' });
      expect(violation).not.toBeNull();
      expect(violation!.type).toBe('per_hour');
    });
  });

  // ── Per-customer spending ─────────────────────────────────────────────────

  describe('maxCostPerCustomer', () => {
    it('blocks specific customer after exceeding limit', () => {
      const guard = new CostGuard({ maxCostPerCustomer: 0.1 });

      guard.recordCost(0.06, 'customer-1');
      guard.recordCost(0.06, 'customer-1');

      const violation = guard.checkPreCall({ model: 'gpt-4o', customerId: 'customer-1' });
      expect(violation).not.toBeNull();
      expect(violation!.type).toBe('per_customer');
      expect(violation!.customerId).toBe('customer-1');
    });

    it('allows other customers', () => {
      const guard = new CostGuard({ maxCostPerCustomer: 0.1 });

      guard.recordCost(0.15, 'customer-1'); // Over limit

      const violation = guard.checkPreCall({ model: 'gpt-4o', customerId: 'customer-2' });
      expect(violation).toBeNull();
    });
  });

  // ── recordCost ────────────────────────────────────────────────────────────

  describe('recordCost', () => {
    it('tracks spend accurately', () => {
      const guard = new CostGuard({ maxCostPerHour: 100 });
      guard.recordCost(0.05);
      guard.recordCost(0.10);
      guard.recordCost(0.03);

      const spend = guard.getCurrentHourSpend();
      expect(spend).toBeCloseTo(0.18);
    });

    it('tracks minute spend', () => {
      const guard = new CostGuard({ maxCostPerMinute: 100 });
      guard.recordCost(0.01);
      guard.recordCost(0.02);

      const spend = guard.getCurrentMinuteSpend();
      expect(spend).toBeCloseTo(0.03);
    });
  });

  // ── blockOnExceed ─────────────────────────────────────────────────────────

  describe('blockOnExceed', () => {
    it('defaults to true', () => {
      const guard = new CostGuard({ maxCostPerMinute: 0.1 });
      expect(guard.shouldBlock).toBe(true);
    });

    it('can be set to false', () => {
      const guard = new CostGuard({ maxCostPerMinute: 0.1, blockOnExceed: false });
      expect(guard.shouldBlock).toBe(false);
    });
  });

  // ── Edge cases ────────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('no violation when no limits configured', () => {
      const guard = new CostGuard({});
      guard.recordCost(999);
      const violation = guard.checkPreCall({ model: 'gpt-4o', maxTokens: 999999 });
      expect(violation).toBeNull();
    });

    it('works without maxTokens parameter', () => {
      const guard = new CostGuard({ maxTokensPerRequest: 4000 });
      const violation = guard.checkPreCall({ model: 'gpt-4o' });
      expect(violation).toBeNull(); // No maxTokens → can't check
    });
  });
});
