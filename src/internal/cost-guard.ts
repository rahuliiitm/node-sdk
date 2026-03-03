/**
 * Cost guard module — in-memory sliding window rate limiting for LLM spend.
 * @internal
 */

import { calculateEventCost } from './cost';

export interface CostGuardOptions {
  maxCostPerRequest?: number;
  maxCostPerMinute?: number;
  maxCostPerHour?: number;
  /** Maximum total spend per 24-hour rolling window. */
  maxCostPerDay?: number;
  maxCostPerCustomer?: number;
  /** Maximum per-customer spend per 24-hour rolling window. */
  maxCostPerCustomerPerDay?: number;
  maxTokensPerRequest?: number;
  onBudgetExceeded?: (violation: BudgetViolation) => void;
  /** If true, throw CostLimitError when budget is exceeded. Default: true */
  blockOnExceed?: boolean;
}

export interface BudgetViolation {
  type: 'per_request' | 'per_minute' | 'per_hour' | 'per_day' | 'per_customer' | 'per_customer_daily' | 'max_tokens';
  currentSpend: number;
  limit: number;
  customerId?: string;
}

interface CostEntry {
  costUsd: number;
  timestampMs: number;
  customerId?: string;
}

/**
 * In-memory cost guard with sliding window tracking.
 * Resets on SDK restart (no persistence).
 */
export class CostGuard {
  private readonly options: CostGuardOptions;
  private readonly entries: CostEntry[] = [];
  private readonly blockOnExceed: boolean;

  constructor(options: CostGuardOptions) {
    this.options = options;
    this.blockOnExceed = options.blockOnExceed ?? true;
  }

  /**
   * Pre-call check: estimate cost from model + max_tokens and check budgets.
   * Returns a BudgetViolation if any limit is exceeded, null otherwise.
   */
  checkPreCall(params: {
    model: string;
    maxTokens?: number;
    customerId?: string;
  }): BudgetViolation | null {
    const now = Date.now();

    // Check max tokens per request
    if (
      this.options.maxTokensPerRequest &&
      params.maxTokens &&
      params.maxTokens > this.options.maxTokensPerRequest
    ) {
      return {
        type: 'max_tokens',
        currentSpend: params.maxTokens,
        limit: this.options.maxTokensPerRequest,
        customerId: params.customerId,
      };
    }

    // Estimate cost (assume worst case: maxTokens for both input and output)
    if (this.options.maxCostPerRequest && params.maxTokens) {
      const estimatedCost = calculateEventCost(
        'openai',
        params.model,
        params.maxTokens,
        params.maxTokens,
      );
      if (estimatedCost > this.options.maxCostPerRequest) {
        return {
          type: 'per_request',
          currentSpend: estimatedCost,
          limit: this.options.maxCostPerRequest,
          customerId: params.customerId,
        };
      }
    }

    // Check per-minute spend
    if (this.options.maxCostPerMinute) {
      const minuteSpend = this.getSpendInWindow(now - 60_000, now);
      if (minuteSpend >= this.options.maxCostPerMinute) {
        return {
          type: 'per_minute',
          currentSpend: minuteSpend,
          limit: this.options.maxCostPerMinute,
          customerId: params.customerId,
        };
      }
    }

    // Check per-hour spend
    if (this.options.maxCostPerHour) {
      const hourSpend = this.getSpendInWindow(now - 3_600_000, now);
      if (hourSpend >= this.options.maxCostPerHour) {
        return {
          type: 'per_hour',
          currentSpend: hourSpend,
          limit: this.options.maxCostPerHour,
          customerId: params.customerId,
        };
      }
    }

    // Check per-day spend (24h rolling window)
    if (this.options.maxCostPerDay) {
      const daySpend = this.getSpendInWindow(now - 86_400_000, now);
      if (daySpend >= this.options.maxCostPerDay) {
        return {
          type: 'per_day',
          currentSpend: daySpend,
          limit: this.options.maxCostPerDay,
          customerId: params.customerId,
        };
      }
    }

    // Check per-customer spend (per hour)
    if (this.options.maxCostPerCustomer && params.customerId) {
      const customerSpend = this.getSpendInWindow(
        now - 3_600_000,
        now,
        params.customerId,
      );
      if (customerSpend >= this.options.maxCostPerCustomer) {
        return {
          type: 'per_customer',
          currentSpend: customerSpend,
          limit: this.options.maxCostPerCustomer,
          customerId: params.customerId,
        };
      }
    }

    // Check per-customer daily spend (24h rolling window)
    if (this.options.maxCostPerCustomerPerDay && params.customerId) {
      const customerDaySpend = this.getSpendInWindow(
        now - 86_400_000,
        now,
        params.customerId,
      );
      if (customerDaySpend >= this.options.maxCostPerCustomerPerDay) {
        return {
          type: 'per_customer_daily',
          currentSpend: customerDaySpend,
          limit: this.options.maxCostPerCustomerPerDay,
          customerId: params.customerId,
        };
      }
    }

    return null;
  }

  /**
   * Post-call: record actual cost from API response.
   */
  recordCost(costUsd: number, customerId?: string): void {
    this.entries.push({
      costUsd,
      timestampMs: Date.now(),
      customerId,
    });

    // Prune entries older than 1 hour to prevent memory growth
    this.pruneOldEntries();
  }

  /**
   * Get total spend in a time window, optionally filtered by customer.
   */
  getSpendInWindow(
    fromMs: number,
    toMs: number,
    customerId?: string,
  ): number {
    let total = 0;
    for (const entry of this.entries) {
      if (entry.timestampMs < fromMs || entry.timestampMs > toMs) continue;
      if (customerId && entry.customerId !== customerId) continue;
      total += entry.costUsd;
    }
    return total;
  }

  /**
   * Get current minute spend.
   */
  getCurrentMinuteSpend(): number {
    const now = Date.now();
    return this.getSpendInWindow(now - 60_000, now);
  }

  /**
   * Get current hour spend.
   */
  getCurrentHourSpend(): number {
    const now = Date.now();
    return this.getSpendInWindow(now - 3_600_000, now);
  }

  /**
   * Get current day spend (24h rolling window).
   */
  getCurrentDaySpend(): number {
    const now = Date.now();
    return this.getSpendInWindow(now - 86_400_000, now);
  }

  /** Whether to block on budget exceeded */
  get shouldBlock(): boolean {
    return this.blockOnExceed;
  }

  /** The configured options */
  get config(): CostGuardOptions {
    return this.options;
  }

  private pruneOldEntries(): void {
    const cutoff = Date.now() - 86_400_000; // 24 hours
    while (this.entries.length > 0 && this.entries[0].timestampMs < cutoff) {
      this.entries.shift();
    }
  }
}
