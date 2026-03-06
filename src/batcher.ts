import type { IngestEventPayload, IngestBatchPayload } from './internal/event-types';

const DEFAULT_FLUSH_AT = 10;
const DEFAULT_FLUSH_INTERVAL_MS = 5000;
const MAX_RETRIES = 3;

export class EventBatcher {
  private queue: IngestEventPayload[] = [];
  private timer: ReturnType<typeof setTimeout> | null = null;
  private flushing = false;

  constructor(
    private readonly apiKey: string,
    private readonly endpoint: string,
    private readonly flushAt: number = DEFAULT_FLUSH_AT,
    private readonly flushIntervalMs: number = DEFAULT_FLUSH_INTERVAL_MS,
  ) {}

  enqueue(event: IngestEventPayload): void {
    this.queue.push(event);
    if (this.queue.length >= this.flushAt) {
      void this.flush();
    } else if (!this.timer) {
      this.timer = setTimeout(() => {
        this.timer = null;
        void this.flush();
      }, this.flushIntervalMs);
    }
  }

  async flush(): Promise<void> {
    if (this.flushing || this.queue.length === 0) return;
    this.flushing = true;

    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    const batch = this.queue.splice(0, this.queue.length);

    try {
      await this.sendWithRetry(batch, 0);
    } finally {
      this.flushing = false;
    }
  }

  private async sendWithRetry(
    events: IngestEventPayload[],
    attempt: number,
  ): Promise<void> {
    try {
      const payload: IngestBatchPayload = { events };
      const response = await fetch(`${this.endpoint}/v1/events/batch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok && attempt < MAX_RETRIES) {
        await this.retryWithBackoff(events, attempt);
      }
    } catch {
      if (attempt < MAX_RETRIES) {
        await this.retryWithBackoff(events, attempt);
      }
    }
  }

  private async retryWithBackoff(
    events: IngestEventPayload[],
    attempt: number,
  ): Promise<void> {
    const delayMs = Math.pow(2, attempt) * 1000;
    await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
    await this.sendWithRetry(events, attempt + 1);
  }

  destroy(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  /** Visible for testing */
  get pendingCount(): number {
    return this.queue.length;
  }
}
