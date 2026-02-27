import { EventBatcher } from './batcher';
import type { IngestEventPayload } from './internal/event-types';

const mockEvent: IngestEventPayload = {
  provider: 'openai',
  model: 'gpt-4o',
  inputTokens: 100,
  outputTokens: 50,
  totalTokens: 150,
  costUsd: 0.001,
  latencyMs: 200,
};

describe('EventBatcher', () => {
  let fetchSpy: jest.SpyInstance;

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
    } as Response);
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it('should flush when flushAt threshold is reached', async () => {
    const batcher = new EventBatcher('lp_test', 'http://localhost:3001', 3, 60000);

    batcher.enqueue(mockEvent);
    batcher.enqueue(mockEvent);
    batcher.enqueue(mockEvent);

    // Wait for the async flush to complete
    await new Promise((r) => setTimeout(r, 50));

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy).toHaveBeenCalledWith(
      'http://localhost:3001/v1/events/batch',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          Authorization: 'Bearer lp_test',
        }),
      }),
    );

    batcher.destroy();
  });

  it('should schedule timer flush when below threshold', () => {
    const batcher = new EventBatcher('lp_test', 'http://localhost:3001', 10, 60000);

    batcher.enqueue(mockEvent);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(batcher.pendingCount).toBe(1);

    batcher.destroy();
  });

  it('should flush on timer expiry', async () => {
    // Use a very short interval so the test runs fast
    const batcher = new EventBatcher('lp_test', 'http://localhost:3001', 100, 50);

    batcher.enqueue(mockEvent);

    // Wait for the timer to fire and flush to complete
    await new Promise((r) => setTimeout(r, 150));

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(batcher.pendingCount).toBe(0);

    batcher.destroy();
  });

  it('should be a no-op when queue is empty', async () => {
    const batcher = new EventBatcher('lp_test', 'http://localhost:3001', 10, 5000);

    await batcher.flush();
    expect(fetchSpy).not.toHaveBeenCalled();

    batcher.destroy();
  });

  it('should not start a second timer if one is already running', () => {
    const batcher = new EventBatcher('lp_test', 'http://localhost:3001', 10, 60000);

    batcher.enqueue(mockEvent);
    batcher.enqueue(mockEvent);

    expect(batcher.pendingCount).toBe(2);

    batcher.destroy();
  });

  it('should retry on fetch failure with exponential backoff', async () => {
    fetchSpy
      .mockRejectedValueOnce(new Error('network error'))
      .mockResolvedValueOnce({ ok: true } as Response);

    const batcher = new EventBatcher('lp_test', 'http://localhost:3001', 1, 60000);

    batcher.enqueue(mockEvent);

    // Wait for retry (1s backoff for first retry + buffer)
    await new Promise((r) => setTimeout(r, 1500));

    expect(fetchSpy).toHaveBeenCalledTimes(2);

    batcher.destroy();
  });

  it('should clear timer on destroy', async () => {
    const batcher = new EventBatcher('lp_test', 'http://localhost:3001', 10, 100);

    batcher.enqueue(mockEvent);
    batcher.destroy();

    // Wait past the timer interval
    await new Promise((r) => setTimeout(r, 200));
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
