import { LaunchPromptly, PromptNotFoundError } from './launch-promptly';

// Mock fetch globally
const fetchSpy = jest.spyOn(globalThis, 'fetch').mockResolvedValue({
  ok: true,
} as Response);

const mockResponse = {
  id: 'chatcmpl-123',
  choices: [{ message: { role: 'assistant', content: 'Hello!' } }],
  usage: {
    prompt_tokens: 50,
    completion_tokens: 20,
    total_tokens: 70,
  },
};

function createMockClient() {
  return {
    chat: {
      completions: {
        create: jest.fn().mockResolvedValue(mockResponse),
      },
    },
    embeddings: {
      create: jest.fn().mockResolvedValue({ data: [] }),
    },
  };
}

describe('LaunchPromptly', () => {
  afterEach(() => {
    fetchSpy.mockClear();
  });

  it('should proxy chat.completions.create and return the original result', async () => {
    const pf = new LaunchPromptly({
      apiKey: 'lp_live_test',
      endpoint: 'http://localhost:3001',
      flushAt: 100,
    });
    const client = createMockClient();
    const wrapped = pf.wrap(client);

    const result = await wrapped.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hello' }],
    });

    expect(result).toBe(mockResponse);
    expect(client.chat.completions.create).toHaveBeenCalledWith({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hello' }],
    });

    pf.destroy();
  });

  it('should enqueue an event after a successful call', async () => {
    const pf = new LaunchPromptly({
      apiKey: 'lp_live_test',
      endpoint: 'http://localhost:3001',
      flushAt: 1, // flush immediately
    });
    const client = createMockClient();
    const wrapped = pf.wrap(client, { feature: 'chat' });

    await wrapped.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hello' }],
    });

    // Wait for the async event capture
    await new Promise((r) => setTimeout(r, 50));

    expect(fetchSpy).toHaveBeenCalledWith(
      'http://localhost:3001/v1/events/batch',
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('"model":"gpt-4o"'),
      }),
    );

    pf.destroy();
  });

  it('should include customer info from customer function', async () => {
    const pf = new LaunchPromptly({
      apiKey: 'lp_live_test',
      endpoint: 'http://localhost:3001',
      flushAt: 1,
    });
    const client = createMockClient();
    const wrapped = pf.wrap(client, {
      customer: () => ({ id: 'cust-42', feature: 'search' }),
    });

    await wrapped.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hello' }],
    });

    await new Promise((r) => setTimeout(r, 50));

    const body = fetchSpy.mock.calls[0]?.[1]?.body as string;
    expect(body).toContain('"customerId":"cust-42"');
    expect(body).toContain('"feature":"search"');

    pf.destroy();
  });

  it('should include traceId and spanName in event payload', async () => {
    const pf = new LaunchPromptly({
      apiKey: 'lp_live_test',
      endpoint: 'http://localhost:3001',
      flushAt: 1,
    });
    const client = createMockClient();
    const wrapped = pf.wrap(client, {
      traceId: 'req-abc-123',
      spanName: 'generate',
      feature: 'knowledge-base',
    });

    await wrapped.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hello' }],
    });

    await new Promise((r) => setTimeout(r, 50));

    const batchCall = fetchSpy.mock.calls.find((c) =>
      (c[0] as string).includes('/v1/events/batch'),
    );
    expect(batchCall).toBeDefined();
    const body = JSON.parse(batchCall![1]!.body as string);
    expect(body.events[0].traceId).toBe('req-abc-123');
    expect(body.events[0].spanName).toBe('generate');
    expect(body.events[0].feature).toBe('knowledge-base');

    pf.destroy();
  });

  it('should omit traceId and spanName when not provided', async () => {
    const pf = new LaunchPromptly({
      apiKey: 'lp_live_test',
      endpoint: 'http://localhost:3001',
      flushAt: 1,
    });
    const client = createMockClient();
    const wrapped = pf.wrap(client);

    await wrapped.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hello' }],
    });

    await new Promise((r) => setTimeout(r, 50));

    const batchCall = fetchSpy.mock.calls.find((c) =>
      (c[0] as string).includes('/v1/events/batch'),
    );
    expect(batchCall).toBeDefined();
    const body = JSON.parse(batchCall![1]!.body as string);
    expect(body.events[0].traceId).toBeUndefined();
    expect(body.events[0].spanName).toBeUndefined();

    pf.destroy();
  });

  it('should not throw if the original create throws', async () => {
    const pf = new LaunchPromptly({
      apiKey: 'lp_live_test',
      endpoint: 'http://localhost:3001',
    });
    const client = createMockClient();
    client.chat.completions.create.mockRejectedValue(new Error('API error'));
    const wrapped = pf.wrap(client);

    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'Hello' }],
      }),
    ).rejects.toThrow('API error');

    pf.destroy();
  });

  it('should pass through non-intercepted properties', async () => {
    const pf = new LaunchPromptly({
      apiKey: 'lp_live_test',
      endpoint: 'http://localhost:3001',
    });
    const client = createMockClient();
    const wrapped = pf.wrap(client);

    const result = await wrapped.embeddings.create({} as never);
    expect(result).toEqual({ data: [] });

    pf.destroy();
  });

  it('should flush pending events', async () => {
    const pf = new LaunchPromptly({
      apiKey: 'lp_live_test',
      endpoint: 'http://localhost:3001',
      flushAt: 100, // won't auto-flush
    });
    const client = createMockClient();
    const wrapped = pf.wrap(client);

    await wrapped.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hello' }],
    });

    // Wait for event capture
    await new Promise((r) => setTimeout(r, 50));

    // Manually flush
    await pf.flush();

    expect(fetchSpy).toHaveBeenCalled();

    pf.destroy();
  });

  // ── prompt() tests ──

  describe('prompt()', () => {
    const resolvedPromptData = {
      content: 'You are a customer support agent.',
      managedPromptId: 'mp-1',
      promptVersionId: 'pv-1',
      version: 2,
    };

    function mockResolveResponse(data: any, status = 200) {
      fetchSpy.mockResolvedValueOnce({
        ok: status >= 200 && status < 300,
        status,
        json: () => Promise.resolve(data),
      } as Response);
    }

    it('should fetch from API and return content', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      mockResolveResponse(resolvedPromptData);

      const content = await pf.prompt('customer-support');
      expect(content).toBe('You are a customer support agent.');
      expect(fetchSpy).toHaveBeenCalledWith(
        'http://localhost:3001/v1/prompts/resolve/customer-support',
        expect.objectContaining({
          headers: { Authorization: 'Bearer lp_live_test' },
        }),
      );
      pf.destroy();
    });

    it('should cache result and reuse on second call', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        promptCacheTtl: 60000,
      });
      mockResolveResponse(resolvedPromptData);

      const first = await pf.prompt('cached-slug');
      const second = await pf.prompt('cached-slug');

      expect(first).toBe(second);
      // Only one fetch call for the resolve endpoint
      const resolveCalls = fetchSpy.mock.calls.filter((c) =>
        (c[0] as string).includes('/v1/prompts/resolve/'),
      );
      expect(resolveCalls).toHaveLength(1);
      pf.destroy();
    });

    it('should re-fetch after TTL expires', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        promptCacheTtl: 1, // 1ms TTL
      });
      mockResolveResponse(resolvedPromptData);
      await pf.prompt('ttl-slug');

      await new Promise((r) => setTimeout(r, 10)); // wait for expiry

      mockResolveResponse({ ...resolvedPromptData, content: 'Updated content' });
      const second = await pf.prompt('ttl-slug');
      expect(second).toBe('Updated content');
      pf.destroy();
    });

    it('should return stale cache on network error', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        promptCacheTtl: 1,
      });
      mockResolveResponse(resolvedPromptData);
      await pf.prompt('stale-slug');

      await new Promise((r) => setTimeout(r, 10));

      fetchSpy.mockRejectedValueOnce(new Error('Network error'));
      const content = await pf.prompt('stale-slug');
      expect(content).toBe('You are a customer support agent.');
      pf.destroy();
    });

    it('should throw PromptNotFoundError on 404', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      mockResolveResponse({}, 404);

      await expect(pf.prompt('missing')).rejects.toThrow(PromptNotFoundError);
      pf.destroy();
    });

    it('should throw PromptNotFoundError on 404 even with stale cache', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        promptCacheTtl: 1,
      });
      mockResolveResponse(resolvedPromptData);
      await pf.prompt('deleted-slug');

      await new Promise((r) => setTimeout(r, 10));

      mockResolveResponse({}, 404);
      await expect(pf.prompt('deleted-slug')).rejects.toThrow(PromptNotFoundError);
      pf.destroy();
    });

    it('should pass customerId as query param', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      mockResolveResponse(resolvedPromptData);

      await pf.prompt('ab-slug', { customerId: 'user-42' });
      expect(fetchSpy).toHaveBeenCalledWith(
        'http://localhost:3001/v1/prompts/resolve/ab-slug?customerId=user-42',
        expect.any(Object),
      );
      pf.destroy();
    });

    it('should include managedPromptId in event after prompt()', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        flushAt: 1,
      });
      mockResolveResponse(resolvedPromptData);

      const systemPrompt = await pf.prompt('event-test');
      const client = createMockClient();
      const wrapped = pf.wrap(client);

      await wrapped.chat.completions.create({
        model: 'gpt-4o',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: 'Hello' },
        ],
      });

      await new Promise((r) => setTimeout(r, 50));

      const batchCall = fetchSpy.mock.calls.find((c) =>
        (c[0] as string).includes('/v1/events/batch'),
      );
      expect(batchCall).toBeDefined();
      const body = JSON.parse(batchCall![1]!.body as string);
      expect(body.events[0].managedPromptId).toBe('mp-1');
      expect(body.events[0].promptVersionId).toBe('pv-1');
      pf.destroy();
    });

    it('should reject with error when no cache and network fails', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      fetchSpy.mockRejectedValueOnce(new Error('Connection refused'));

      await expect(pf.prompt('no-cache')).rejects.toThrow('Connection refused');
      pf.destroy();
    });

    // ── Template variable interpolation ──

    it('should interpolate variables in fetched prompt', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      mockResolveResponse({
        content: 'Hello {{name}}, you are a {{role}}.',
        managedPromptId: 'mp-1',
        promptVersionId: 'pv-1',
        version: 1,
      });

      const content = await pf.prompt('greeting', {
        variables: { name: 'Alice', role: 'admin' },
      });
      expect(content).toBe('Hello Alice, you are a admin.');
      pf.destroy();
    });

    it('should return raw template when no variables provided', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      mockResolveResponse({
        content: 'Hello {{name}}',
        managedPromptId: 'mp-1',
        promptVersionId: 'pv-1',
        version: 1,
      });

      const content = await pf.prompt('raw-template');
      expect(content).toBe('Hello {{name}}');
      pf.destroy();
    });

    it('should interpolate from cache on second call', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        promptCacheTtl: 60000,
      });
      mockResolveResponse({
        content: 'Hi {{name}}, topic: {{topic}}',
        managedPromptId: 'mp-1',
        promptVersionId: 'pv-1',
        version: 1,
      });

      const first = await pf.prompt('cached-vars', {
        variables: { name: 'Alice', topic: 'billing' },
      });
      expect(first).toBe('Hi Alice, topic: billing');

      // Second call with different variables — should use cache, no fetch
      const second = await pf.prompt('cached-vars', {
        variables: { name: 'Bob', topic: 'support' },
      });
      expect(second).toBe('Hi Bob, topic: support');

      // Only one fetch call
      const resolveCalls = fetchSpy.mock.calls.filter((c) =>
        (c[0] as string).includes('/v1/prompts/resolve/'),
      );
      expect(resolveCalls).toHaveLength(1);
      pf.destroy();
    });

    it('should track interpolated content for event metadata', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        flushAt: 1,
      });
      mockResolveResponse({
        content: 'You are a {{role}} assistant.',
        managedPromptId: 'mp-2',
        promptVersionId: 'pv-2',
        version: 3,
      });

      const systemPrompt = await pf.prompt('role-prompt', {
        variables: { role: 'support' },
      });
      expect(systemPrompt).toBe('You are a support assistant.');

      const client = createMockClient();
      const wrapped = pf.wrap(client);

      await wrapped.chat.completions.create({
        model: 'gpt-4o',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: 'Hello' },
        ],
      });

      await new Promise((r) => setTimeout(r, 50));

      const batchCall = fetchSpy.mock.calls.find((c) =>
        (c[0] as string).includes('/v1/events/batch'),
      );
      expect(batchCall).toBeDefined();
      const body = JSON.parse(batchCall![1]!.body as string);
      expect(body.events[0].managedPromptId).toBe('mp-2');
      expect(body.events[0].promptVersionId).toBe('pv-2');
      pf.destroy();
    });

    it('should interpolate stale cache on network error', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        promptCacheTtl: 1,
      });
      mockResolveResponse({
        content: 'Hello {{name}}',
        managedPromptId: 'mp-1',
        promptVersionId: 'pv-1',
        version: 1,
      });
      await pf.prompt('stale-var-slug', { variables: { name: 'Alice' } });

      await new Promise((r) => setTimeout(r, 10));

      fetchSpy.mockRejectedValueOnce(new Error('Network error'));
      const content = await pf.prompt('stale-var-slug', { variables: { name: 'Bob' } });
      expect(content).toBe('Hello Bob');
      pf.destroy();
    });
  });

  // ── Singleton pattern ──

  describe('singleton', () => {
    afterEach(() => {
      LaunchPromptly.reset();
    });

    it('init() creates a singleton', () => {
      const lp = LaunchPromptly.init({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      expect(lp).toBeInstanceOf(LaunchPromptly);
      expect(LaunchPromptly.shared).toBe(lp);
    });

    it('init() returns existing instance on second call', () => {
      const first = LaunchPromptly.init({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      const second = LaunchPromptly.init({
        apiKey: 'lp_live_other',
        endpoint: 'http://localhost:9999',
      });
      expect(second).toBe(first);
    });

    it('shared throws before init()', () => {
      expect(() => LaunchPromptly.shared).toThrow('LaunchPromptly has not been initialized');
    });

    it('reset() clears the singleton', () => {
      LaunchPromptly.init({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      LaunchPromptly.reset();
      expect(() => LaunchPromptly.shared).toThrow();
    });
  });

  // ── AsyncLocalStorage context propagation ──

  describe('withContext()', () => {
    const resolvedPromptData = {
      content: 'You are helpful.',
      managedPromptId: 'mp-ctx',
      promptVersionId: 'pv-ctx',
      version: 1,
    };

    function mockResolveResponse(data: any, status = 200) {
      fetchSpy.mockResolvedValueOnce({
        ok: status >= 200 && status < 300,
        status,
        json: () => Promise.resolve(data),
      } as Response);
    }

    it('getContext() returns undefined outside withContext', () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      expect(pf.getContext()).toBeUndefined();
      pf.destroy();
    });

    it('getContext() returns the context inside withContext', () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      pf.withContext({ traceId: 'trace-1', customerId: 'cust-1' }, () => {
        expect(pf.getContext()).toEqual({ traceId: 'trace-1', customerId: 'cust-1' });
      });
      pf.destroy();
    });

    it('ALS traceId overrides WrapOptions traceId in events', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        flushAt: 1,
      });
      const client = createMockClient();
      const wrapped = pf.wrap(client, { traceId: 'static-trace' });

      await pf.withContext({ traceId: 'als-trace-42' }, async () => {
        await wrapped.chat.completions.create({
          model: 'gpt-4o',
          messages: [{ role: 'user', content: 'Hello' }],
        });
      });

      await new Promise((r) => setTimeout(r, 50));

      const batchCall = fetchSpy.mock.calls.find((c) =>
        (c[0] as string).includes('/v1/events/batch'),
      );
      expect(batchCall).toBeDefined();
      const body = JSON.parse(batchCall![1]!.body as string);
      expect(body.events[0].traceId).toBe('als-trace-42');
      pf.destroy();
    });

    it('ALS customerId is used when no customer function is set', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        flushAt: 1,
      });
      const client = createMockClient();
      const wrapped = pf.wrap(client);

      await pf.withContext({ customerId: 'als-cust-7' }, async () => {
        await wrapped.chat.completions.create({
          model: 'gpt-4o',
          messages: [{ role: 'user', content: 'Hello' }],
        });
      });

      await new Promise((r) => setTimeout(r, 50));

      const batchCall = fetchSpy.mock.calls.find((c) =>
        (c[0] as string).includes('/v1/events/batch'),
      );
      const body = JSON.parse(batchCall![1]!.body as string);
      expect(body.events[0].customerId).toBe('als-cust-7');
      pf.destroy();
    });

    it('prompt() uses ALS customerId for A/B resolution', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      mockResolveResponse(resolvedPromptData);

      await pf.withContext({ customerId: 'als-user-99' }, async () => {
        await pf.prompt('greeting');
      });

      expect(fetchSpy).toHaveBeenCalledWith(
        'http://localhost:3001/v1/prompts/resolve/greeting?customerId=als-user-99',
        expect.any(Object),
      );
      pf.destroy();
    });

    it('falls back to WrapOptions when no ALS context', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        flushAt: 1,
      });
      const client = createMockClient();
      const wrapped = pf.wrap(client, {
        traceId: 'fallback-trace',
        spanName: 'fallback-span',
      });

      // NO withContext — should use static WrapOptions
      await wrapped.chat.completions.create({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'Hello' }],
      });

      await new Promise((r) => setTimeout(r, 50));

      const batchCall = fetchSpy.mock.calls.find((c) =>
        (c[0] as string).includes('/v1/events/batch'),
      );
      const body = JSON.parse(batchCall![1]!.body as string);
      expect(body.events[0].traceId).toBe('fallback-trace');
      expect(body.events[0].spanName).toBe('fallback-span');
      pf.destroy();
    });

    it('ALS metadata is included in events', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        flushAt: 1,
      });
      const client = createMockClient();
      const wrapped = pf.wrap(client);

      await pf.withContext({ metadata: { requestId: 'req-1', region: 'us-east-1' } }, async () => {
        await wrapped.chat.completions.create({
          model: 'gpt-4o',
          messages: [{ role: 'user', content: 'Hello' }],
        });
      });

      await new Promise((r) => setTimeout(r, 50));

      const batchCall = fetchSpy.mock.calls.find((c) =>
        (c[0] as string).includes('/v1/events/batch'),
      );
      const body = JSON.parse(batchCall![1]!.body as string);
      expect(body.events[0].metadata).toEqual({ requestId: 'req-1', region: 'us-east-1' });
      pf.destroy();
    });
  });

  // ── shutdown() ──

  describe('shutdown()', () => {
    it('flushes and destroys', async () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
        flushAt: 100,
      });
      const client = createMockClient();
      const wrapped = pf.wrap(client);

      await wrapped.chat.completions.create({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'Hello' }],
      });

      await new Promise((r) => setTimeout(r, 50));
      await pf.shutdown();

      expect(pf.isDestroyed).toBe(true);
      // Event batch should have been flushed
      const batchCall = fetchSpy.mock.calls.find((c) =>
        (c[0] as string).includes('/v1/events/batch'),
      );
      expect(batchCall).toBeDefined();
    });

    it('destroy is safe to call multiple times', () => {
      const pf = new LaunchPromptly({
        apiKey: 'lp_live_test',
        endpoint: 'http://localhost:3001',
      });
      pf.destroy();
      pf.destroy(); // should not throw
      expect(pf.isDestroyed).toBe(true);
    });
  });
});
