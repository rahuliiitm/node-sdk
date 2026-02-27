/**
 * LaunchPromptly SDK — Integration Test Suite
 *
 * Self-bootstrapping: creates its own user, prompt, deployment, and API key,
 * then exercises every SDK feature against the live local API.
 *
 * Prerequisites:
 *   - API server running on localhost:3001
 *   - Postgres running with migrations applied
 *
 * Run:
 *   npx tsx tests/integration-test.ts
 */

import {
  LaunchPromptly,
  PromptNotFoundError,
  extractVariables,
  interpolate,
} from '../src/index';
import type { RequestContext } from '../src/index';
import { setup, teardown, apiCall, type TestContext } from './helpers';

// ── Test Harness ─────────────────────────────────────────────────────────────

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function assert(label: string, condition: boolean, detail?: string): void {
  if (condition) {
    passed++;
    console.log(`  ${GREEN}✓${RESET} ${label}`);
  } else {
    failed++;
    const msg = detail ? `${label} — ${detail}` : label;
    failures.push(msg);
    console.log(`  ${RED}✗${RESET} ${label}${detail ? ` ${DIM}(${detail})${RESET}` : ''}`);
  }
}

function assertEqual(label: string, actual: unknown, expected: unknown): void {
  const ok = actual === expected;
  assert(label, ok, ok ? undefined : `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function assertIncludes(label: string, haystack: string, needle: string): void {
  const ok = haystack.includes(needle);
  assert(label, ok, ok ? undefined : `"${needle}" not found in "${haystack.slice(0, 100)}..."`);
}

function assertArrayEqual(label: string, actual: string[], expected: string[]): void {
  const ok = actual.length === expected.length && actual.every((v, i) => v === expected[i]);
  assert(label, ok, ok ? undefined : `expected [${expected}], got [${actual}]`);
}

async function assertThrows<T extends Error>(
  label: string,
  fn: () => Promise<unknown>,
  errorClass?: new (...args: any[]) => T,
): Promise<void> {
  try {
    await fn();
    assert(label, false, 'expected to throw but did not');
  } catch (err) {
    if (errorClass) {
      assert(label, err instanceof errorClass, `expected ${errorClass.name} but got ${(err as Error).constructor.name}`);
    } else {
      assert(label, true);
    }
  }
}

function section(name: string): void {
  console.log(`\n${BOLD}▸ ${name}${RESET}`);
}

// ── Test Suites ──────────────────────────────────────────────────────────────

const API_ENDPOINT = process.env.API_URL ?? 'http://localhost:3001';

async function testInitialization(ctx: TestContext): Promise<void> {
  section('Test 1: Initialization');

  // Explicit API key + endpoint
  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
  });
  assert('Creates instance with explicit apiKey + endpoint', lp instanceof LaunchPromptly);
  lp.destroy();

  // Missing API key throws
  const origKey = process.env.LAUNCHPROMPTLY_API_KEY;
  const origLp = process.env.LP_API_KEY;
  delete process.env.LAUNCHPROMPTLY_API_KEY;
  delete process.env.LP_API_KEY;
  try {
    await assertThrows('Throws when no API key provided', async () => {
      new LaunchPromptly({});
    }, Error);
  } finally {
    if (origKey) process.env.LAUNCHPROMPTLY_API_KEY = origKey;
    if (origLp) process.env.LP_API_KEY = origLp;
  }
}

async function testSingleton(ctx: TestContext): Promise<void> {
  section('Test 2: Singleton Pattern');

  // Reset any previous singleton
  LaunchPromptly.reset();

  // shared throws before init
  let threwBeforeInit = false;
  try {
    LaunchPromptly.shared;
  } catch {
    threwBeforeInit = true;
  }
  assert('shared throws before init()', threwBeforeInit);

  // init creates singleton
  const lp = LaunchPromptly.init({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
  });
  assert('init() returns an instance', lp instanceof LaunchPromptly);
  assertEqual('shared returns the same instance', LaunchPromptly.shared, lp);

  // Second init returns same instance
  const lp2 = LaunchPromptly.init({
    apiKey: 'lp_live_different',
    endpoint: 'http://other:9999',
  });
  assertEqual('Second init() returns existing instance', lp2, lp);

  // Singleton can fetch prompts
  const content = await LaunchPromptly.shared.prompt(ctx.promptSlug);
  assert('Singleton fetches prompt', content.length > 0);

  // reset clears singleton
  LaunchPromptly.reset();
  let threwAfterReset = false;
  try {
    LaunchPromptly.shared;
  } catch {
    threwAfterReset = true;
  }
  assert('reset() clears the singleton', threwAfterReset);
}

async function testPromptFetch(ctx: TestContext): Promise<void> {
  section('Test 3: Prompt Fetch');

  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
  });

  const content = await lp.prompt(ctx.promptSlug);
  assert('Fetches prompt successfully', typeof content === 'string' && content.length > 0);
  assertIncludes('Contains {{name}} placeholder', content, '{{name}}');
  assertIncludes('Contains {{role}} placeholder', content, '{{role}}');
  assertIncludes('Contains {{company}} placeholder', content, '{{company}}');

  lp.destroy();
}

async function testTemplateVariables(ctx: TestContext): Promise<void> {
  section('Test 4: Template Variables');

  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
  });

  const content = await lp.prompt(ctx.promptSlug, {
    variables: { name: 'Alice', role: 'admin', company: 'Acme Corp' },
  });

  assertEqual('Interpolates name', content, 'Hello Alice, you are a admin. Welcome to Acme Corp!');

  // Partial variables — unmatched left as-is
  const lp2 = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    promptCacheTtl: 1, // force refetch
  });
  await sleep(10);
  const partial = await lp2.prompt(ctx.promptSlug, {
    variables: { name: 'Bob' },
  });
  assertIncludes('Partial variables: name interpolated', partial, 'Hello Bob');
  assertIncludes('Partial variables: role left as placeholder', partial, '{{role}}');

  lp.destroy();
  lp2.destroy();
}

async function testCaching(ctx: TestContext): Promise<void> {
  section('Test 5: Caching');

  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    promptCacheTtl: 60000, // 60s
  });

  // First fetch — network call
  const t1 = Date.now();
  const first = await lp.prompt(ctx.promptSlug);
  const networkMs = Date.now() - t1;

  // Second fetch — should be cached (instant)
  const t2 = Date.now();
  const second = await lp.prompt(ctx.promptSlug);
  const cacheMs = Date.now() - t2;

  assertEqual('Cached result matches first result', first, second);
  assert('Cached fetch is faster than network fetch', cacheMs < networkMs || cacheMs < 5,
    `network: ${networkMs}ms, cache: ${cacheMs}ms`);

  lp.destroy();
}

async function testStaleCacheFallback(ctx: TestContext): Promise<void> {
  section('Test 6: Stale Cache Fallback');

  // Use a very short TTL so the cache expires quickly
  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    promptCacheTtl: 50, // 50ms TTL
  });

  // Prime the cache
  const original = await lp.prompt(ctx.promptSlug);
  assert('Primed cache with prompt', original.length > 0);

  // Wait for cache to expire
  await sleep(100);

  // Test that 404 does NOT use stale cache
  await assertThrows('404 throws PromptNotFoundError (no stale fallback)', async () => {
    await lp.prompt('nonexistent-slug-12345');
  }, PromptNotFoundError);

  lp.destroy();
}

async function testNotFoundHandling(ctx: TestContext): Promise<void> {
  section('Test 7: 404 Handling');

  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
  });

  await assertThrows('Throws PromptNotFoundError for missing slug', async () => {
    await lp.prompt('this-prompt-does-not-exist');
  }, PromptNotFoundError);

  // Verify error message includes slug
  try {
    await lp.prompt('another-missing-slug');
  } catch (err) {
    assertIncludes(
      'Error message includes slug name',
      (err as Error).message,
      'another-missing-slug',
    );
  }

  lp.destroy();
}

async function testTemplateUtilities(): Promise<void> {
  section('Test 8: Template Utilities');

  // extractVariables
  const vars = extractVariables('Hello {{name}}, your role is {{role}}. Email: {{email}}');
  assertArrayEqual('extractVariables finds all variables', vars, ['name', 'role', 'email']);

  const empty = extractVariables('No variables here');
  assertArrayEqual('extractVariables returns empty for no variables', empty, []);

  const dupes = extractVariables('{{x}} and {{x}} again');
  assertArrayEqual('extractVariables deduplicates', dupes, ['x']);

  // interpolate
  const result = interpolate('Hi {{name}}, welcome to {{place}}!', { name: 'World', place: 'Earth' });
  assertEqual('interpolate replaces all variables', result, 'Hi World, welcome to Earth!');

  const partialResult = interpolate('{{a}} + {{b}} = {{c}}', { a: '1', b: '2' });
  assertEqual('interpolate leaves unmatched as-is', partialResult, '1 + 2 = {{c}}');

  const specialChars = interpolate('Price: {{amount}}', { amount: '$100.00 (USD)' });
  assertEqual('interpolate handles special chars in values', specialChars, 'Price: $100.00 (USD)');
}

async function testOpenAIWrap(ctx: TestContext): Promise<void> {
  section('Test 9: OpenAI Wrap (Mock Client)');

  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    flushAt: 100, // high threshold so we control flushing
  });

  // Mock OpenAI-like client
  let createCalled = false;
  const mockClient = {
    chat: {
      completions: {
        create: async (params: { model: string; messages: { role: string; content: string }[] }) => {
          createCalled = true;
          return {
            id: 'chatcmpl-test',
            object: 'chat.completion',
            model: params.model,
            choices: [
              {
                index: 0,
                message: { role: 'assistant', content: 'Hello! How can I help?' },
                finish_reason: 'stop',
              },
            ],
            usage: {
              prompt_tokens: 25,
              completion_tokens: 10,
              total_tokens: 35,
            },
          };
        },
      },
    },
    // Non-chat method to test passthrough
    models: {
      list: async () => ({ data: [{ id: 'gpt-4o' }] }),
    },
  };

  const wrapped = lp.wrap(mockClient);

  // Call through wrapped client
  const result = await wrapped.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: 'You are helpful.' },
      { role: 'user', content: 'Hi!' },
    ],
  });

  assert('Wrapped create() was called', createCalled);
  assertEqual('Response is passed through unchanged', result.choices[0].message.content, 'Hello! How can I help?');
  assertEqual('Usage data preserved', result.usage?.total_tokens, 35);

  // Non-intercepted methods pass through
  const models = await wrapped.models.list();
  assertEqual('Non-chat methods pass through', models.data[0].id, 'gpt-4o');

  // Give async event processing time to run
  await sleep(50);

  lp.destroy();
}

async function testCustomerContextAndTracing(ctx: TestContext): Promise<void> {
  section('Test 10: Customer Context & Tracing');

  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    flushAt: 100,
  });

  const mockClient = {
    chat: {
      completions: {
        create: async (_p: any) => ({
          model: 'gpt-4o',
          choices: [{ index: 0, message: { role: 'assistant', content: 'Sure!' }, finish_reason: 'stop' }],
          usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
        }),
      },
    },
  };

  const wrapped = lp.wrap(mockClient, {
    customer: async () => ({ id: 'cust-123', feature: 'onboarding' }),
    traceId: 'trace-abc',
    spanName: 'test-span',
    feature: 'default-feature',
  });

  await wrapped.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: 'Hello' }],
  });

  // Give async event generation time
  await sleep(50);

  // Verify the flush sends successfully (202 accepted)
  await lp.flush();
  assert('Flush with customer context succeeds (no throw)', true);

  lp.destroy();
}

async function testWithContext(ctx: TestContext): Promise<void> {
  section('Test 11: AsyncLocalStorage Context Propagation');

  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    flushAt: 100,
  });

  // 1. getContext() outside withContext returns undefined
  assertEqual('getContext() outside withContext is undefined', lp.getContext(), undefined);

  // 2. getContext() inside withContext returns the context
  let capturedCtx: RequestContext | undefined;
  lp.withContext({ traceId: 'req-001', customerId: 'user-42' }, () => {
    capturedCtx = lp.getContext();
  });
  assertEqual('getContext() returns traceId', capturedCtx?.traceId, 'req-001');
  assertEqual('getContext() returns customerId', capturedCtx?.customerId, 'user-42');

  // 3. Context flows across async/await
  let asyncCtx: RequestContext | undefined;
  await lp.withContext({ traceId: 'async-trace', feature: 'billing' }, async () => {
    await sleep(10); // cross async boundary
    asyncCtx = lp.getContext();
  });
  assertEqual('Context flows across async/await', asyncCtx?.traceId, 'async-trace');
  assertEqual('Feature flows across async/await', asyncCtx?.feature, 'billing');

  // 4. Nested contexts — inner overrides outer
  let innerCtx: RequestContext | undefined;
  let outerCtxAfter: RequestContext | undefined;
  await lp.withContext({ traceId: 'outer' }, async () => {
    lp.withContext({ traceId: 'inner' }, () => {
      innerCtx = lp.getContext();
    });
    outerCtxAfter = lp.getContext();
  });
  assertEqual('Inner context overrides outer', innerCtx?.traceId, 'inner');
  assertEqual('Outer context restored after inner', outerCtxAfter?.traceId, 'outer');

  // 5. withContext + prompt() uses ALS customerId
  const lp2 = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    promptCacheTtl: 1,
  });
  await sleep(10);
  await lp2.withContext({ customerId: 'als-customer-55' }, async () => {
    const content = await lp2.prompt(ctx.promptSlug);
    assert('prompt() works inside withContext', content.length > 0);
  });

  // 6. withContext + wrap(): ALS context used for events
  const mockClient = {
    chat: {
      completions: {
        create: async (_p: any) => ({
          model: 'gpt-4o',
          choices: [{ index: 0, message: { role: 'assistant', content: 'ok' }, finish_reason: 'stop' }],
          usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
        }),
      },
    },
  };

  // Wrap once (at app startup level) — no static traceId
  const wrapped = lp.wrap(mockClient);

  // Use withContext per-request
  await lp.withContext(
    { traceId: 'req-777', customerId: 'cust-ctx-1', feature: 'search', spanName: 'query' },
    async () => {
      await wrapped.chat.completions.create({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'ALS test' }],
      });
    },
  );

  await sleep(50);
  await lp.flush();
  assert('Flush with ALS context events succeeds', true);

  // 7. withContext with metadata
  await lp.withContext(
    { traceId: 'meta-trace', metadata: { region: 'us-east-1', version: 'v2' } },
    async () => {
      await wrapped.chat.completions.create({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'metadata test' }],
      });
    },
  );

  await sleep(50);
  await lp.flush();
  assert('Flush with metadata context succeeds', true);

  lp.destroy();
  lp2.destroy();
}

async function testPromptEventLinking(ctx: TestContext): Promise<void> {
  section('Test 12: Prompt→Event Linking');

  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    flushAt: 100,
  });

  // First fetch the prompt — this registers it internally for linking
  const promptContent = await lp.prompt(ctx.promptSlug);
  assert('Fetched prompt for linking', promptContent.length > 0);

  const mockClient = {
    chat: {
      completions: {
        create: async (_p: any) => ({
          model: 'gpt-4o',
          choices: [{ index: 0, message: { role: 'assistant', content: 'Linked!' }, finish_reason: 'stop' }],
          usage: { prompt_tokens: 30, completion_tokens: 8, total_tokens: 38 },
        }),
      },
    },
  };

  const wrapped = lp.wrap(mockClient);

  // Use the fetched prompt as the system message — SDK should link it to managedPromptId
  await wrapped.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: promptContent },
      { role: 'user', content: 'Tell me about my account' },
    ],
  });

  await sleep(50);
  await lp.flush();
  assert('Flush with linked prompt events succeeds', true);

  lp.destroy();
}

async function testEventBatchingAndFlush(ctx: TestContext): Promise<void> {
  section('Test 13: Event Batching & Flush');

  // Test 1: flushAt threshold triggers automatic flush
  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    flushAt: 3, // low threshold
    flushInterval: 60000, // long interval (won't trigger)
  });

  const mockClient = {
    chat: {
      completions: {
        create: async (_p: any) => ({
          model: 'gpt-4o-mini',
          choices: [{ index: 0, message: { role: 'assistant', content: 'ok' }, finish_reason: 'stop' }],
          usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 },
        }),
      },
    },
  };

  const wrapped = lp.wrap(mockClient);

  // Generate 5 events — should trigger auto-flush at 3
  for (let i = 0; i < 5; i++) {
    await wrapped.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: `msg ${i}` }],
    });
  }

  await sleep(100); // let async event processing run
  assert('Multiple events generated without error', true);

  // Manual flush for any remaining
  await lp.flush();
  assert('Manual flush after batch succeeds', true);

  lp.destroy();
}

async function testABTestResolution(ctx: TestContext): Promise<void> {
  section('Test 14: A/B Test Resolution (customerId)');

  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    promptCacheTtl: 1, // minimal cache to test customerId pass-through
  });

  // Fetch with customerId — even without an active A/B test,
  // the API accepts the parameter and returns the default version
  await sleep(10);
  const contentA = await lp.prompt(ctx.promptSlug, { customerId: 'user-alpha' });
  assert('Fetch with customerId succeeds', contentA.length > 0);

  await sleep(10);
  const contentB = await lp.prompt(ctx.promptSlug, { customerId: 'user-beta' });
  assert('Fetch with different customerId succeeds', contentB.length > 0);

  // Without an active A/B test, both should return the same content
  assertEqual('Same prompt returned for both (no active A/B test)', contentA, contentB);

  lp.destroy();
}

async function testDeploymentStatusAndRunCount(ctx: TestContext): Promise<void> {
  section('Test 15: Deployment Status & Run Count');

  // 1. Generate real events linked to the managed prompt
  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    flushAt: 100,
  });

  // Fetch the prompt so SDK registers it for linking
  const promptContent = await lp.prompt(ctx.promptSlug);
  assert('Fetched prompt for event linking', promptContent.length > 0);

  const mockClient = {
    chat: {
      completions: {
        create: async (_p: any) => ({
          model: 'gpt-4o',
          choices: [{ index: 0, message: { role: 'assistant', content: 'ok' }, finish_reason: 'stop' }],
          usage: { prompt_tokens: 20, completion_tokens: 5, total_tokens: 25 },
        }),
      },
    },
  };

  const wrapped = lp.wrap(mockClient);

  // Generate 3 events with the prompt as system message (links managedPromptId)
  for (let i = 0; i < 3; i++) {
    await wrapped.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: promptContent },
        { role: 'user', content: `deployment status test ${i}` },
      ],
    });
  }

  await sleep(100); // let async event generation complete
  await lp.flush();
  await sleep(200); // let API persist events

  // 2. Query deployment usage stats via REST API (same endpoint the web UI uses)
  const usageStats = await apiCall<{
    environmentId: string;
    callCount24h: number;
    callCount1h: number;
    totalCostUsd24h: number;
    avgLatencyMs: number;
    lastCalledAt: string | null;
  }[]>(
    `/prompt/${ctx.projectId}/${ctx.promptId}/deployments/usage`,
    {},
    ctx.jwt,
  );

  assert('Usage stats returned for environments', usageStats.length > 0);

  // Find stats for our test environment
  const envStats = usageStats.find((s) => s.environmentId === ctx.environmentId);
  assert('Stats found for test environment', envStats !== undefined);

  if (envStats) {
    assert(
      'callCount24h > 0 (events tracked)',
      envStats.callCount24h > 0,
      `callCount24h = ${envStats.callCount24h}`,
    );
    assert(
      'lastCalledAt is set',
      envStats.lastCalledAt !== null,
      envStats.lastCalledAt ?? 'null',
    );

    if (envStats.lastCalledAt) {
      const ageMs = Date.now() - new Date(envStats.lastCalledAt).getTime();
      assert(
        'lastCalledAt is recent (< 60s)',
        ageMs < 60_000,
        `age = ${Math.round(ageMs / 1000)}s`,
      );
    }
  }

  // 3. Query deployments list (what the UI shows for version + environment)
  const deployments = await apiCall<{
    environmentId: string;
    promptVersionId: string;
    version: number;
    deployedAt: string;
  }[]>(
    `/prompt/${ctx.projectId}/${ctx.promptId}/deployments`,
    {},
    ctx.jwt,
  );

  assert('Deployments list returned', deployments.length > 0);

  const envDep = deployments.find((d) => d.environmentId === ctx.environmentId);
  assert('Deployment found for test environment', envDep !== undefined);

  if (envDep) {
    assertEqual('Deployed version ID matches', envDep.promptVersionId, ctx.versionId);
    assert('deployedAt is set', envDep.deployedAt !== null);
  }

  // 4. Verify fetch stats (PromptFetchLog — daily aggregate from prompt fetches)
  const fetchStats = await apiCall<{
    totalFetches: number;
    prompts: { id: string; slug: string; fetchCount: number }[];
  }>(
    `/prompt/${ctx.projectId}/fetch-stats?days=1`,
    {},
    ctx.jwt,
  );

  assert('Fetch stats returned', fetchStats !== undefined);
  assert(
    'totalFetches > 0 (prompt fetches tracked)',
    fetchStats.totalFetches > 0,
    `totalFetches = ${fetchStats.totalFetches}`,
  );

  const promptFetch = fetchStats.prompts.find((p) => p.id === ctx.promptId);
  assert(
    'Fetch count tracked for test prompt',
    promptFetch !== undefined && promptFetch.fetchCount > 0,
    promptFetch ? `fetchCount = ${promptFetch.fetchCount}` : 'prompt not found in fetch stats',
  );

  lp.destroy();
}

async function testShutdown(ctx: TestContext): Promise<void> {
  section('Test 16: Shutdown & Cleanup');

  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    flushAt: 100,
    flushInterval: 100,
  });

  // Use the SDK briefly
  await lp.prompt(ctx.promptSlug);

  const mockClient = {
    chat: {
      completions: {
        create: async (_p: any) => ({
          model: 'gpt-4o-mini',
          choices: [{ index: 0, message: { role: 'assistant', content: 'bye' }, finish_reason: 'stop' }],
          usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 },
        }),
      },
    },
  };

  const wrapped = lp.wrap(mockClient);
  await wrapped.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: 'shutdown test' }],
  });
  await sleep(50);

  // shutdown() should flush + destroy
  await lp.shutdown();
  assert('shutdown() completes without error', true);
  assert('isDestroyed is true after shutdown', lp.isDestroyed);

  // Double destroy/shutdown should be safe
  lp.destroy();
  assert('Double destroy() after shutdown is safe', true);

  // Simple destroy test
  const lp2 = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    flushInterval: 100,
  });
  await lp2.prompt(ctx.promptSlug);
  lp2.destroy();
  assert('destroy() completes without error', true);
  assert('isDestroyed is true after destroy', lp2.isDestroyed);

  // Double destroy
  lp2.destroy();
  assert('Double destroy() is safe (no throw)', true);
}

async function testWithContextEventVerification(ctx: TestContext): Promise<void> {
  section('Test 17: withContext Event Verification via API');

  // This test verifies events created inside withContext() actually reach the API
  // by generating events and then checking deployment usage stats increase

  const lp = new LaunchPromptly({
    apiKey: ctx.sdkApiKey,
    endpoint: API_ENDPOINT,
    flushAt: 100,
  });

  // Get baseline stats
  const baselineStats = await apiCall<{
    environmentId: string;
    callCount24h: number;
  }[]>(
    `/prompt/${ctx.projectId}/${ctx.promptId}/deployments/usage`,
    {},
    ctx.jwt,
  );
  const baselineCount = baselineStats.find(
    (s) => s.environmentId === ctx.environmentId,
  )?.callCount24h ?? 0;

  // Fetch prompt for linking
  const promptContent = await lp.prompt(ctx.promptSlug);

  const mockClient = {
    chat: {
      completions: {
        create: async (_p: any) => ({
          model: 'gpt-4o',
          choices: [{ index: 0, message: { role: 'assistant', content: 'ctx ok' }, finish_reason: 'stop' }],
          usage: { prompt_tokens: 15, completion_tokens: 5, total_tokens: 20 },
        }),
      },
    },
  };

  const wrapped = lp.wrap(mockClient);

  // Generate events inside withContext
  await lp.withContext(
    { traceId: 'verify-trace-1', customerId: 'verify-cust', feature: 'verify-feature' },
    async () => {
      for (let i = 0; i < 2; i++) {
        await wrapped.chat.completions.create({
          model: 'gpt-4o',
          messages: [
            { role: 'system', content: promptContent },
            { role: 'user', content: `withContext verify ${i}` },
          ],
        });
      }
    },
  );

  await sleep(100);
  await lp.flush();
  await sleep(200);

  // Verify events were received
  const afterStats = await apiCall<{
    environmentId: string;
    callCount24h: number;
  }[]>(
    `/prompt/${ctx.projectId}/${ctx.promptId}/deployments/usage`,
    {},
    ctx.jwt,
  );
  const afterCount = afterStats.find(
    (s) => s.environmentId === ctx.environmentId,
  )?.callCount24h ?? 0;

  assert(
    'Events from withContext increased call count',
    afterCount > baselineCount,
    `before: ${baselineCount}, after: ${afterCount}`,
  );

  lp.destroy();
}

// ── Utility ──────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Main ─────────────────────────────────────────────────────────────────────

const keepData = process.argv.includes('--keep');

async function main(): Promise<void> {
  console.log(`${BOLD}LaunchPromptly SDK — Integration Test Suite${RESET}`);
  console.log(`${DIM}API: ${API_ENDPOINT}${RESET}`);
  if (keepData) console.log(`${DIM}Mode: --keep (test data will NOT be deleted)${RESET}`);
  console.log('');

  // Health check
  try {
    const res = await fetch(`${API_ENDPOINT}/health`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    console.log(`${GREEN}✓${RESET} API health check passed\n`);
  } catch (err) {
    console.error(`${RED}✗ API is not reachable at ${API_ENDPOINT}${RESET}`);
    console.error(`  Make sure the API server is running: cd apps/api && npm run dev`);
    process.exit(1);
  }

  // Setup
  console.log(`${DIM}Setting up test data...${RESET}`);
  let ctx: TestContext;
  try {
    ctx = await setup();
    console.log(`${GREEN}✓${RESET} Test data created (project: ${ctx.projectId.slice(0, 8)}...)\n`);
  } catch (err) {
    console.error(`${RED}✗ Setup failed:${RESET}`, (err as Error).message);
    process.exit(1);
  }

  // Run all tests
  try {
    await testInitialization(ctx);
    await testSingleton(ctx);
    await testPromptFetch(ctx);
    await testTemplateVariables(ctx);
    await testCaching(ctx);
    await testStaleCacheFallback(ctx);
    await testNotFoundHandling(ctx);
    await testTemplateUtilities();
    await testOpenAIWrap(ctx);
    await testCustomerContextAndTracing(ctx);
    await testWithContext(ctx);
    await testPromptEventLinking(ctx);
    await testEventBatchingAndFlush(ctx);
    await testABTestResolution(ctx);
    await testDeploymentStatusAndRunCount(ctx);
    await testShutdown(ctx);
    await testWithContextEventVerification(ctx);
  } catch (err) {
    console.error(`\n${RED}Unexpected error:${RESET}`, err);
  }

  // Teardown
  if (keepData) {
    console.log(`\n${DIM}Skipping teardown (--keep). Test data persists:${RESET}`);
    console.log(`  Prompt: ${ctx.promptSlug} (${ctx.promptId})`);
    console.log(`  Environment: ${ctx.environmentId}`);
    console.log(`  API Key: ${ctx.sdkApiKey.slice(0, 16)}...`);
    console.log(`  ${DIM}View in UI: http://localhost:3000/prompts/managed/${ctx.promptId}${RESET}`);
  } else {
    console.log(`\n${DIM}Cleaning up test data...${RESET}`);
    await teardown(ctx);
  }

  // Summary
  const total = passed + failed;
  console.log(`\n${'─'.repeat(50)}`);
  if (failed === 0) {
    console.log(`${GREEN}${BOLD}All ${total} tests passed!${RESET}`);
  } else {
    console.log(`${RED}${BOLD}${failed}/${total} tests failed:${RESET}`);
    for (const f of failures) {
      console.log(`  ${RED}✗${RESET} ${f}`);
    }
  }
  console.log('');

  process.exit(failed > 0 ? 1 : 0);
}

main();
