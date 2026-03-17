/**
 * Red Team runner — executes attacks against a wrapped LLM client,
 * captures guardrail events, and generates a security report.
 * @module
 */

import type { GuardrailEvent } from '../types';
import type {
  AttackPayload,
  AttackResult,
  GuardrailEventCapture,
  RedTeamOptions,
  RedTeamReport,
} from './types';
import { BUILT_IN_ATTACKS, getBuiltInAttacks, injectSystemPrompt } from './attacks';
import { analyzeAttackResult } from './analyzer';
import { generateReport } from './reporter';

// ── Helpers ──────────────────────────────────────────────────────────────────

function shuffle<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Extract response text from various provider response formats.
 */
function extractResponseText(result: unknown): string | undefined {
  if (!result || typeof result !== 'object') return undefined;
  const r = result as Record<string, unknown>;

  // OpenAI format
  if (Array.isArray(r.choices)) {
    const first = r.choices[0] as Record<string, unknown> | undefined;
    if (first) {
      const msg = first.message as Record<string, unknown> | undefined;
      if (msg && typeof msg.content === 'string') return msg.content;
    }
  }

  // Anthropic format
  if (Array.isArray(r.content)) {
    const texts: string[] = [];
    for (const block of r.content as Array<Record<string, unknown>>) {
      if (block.type === 'text' && typeof block.text === 'string') {
        texts.push(block.text);
      }
    }
    if (texts.length > 0) return texts.join('');
  }

  // Gemini format
  if (typeof (r as any).text === 'function') {
    try {
      return (r as any).text();
    } catch {
      // ignore
    }
  }

  return undefined;
}

/**
 * Detect provider type and call the appropriate chat method.
 */
async function callWrappedClient(
  client: unknown,
  messages: AttackPayload['messages'],
  model?: string,
): Promise<unknown> {
  const c = client as Record<string, unknown>;

  // OpenAI-style: client.chat.completions.create()
  if (c.chat && typeof c.chat === 'object') {
    const chat = c.chat as Record<string, unknown>;
    if (chat.completions && typeof chat.completions === 'object') {
      const completions = chat.completions as Record<string, unknown>;
      if (typeof completions.create === 'function') {
        const params: Record<string, unknown> = { messages };
        if (model) params.model = model;
        else params.model = 'gpt-4o-mini';
        return completions.create(params);
      }
    }
  }

  // Anthropic-style: client.messages.create()
  if (c.messages && typeof c.messages === 'object') {
    const msgs = c.messages as Record<string, unknown>;
    if (typeof msgs.create === 'function') {
      // Anthropic needs system separate from messages
      const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n');
      const nonSystem = messages.filter((m) => m.role !== 'system');
      const params: Record<string, unknown> = {
        messages: nonSystem,
        max_tokens: 256,
      };
      if (system) params.system = system;
      if (model) params.model = model;
      else params.model = 'claude-sonnet-4-20250514';
      return msgs.create(params);
    }
  }

  // Gemini-style: client.models.generateContent()
  if (c.models && typeof c.models === 'object') {
    const models = c.models as Record<string, unknown>;
    if (typeof models.generateContent === 'function') {
      const contents = messages
        .filter((m) => m.role !== 'system')
        .map((m) => ({
          role: m.role === 'assistant' ? 'model' : 'user',
          parts: [{ text: m.content }],
        }));
      const params: Record<string, unknown> = {
        model: model || 'gemini-2.0-flash',
        contents,
      };
      const systemMsg = messages.find((m) => m.role === 'system');
      if (systemMsg) {
        params.config = { systemInstruction: systemMsg.content };
      }
      return models.generateContent(params);
    }
  }

  throw new Error('Unsupported client format. Expected OpenAI, Anthropic, or Gemini client.');
}

// ── Semaphore for bounded concurrency ────────────────────────────────────────

class Semaphore {
  private _available: number;
  private _queue: Array<() => void> = [];

  constructor(max: number) {
    this._available = max;
  }

  async acquire(): Promise<void> {
    if (this._available > 0) {
      this._available--;
      return;
    }
    return new Promise<void>((resolve) => {
      this._queue.push(resolve);
    });
  }

  release(): void {
    const next = this._queue.shift();
    if (next) {
      next();
    } else {
      this._available++;
    }
  }
}

// ── Runner ───────────────────────────────────────────────────────────────────

/**
 * Run the red team attack suite against a wrapped LLM client.
 *
 * @param wrappedClient - A client previously returned by `lp.wrap()`
 * @param lpInstance - The LaunchPromptly instance (for event interception)
 * @param options - Red team configuration
 */
export async function runRedTeam(
  wrappedClient: unknown,
  lpInstance: unknown,
  options: RedTeamOptions = {},
): Promise<RedTeamReport> {
  const {
    categories,
    maxAttacks = 50,
    concurrency = 3,
    delayMs = 500,
    systemPrompt,
    customAttacks = [],
    onProgress,
    model,
    dryRun = false,
  } = options;

  // 1. Build attack list
  let attacks: AttackPayload[] = [
    ...getBuiltInAttacks(categories),
    ...customAttacks,
  ];

  // 2. Inject system prompt into prompt_leakage attacks
  if (systemPrompt) {
    attacks = injectSystemPrompt(attacks, systemPrompt);
  }

  // 3. Shuffle and limit
  attacks = shuffle(attacks).slice(0, maxAttacks);

  // 4. Dry run — just validate
  if (dryRun) {
    const dryResults: AttackResult[] = attacks.map((attack) => ({
      attack,
      outcome: 'inconclusive' as const,
      guardrailEvents: [],
      latencyMs: 0,
      analysisReason: 'Dry run — no LLM calls made',
    }));
    return generateReport(dryResults, 0, 0);
  }

  // 5. Set up event interception
  const lp = lpInstance as Record<string, unknown>;
  const originalEmit = lp._emit as (type: string, data: Record<string, unknown>) => void;
  let capturedEvents: GuardrailEventCapture[] = [];

  // Replace _emit to capture events per-attack
  lp._emit = function interceptedEmit(type: string, data: Record<string, unknown>) {
    capturedEvents.push({ type, data, timestamp: Date.now() });
    // Still call original so user handlers fire
    originalEmit.call(lp, type, data);
  };

  const results: AttackResult[] = [];
  const sem = new Semaphore(concurrency);
  const startTime = Date.now();
  let estimatedCost = 0;

  // 6. Execute attacks
  const tasks = attacks.map((attack, idx) => {
    return (async () => {
      await sem.acquire();
      try {
        // Isolate event capture for this attack
        const myEvents: GuardrailEventCapture[] = [];
        const prevEvents = capturedEvents;
        capturedEvents = myEvents;

        const attackStart = Date.now();
        let responseText: string | undefined;
        let error: Error | undefined;

        try {
          const result = await callWrappedClient(wrappedClient, attack.messages, model);
          responseText = extractResponseText(result);
        } catch (e) {
          error = e instanceof Error ? e : new Error(String(e));
        }

        const latencyMs = Date.now() - attackStart;

        // Estimate cost (rough: ~200 input + 100 output tokens at $0.001/1K)
        estimatedCost += 0.0003;

        const analysis = analyzeAttackResult({
          attack,
          responseText,
          error,
          guardrailEvents: myEvents,
        });

        const attackResult: AttackResult = {
          attack,
          outcome: analysis.outcome,
          responsePreview: responseText?.slice(0, 500),
          guardrailEvents: myEvents,
          error: error?.message,
          latencyMs,
          analysisReason: analysis.reason,
        };

        results.push(attackResult);

        // Restore parent event capture
        capturedEvents = prevEvents;

        // Progress callback
        onProgress?.({
          completed: results.length,
          total: attacks.length,
          currentAttack: attack.name,
          currentCategory: attack.category,
        });

        // Delay between attacks
        if (delayMs > 0 && idx < attacks.length - 1) {
          await delay(delayMs);
        }
      } finally {
        sem.release();
      }
    })();
  });

  await Promise.all(tasks);

  // 7. Restore original _emit
  lp._emit = originalEmit;

  // 8. Generate report
  const totalDuration = Date.now() - startTime;
  return generateReport(results, totalDuration, estimatedCost);
}
