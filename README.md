# launchpromptly

Official Node.js SDK for [LaunchPromptly](https://launchpromptly.dev) — runtime safety layer for LLM applications. PII redaction, prompt injection detection, cost guards, and content filtering with zero dependencies.

## Install

```bash
npm install launchpromptly
```

## Quick Start

```typescript
import { LaunchPromptly } from 'launchpromptly';
import OpenAI from 'openai';

const lp = new LaunchPromptly({
  apiKey: 'lp_live_...',
  security: {
    pii: { enabled: true, redaction: 'placeholder' },
    injection: { enabled: true, blockOnHighRisk: true },
    costGuard: { maxCostPerRequest: 0.50 },
  },
});

// Wrap your OpenAI client — all security features activate automatically
const openai = lp.wrap(new OpenAI(), {
  customer: () => ({ id: getCurrentUser().id }),
  feature: 'chat',
});

// Use openai as normal — PII is redacted, injections are blocked
const response = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: userInput }],
});
// If userInput contains "john@acme.com", the LLM receives "[EMAIL_1]"
// The response is de-redacted before being returned to your code

await lp.flush(); // On server shutdown
```

## Features

- **PII Redaction** — 16 built-in regex detectors (email, phone, SSN, credit card, IP, etc.) with pluggable ML providers
- **Prompt Injection Detection** — Rule-based scoring across 5 attack categories with configurable thresholds
- **Cost Guards** — Per-request, per-minute, per-hour, per-day, and per-customer budget limits
- **Content Filtering** — Block or warn on hate speech, violence, self-harm, and custom patterns
- **Model Policy** — Restrict which models, providers, and parameters are allowed
- **Output Schema Validation** — Validate LLM responses against JSON schemas
- **Streaming Guards** — Mid-stream PII scanning, injection detection, and response length limits
- **Multi-Provider** — Wrap OpenAI, Anthropic, and Google Gemini clients
- **Zero Dependencies** — No runtime dependencies; everything runs client-side
- **Event Dashboard** — Enriched security events sent to your LaunchPromptly dashboard

## Security Pipeline

On every LLM call, the SDK runs these checks in order:

1. Cost guard (estimate cost, check budgets)
2. PII scan & redact (replace PII with placeholders)
3. Injection detection (score risk, warn/block)
4. Content filter (check input policy violations)
5. **LLM API Call** (with redacted content)
6. Response PII scan (defense-in-depth)
7. Response content filter
8. Output schema validation
9. De-redact response (restore original values)
10. Send enriched event to dashboard

## API

### `new LaunchPromptly(options?)`

| Option | Default | Description |
|--------|---------|-------------|
| `apiKey` | `LAUNCHPROMPTLY_API_KEY` env | Your LaunchPromptly API key |
| `endpoint` | `https://launchpromptly-api-950530830180.us-west1.run.app` | API base URL |
| `flushAt` | `10` | Batch size threshold for auto-flush |
| `flushInterval` | `5000` | Timer interval for auto-flush (ms) |
| `on` | — | Guardrail event handlers |

### `lp.wrap(client, options?)`

Wrap an LLM client with security guardrails. Supports OpenAI, Anthropic, and Gemini.

```typescript
const wrapped = lp.wrap(new OpenAI(), {
  feature: 'chat',
  customer: () => ({ id: 'user-42' }),
  traceId: 'req-abc-123',
  security: {
    pii: { enabled: true, redaction: 'placeholder' },
    injection: { enabled: true, blockOnHighRisk: true },
    costGuard: { maxCostPerRequest: 1.00 },
    contentFilter: { enabled: true, categories: ['hate_speech', 'violence'] },
    modelPolicy: { allowedModels: ['gpt-4o', 'gpt-4o-mini'] },
    streamGuard: { piiScan: true, onViolation: 'abort' },
    outputSchema: { schema: myJsonSchema, strict: true },
  },
});
```

### PII Redaction Options

```typescript
{
  pii: {
    enabled: true,
    redaction: 'placeholder',  // 'placeholder' | 'mask' | 'hash' | 'none'
    types: ['email', 'phone', 'ssn', 'credit_card', 'ip_address'],
    scanResponse: true,
    providers: [new PresidioPIIDetector()],  // optional ML providers
    onDetect: (detections) => log(detections),
  }
}
```

**Built-in PII types:** `email`, `phone`, `ssn`, `credit_card`, `ip_address`, `iban`, `drivers_license`, `uk_nino`, `nhs_number`, `passport`, `aadhaar`, `eu_phone`, `us_address`, `api_key`, `date_of_birth`, `medicare`

### Injection Detection Options

```typescript
{
  injection: {
    enabled: true,
    blockThreshold: 0.7,     // 0-1 risk score
    blockOnHighRisk: true,   // throw PromptInjectionError
    providers: [new MLInjectionDetector()],  // optional ML providers
    onDetect: (analysis) => log(analysis.riskScore),
  }
}
```

### Cost Guard Options

```typescript
{
  costGuard: {
    maxCostPerRequest: 1.00,
    maxCostPerMinute: 10.00,
    maxCostPerHour: 50.00,
    maxCostPerDay: 200.00,
    maxCostPerCustomer: 5.00,
    maxTokensPerRequest: 100000,
    blockOnExceed: true,
  }
}
```

### `lp.withContext(ctx, fn)`

Propagate request context via AsyncLocalStorage.

```typescript
await lp.withContext({ traceId: 'req-123', customerId: 'user-42' }, async () => {
  // All SDK calls inside inherit the context
  await wrapped.chat.completions.create({ ... });
});
```

### `lp.flush()` / `lp.destroy()`

- `flush()` — send all pending events
- `destroy()` — stop timers and release resources

## Error Handling

```typescript
import {
  PromptInjectionError,
  CostLimitError,
  ContentViolationError,
  ModelPolicyError,
  OutputSchemaError,
  StreamAbortError,
} from 'launchpromptly';

try {
  const res = await wrapped.chat.completions.create({ ... });
} catch (err) {
  if (err instanceof PromptInjectionError) {
    // err.analysis — injection risk analysis
  } else if (err instanceof CostLimitError) {
    // err.violation — which budget was exceeded
  } else if (err instanceof ContentViolationError) {
    // err.violations — list of content policy violations
  }
}
```

## Guardrail Events

Subscribe to security events for logging or alerting:

```typescript
const lp = new LaunchPromptly({
  apiKey: 'lp_live_...',
  on: {
    'pii.detected': (e) => log('PII found', e.data),
    'injection.blocked': (e) => alert('Injection blocked', e.data),
    'cost.exceeded': (e) => alert('Budget exceeded', e.data),
  },
});
```

**Event types:** `pii.detected`, `pii.redacted`, `injection.detected`, `injection.blocked`, `cost.exceeded`, `content.violated`, `schema.invalid`, `model.blocked`

## ML-Enhanced Detection (Optional)

The core SDK uses regex and rule-based detection — zero dependencies, sub-millisecond. For higher accuracy on obfuscated attacks and nuanced content, opt in to local ML models:

```bash
npm install @huggingface/transformers
```

```typescript
import { LaunchPromptly } from 'launchpromptly';
import { MLToxicityDetector, MLInjectionDetector, MLPIIDetector } from 'launchpromptly/ml';

// Load models (async — first run downloads from HuggingFace)
const [toxicity, injection, pii] = await Promise.all([
  MLToxicityDetector.create(),     // Xenova/toxic-bert (~170MB)
  MLInjectionDetector.create(),    // protectai/deberta-v3 (~350MB)
  MLPIIDetector.create(),          // Xenova/bert-base-NER (~170MB)
]);

const lp = new LaunchPromptly({
  apiKey: process.env.LP_KEY,
  security: {
    pii: {
      enabled: true,
      redaction: 'placeholder',
      providers: [pii],       // Adds NER: person names, orgs, locations
    },
    injection: {
      enabled: true,
      providers: [injection], // Semantic injection detection via DeBERTa
    },
    contentFilter: {
      enabled: true,
      providers: [toxicity],  // ML toxicity: hate speech, threats, obscenity
    },
  },
});
```

### Layered Defense

ML providers **merge with** the built-in regex/rule detectors — they don't replace them:

| Layer | Speed | Catches | Dependencies |
|-------|-------|---------|-------------|
| **Layer 1: Regex/Rules** (always on) | <1ms | Obvious patterns — emails, SSNs, keyword injection | None |
| **Layer 2: Local ML** (opt-in) | <100ms | Obfuscated attacks, person names, nuanced hate speech | `@huggingface/transformers` |

All ML inference runs locally — no data leaves your infrastructure.

### ML Detectors

| Detector | Model | What it adds |
|----------|-------|-------------|
| `MLToxicityDetector` | `Xenova/toxic-bert` | Hate speech, threats, obscenity, identity attacks |
| `MLInjectionDetector` | `protectai/deberta-v3-base-prompt-injection-v2` | Semantic prompt injection (catches obfuscated/encoded attacks) |
| `MLPIIDetector` | `Xenova/bert-base-NER` | Person names, organization names, locations (NER) |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `LAUNCHPROMPTLY_API_KEY` | API key (alternative to passing in constructor) |
| `LP_API_KEY` | Shorthand alias |

## License

MIT
