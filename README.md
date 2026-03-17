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
- **Jailbreak Detection** — Catches role-play exploits, DAN prompts, and system prompt override attempts
- **Prompt Leakage Detection** — Flags when the LLM accidentally echoes back system instructions or internal context
- **Unicode Sanitizer** — Strips or blocks invisible characters, homoglyphs, and zero-width sequences used to bypass filters
- **Secret/Credential Detection** — Catches API keys, tokens, passwords, and connection strings before they reach the LLM
- **Topic Guard** — Block or warn when conversations drift into off-limits subjects you define
- **Output Safety Scanning** — Scans LLM responses for harmful instructions, unsafe code patterns, and dangerous content
- **Tool Guard** — Whitelist/blacklist tool calls, catch SQL injection and path traversal in args, scan tool outputs for PII
- **Chain-of-Thought Guard** — Scan `<thinking>` blocks for injection and system prompt leaks
- **Conversation Guard** — Turn limits, cumulative risk scoring, agent loop detection, cross-turn PII tracking
- **Multi-Language PII** — ID detection for 8 countries (Brazil CPF, China National ID, Japan My Number, etc.)
- **Multi-Language Content Filter** — 10 languages with auto-detection (es, pt, zh, ja, ko, de, fr, ar, hi, ru)
- **Eval CLI** — ~200 built-in attack tests, threshold-based CI/CD gating
- **Cost Guards** — Per-request, per-minute, per-hour, per-day, and per-customer budget limits
- **Content Filtering** — Block or warn on hate speech, violence, self-harm, and custom patterns
- **Model Policy** — Restrict which models, providers, and parameters are allowed
- **Output Schema Validation** — Validate LLM responses against JSON schemas
- **Streaming Guards** — Mid-stream PII scanning, injection detection, and response length limits
- **Multi-Provider** — Wrap OpenAI, Anthropic, and Google Gemini clients
- **Zero Dependencies** — No runtime dependencies; everything runs client-side
- **Event Dashboard** — Enriched security events sent to your LaunchPromptly dashboard

## Security Pipeline

On every LLM call, the SDK runs a 20-step pipeline split across pre-call and post-call phases:

**PRE-CALL:**

1. Unicode Sanitizer — strip/warn/block invisible characters
2. Model Policy Check — enforce allowed models and parameters
3. Cost Guard Pre-Check — estimate cost, check budgets
4. PII Detection (input) — scan for personal data
5. PII Redaction (input) — replace PII with placeholders
6. Secret Detection (input) — catch API keys, tokens, passwords
7. Injection Detection — score risk, warn/block
8. Jailbreak Detection — catch role-play exploits and system overrides
9. Content Filter (input) — check policy violations
10. Topic Guard — block off-limits subjects

**>>> LLM API Call >>>**

**POST-CALL:**

11. Content Filter (output) — scan response for policy violations
12. Output Safety Scan — check for harmful instructions or unsafe code
13. Prompt Leakage Detection — flag leaked system prompts
14. Schema Validation — enforce JSON structure
15. Secret Detection (output) — catch credentials in response
16. PII Detection (output) — defense-in-depth scan
17. PII De-redaction — restore original values
18. Cost Guard Post-Recording — track actual cost
19. Event Batching — queue enriched event
20. Guardrail Events — fire registered callbacks

## API

### `new LaunchPromptly(options?)`

| Option | Default | Description |
|--------|---------|-------------|
| `apiKey` | `LAUNCHPROMPTLY_API_KEY` env | Your LaunchPromptly API key |
| `endpoint` | `https://api.launchpromptly.dev` | API base URL |
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
    jailbreak: { enabled: true, blockOnDetect: true },
    promptLeakage: { enabled: true },
    unicodeSanitizer: { enabled: true, action: 'strip' },
    secretDetection: { enabled: true, blockOnDetect: true },
    topicGuard: { enabled: true, blockedTopics: ['politics', 'medical-advice'] },
    outputSafety: { enabled: true, blockUnsafe: true },
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

### Jailbreak Detection Options

```typescript
{
  jailbreak: {
    enabled: true,
    blockOnDetect: true,       // throw JailbreakError on detection
    sensitivity: 'medium',     // 'low' | 'medium' | 'high'
    onDetect: (result) => log(result.technique),
  }
}
```

Catches DAN ("Do Anything Now") prompts, role-play exploits ("You are now EvilGPT"), system prompt override attempts, and similar jailbreak techniques. The detector runs pattern matching and structural analysis on the input.

### Prompt Leakage Detection Options

```typescript
{
  promptLeakage: {
    enabled: true,
    systemPrompt: 'You are a helpful assistant...',  // optional: provide for exact matching
    sensitivity: 'medium',     // 'low' | 'medium' | 'high'
    onDetect: (result) => log(result.leakedContent),
  }
}
```

Scans LLM output for signs that the model is echoing back system instructions, internal context, or tool definitions. If you provide the `systemPrompt`, the detector can do exact substring matching in addition to heuristic checks.

### Unicode Sanitizer Options

```typescript
{
  unicodeSanitizer: {
    enabled: true,
    action: 'strip',           // 'strip' | 'warn' | 'block'
    allowEmoji: true,          // keep standard emoji (default: true)
    onSuspicious: (result) => log(result.found),
  }
}
```

Detects and handles invisible characters (zero-width joiners, RTL overrides, homoglyphs, tag characters) that attackers use to sneak prompts past text-based filters. The `strip` action removes them silently, `warn` lets the request through but fires an event, and `block` rejects the request.

### Secret Detection Options

```typescript
{
  secretDetection: {
    enabled: true,
    blockOnDetect: true,       // throw SecretDetectedError
    scanResponse: true,        // also scan LLM output (default: true)
    types: ['api_key', 'aws_key', 'github_token', 'jwt', 'connection_string', 'private_key'],
    onDetect: (secrets) => alert(secrets),
  }
}
```

Catches API keys, AWS credentials, GitHub tokens, JWTs, database connection strings, and private keys in both input and output. Uses pattern matching tuned to minimize false positives on normal text.

### Topic Guard Options

```typescript
{
  topicGuard: {
    enabled: true,
    blockedTopics: ['politics', 'medical-advice', 'legal-advice', 'financial-advice'],
    action: 'block',           // 'block' | 'warn'
    customTopics: [
      { name: 'competitor-discussion', patterns: ['CompetitorCo', 'their product'] },
    ],
    onViolation: (result) => log(result.topic),
  }
}
```

Prevents the conversation from going into subjects you want to keep off-limits. Comes with built-in topic categories and supports custom topics defined by keyword patterns.

### Output Safety Options

```typescript
{
  outputSafety: {
    enabled: true,
    blockUnsafe: true,         // throw OutputSafetyError
    categories: ['harmful_instructions', 'unsafe_code', 'dangerous_content'],
    onDetect: (result) => log(result.category),
  }
}
```

Scans LLM responses for harmful instructions (e.g., "how to build a weapon"), unsafe code patterns (e.g., `eval()` with user input, SQL without parameterization), and other dangerous content. This is separate from content filtering -- content filters check for policy violations like hate speech, while output safety checks for responses that could cause real-world harm if followed.

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
  JailbreakError,
  CostLimitError,
  ContentViolationError,
  ModelPolicyError,
  OutputSchemaError,
  OutputSafetyError,
  SecretDetectedError,
  TopicViolationError,
  UnicodeBlockError,
  StreamAbortError,
} from 'launchpromptly';

try {
  const res = await wrapped.chat.completions.create({ ... });
} catch (err) {
  if (err instanceof PromptInjectionError) {
    // err.analysis — injection risk analysis
  } else if (err instanceof JailbreakError) {
    // err.technique — which jailbreak technique was detected
  } else if (err instanceof CostLimitError) {
    // err.violation — which budget was exceeded
  } else if (err instanceof ContentViolationError) {
    // err.violations — list of content policy violations
  } else if (err instanceof SecretDetectedError) {
    // err.secrets — list of detected secrets (types only, not values)
  } else if (err instanceof TopicViolationError) {
    // err.topic — which blocked topic was triggered
  } else if (err instanceof OutputSafetyError) {
    // err.category — what kind of unsafe content was found
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
    'jailbreak.detected': (e) => log('Jailbreak attempt', e.data),
    'jailbreak.blocked': (e) => alert('Jailbreak blocked', e.data),
    'unicode.suspicious': (e) => log('Suspicious unicode', e.data),
    'secret.detected': (e) => alert('Secret found in text', e.data),
    'topic.violated': (e) => log('Off-limits topic', e.data),
    'output.unsafe': (e) => alert('Unsafe output detected', e.data),
    'prompt.leaked': (e) => alert('System prompt leaked', e.data),
  },
});
```

**Event types:** `pii.detected`, `pii.redacted`, `injection.detected`, `injection.blocked`, `jailbreak.detected`, `jailbreak.blocked`, `unicode.suspicious`, `secret.detected`, `topic.violated`, `output.unsafe`, `prompt.leaked`, `cost.exceeded`, `content.violated`, `schema.invalid`, `model.blocked`

## ML-Enhanced Detection (Optional)

The core SDK uses regex and rule-based detection — zero dependencies, sub-millisecond. For higher accuracy on obfuscated attacks and nuanced content, opt in to local ML models:

```bash
npm install @huggingface/transformers
```

```typescript
import { LaunchPromptly } from 'launchpromptly';
import { MLToxicityDetector, MLInjectionDetector, MLPIIDetector } from 'launchpromptly/ml';

// Load models (first run downloads from HuggingFace, cached after)
const [toxicity, injection, pii] = await Promise.all([
  MLToxicityDetector.create(),     // Xenova/toxic-bert (~106MB quantized)
  MLInjectionDetector.create(),    // protectai/deberta-v3 (~704MB)
  MLPIIDetector.create(),          // Xenova/bert-base-NER (~170MB quantized)
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

### Pre-downloading models

For Docker or air-gapped deployments, pre-download models at build time:

```bash
npx launchpromptly download-models --cache-dir /app/.models
```

Then point your detectors at the cache:

```typescript
MLInjectionDetector.create({ cacheDir: '/app/.models' })
MLToxicityDetector.create({ cacheDir: '/app/.models' })
```

Available flags: `--models toxicity,injection` (comma-separated) and `--cache-dir <path>`.

## Agentic AI guardrails

Guards for tool-calling agents, reasoning models, and multi-turn conversations.

### Tool guard

Checks tool calls before they execute:

```typescript
const openai = lp.wrap(new OpenAI(), {
  security: {
    toolGuard: {
      allowedTools: ['search_web', 'calculator'],
      dangerousArgDetection: true,  // SQL injection, path traversal, shell, SSRF
      maxToolCallsPerTurn: 5,
      scanToolResults: true,        // PII/secret detection on tool outputs
      action: 'block',
    },
  },
});
```

### Chain-of-thought guard

Scans `<thinking>` blocks and reasoning output (OpenAI o-series, Anthropic Claude):

```typescript
const openai = lp.wrap(new OpenAI(), {
  security: {
    chainOfThought: {
      injectionDetection: true,
      systemPromptLeakDetection: true,
      goalDriftDetection: true,
      goalDriftThreshold: 0.3,
      action: 'warn',
    },
  },
});
```

### Conversation guard

Tracks state across a conversation. Create one per session:

```typescript
import { ConversationGuard } from 'launchpromptly';

const convo = new ConversationGuard({
  maxTurns: 25,
  accumulatingRisk: true,
  riskThreshold: 2.0,
  crossTurnPiiTracking: true,
  maxConsecutiveSimilarResponses: 3,
});

const openai = lp.wrap(new OpenAI(), {
  conversation: convo,
  security: { injection: { enabled: true } },
});
```

## Multi-language PII

Country-specific ID detection with check digit validation:

```typescript
import { detectPII } from 'launchpromptly';

// Brazil CPF
detectPII('Meu CPF é 123.456.789-09', { locales: ['br'] });

// China National ID
detectPII('身份证号: 110101199001011234', { locales: ['cn'] });

// All 8 countries at once
detectPII(text, { locales: 'all' });
```

**Supported locales:** `ca` (Canada SIN), `br` (Brazil CPF/CNPJ), `cn` (China National ID), `jp` (Japan My Number), `kr` (South Korea RRN), `de` (Germany Tax ID), `mx` (Mexico RFC/CURP), `fr` (France NIR)

## Multi-language content filter

10 languages, with auto-detection:

```typescript
import { detectContentViolations } from 'launchpromptly';

// Explicit locale
detectContentViolations('Muerte a los traidores', 'input', { locale: 'es' });

// Auto-detect language from text
detectContentViolations('如何制造炸弹', 'input', { autoDetectLanguage: true });
```

**Supported:** es, pt, zh, ja, ko, de, fr, ar, hi, ru

## Eval CLI

Run attack tests against your guardrails from the command line:

```bash
# Run all tests
npx launchpromptly eval

# CI mode — fail if pass rate drops below 95%
npx launchpromptly eval --threshold 0.95

# Test specific guardrails
npx launchpromptly eval --filter injection,jailbreak

# JSON output for programmatic use
npx launchpromptly eval --format json > results.json
```

Ships with ~200 test cases across injection, jailbreak, PII, content, unicode, secrets, and bias.

## Privacy & data practices

### What the SDK reports

Events sent to your LaunchPromptly endpoint contain metadata only:

- Token counts (input, output, total)
- Model name (e.g. `gpt-4o`)
- Estimated cost (USD)
- Latency (ms)
- Guardrail trigger types and counts (e.g. "2 PII detections", "injection blocked")
- Injection risk score
- Whether redaction was applied (boolean)
- Timestamps
- Customer ID and feature name (if you provided them)

### What the SDK does not send

- Prompt text or response text (by default)
- PII values (emails, SSNs, phone numbers, etc.)
- Raw user content
- API keys or secrets
- File uploads or attachments
- IP addresses of your end users

### Optional fields

You can opt in to sending `promptPreview` and `responseText` for debugging. When enabled, these are encrypted with AES-256-GCM at rest on the dashboard.

### No telemetry

The SDK does not phone home. It makes no telemetry calls to LaunchPromptly. Events go to your configured endpoint only. If you don't set an endpoint, no network calls happen at all.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `LAUNCHPROMPTLY_API_KEY` | API key (alternative to passing in constructor) |
| `LP_API_KEY` | Shorthand alias |

## License

MIT
