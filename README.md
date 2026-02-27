# launchpromptly

Official Node.js SDK for [LaunchPromptly](https://launchpromptly.dev) — manage, version, and deploy AI prompts without redeploying your app.

## Install

```bash
npm install launchpromptly
```

## Quick Start

```typescript
import { LaunchPromptly } from 'launchpromptly';

const lp = new LaunchPromptly({ apiKey: 'lp_live_...' });

// Fetch a managed prompt (cached, with stale-while-error fallback)
const systemPrompt = await lp.prompt('onboarding-assistant', {
  variables: { userName: 'Alice' },
});

// Use with any LLM provider
const response = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: 'How do I reset my password?' },
  ],
});
```

## Features

- **Prompt fetching** — `lp.prompt(slug, options)` fetches the active deployed version
- **Template variables** — `{{variable}}` placeholders are interpolated at runtime
- **Caching** — prompts are cached in-memory with configurable TTL (default 60s)
- **Stale-while-error** — returns expired cache on network failure (404s always throw)
- **Auto-tracking** — wrap your OpenAI client to automatically track cost, latency, and tokens
- **Event batching** — LLM events are batched and sent asynchronously

## API

### `new LaunchPromptly(options?)`

| Option | Default | Description |
|--------|---------|-------------|
| `apiKey` | `LAUNCHPROMPTLY_API_KEY` env | Your LaunchPromptly API key |
| `endpoint` | `https://api.launchpromptly.dev` | API base URL |
| `promptCacheTtl` | `60000` | Prompt cache TTL in ms |
| `flushAt` | `10` | Batch size threshold for auto-flush |
| `flushInterval` | `5000` | Timer interval for auto-flush (ms) |

### `lp.prompt(slug, options?)`

Fetch a managed prompt by slug. Returns the interpolated content string.

```typescript
const content = await lp.prompt('my-prompt', {
  variables: { name: 'Alice', role: 'admin' },
  customerId: 'user-42', // for A/B testing
});
```

### `lp.wrap(client, options?)`

Wrap an OpenAI client to automatically capture LLM events.

```typescript
const wrapped = lp.wrap(openai, {
  feature: 'chat',
  customer: () => ({ id: 'user-42' }),
  traceId: 'req-abc-123',
  spanName: 'generate',
});
```

### `lp.flush()`

Manually flush pending events.

### `lp.destroy()`

Clean up timers and resources.

## Template Variables

Prompts support `{{variable}}` placeholders:

```typescript
// If prompt content is: "Hello {{name}}, your role is {{role}}"
const content = await lp.prompt('greeting', {
  variables: { name: 'Alice', role: 'admin' },
});
// → "Hello Alice, your role is admin"
```

Unmatched variables are left as-is.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `LAUNCHPROMPTLY_API_KEY` | API key (alternative to passing in constructor) |
| `LP_API_KEY` | Shorthand alias |

## License

MIT
