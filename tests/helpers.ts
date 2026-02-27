// helpers.ts — HTTP utility and test setup/teardown for SDK integration tests

const API_BASE = process.env.API_URL ?? 'http://localhost:3001';

export async function apiCall<T>(
  path: string,
  options: RequestInit = {},
  token?: string,
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers as Record<string, string> ?? {}),
  };

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API ${options.method ?? 'GET'} ${path} → ${res.status}: ${body}`);
  }

  if (res.status === 204 || res.headers.get('content-length') === '0') {
    return undefined as T;
  }
  return res.json() as Promise<T>;
}

export interface TestContext {
  jwt: string;
  userId: string;
  projectId: string;
  promptId: string;
  promptSlug: string;
  versionId: string;
  environmentId: string;
  sdkApiKey: string; // raw key (lp_live_...)
  apiKeyId: string;
}

/**
 * Bootstraps a fresh user, project, prompt, version, deployment, and SDK API key.
 * Returns everything the test runner needs.
 */
export async function setup(): Promise<TestContext> {
  const email = 'rahul.iiitm06@gmail.com';
  const password = '12345678';

  // 1. Login (use existing account)
  const auth = await apiCall<{
    accessToken: string;
    userId: string;
    plan: string;
  }>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });

  const jwt = auth.accessToken;

  // 2. Get profile → projectId
  const me = await apiCall<{
    id: string;
    email: string;
    projectId: string;
  }>('/auth/me', {}, jwt);

  const projectId = me.projectId;

  // 3. Get environments (created automatically with project)
  const envs = await apiCall<{ id: string; slug: string; sdkKeyPrefix?: string }[]>(
    `/environment/${projectId}`,
    {},
    jwt,
  );
  const env = envs[0]!;

  // 4. Create a managed prompt with template content (unique slug per run)
  const suffix = Date.now().toString(36).slice(-4);
  const promptSlug = `sdk-test-prompt-${suffix}`;
  const prompt = await apiCall<{
    id: string;
    slug: string;
    versions: { id: string; version: number }[];
  }>(`/prompt/${projectId}`, {
    method: 'POST',
    body: JSON.stringify({
      slug: promptSlug,
      name: `SDK Test Prompt (${suffix})`,
      description: 'Integration test prompt with template variables',
      initialContent: 'Hello {{name}}, you are a {{role}}. Welcome to {{company}}!',
    }),
  }, jwt);

  const versionId = prompt.versions[0]!.id;

  // 5. Deploy version to the environment
  await apiCall(
    `/prompt/${projectId}/${prompt.id}/versions/${versionId}/deploy-to/${env.id}`,
    { method: 'POST' },
    jwt,
  );

  // 6. Generate an SDK API key (linked to environment for usage tracking)
  const keyRes = await apiCall<{
    rawKey: string;
    apiKey: { id: string };
  }>(`/project/${projectId}/api-keys`, {
    method: 'POST',
    body: JSON.stringify({ name: 'SDK Integration Test Key', environmentId: env.id }),
  }, jwt);

  return {
    jwt,
    userId: me.id,
    projectId,
    promptId: prompt.id,
    promptSlug,
    versionId,
    environmentId: env.id,
    sdkApiKey: keyRes.rawKey,
    apiKeyId: keyRes.apiKey.id,
  };
}

/**
 * Cleans up test data.
 */
export async function teardown(ctx: TestContext): Promise<void> {
  try {
    // Delete prompt (cascades versions + deployments)
    await apiCall(`/prompt/${ctx.projectId}/${ctx.promptId}`, {
      method: 'DELETE',
    }, ctx.jwt);
  } catch {
    // Best effort
  }

  try {
    // Revoke API key
    await apiCall(`/project/${ctx.projectId}/api-keys/${ctx.apiKeyId}`, {
      method: 'DELETE',
    }, ctx.jwt);
  } catch {
    // Best effort
  }
}
