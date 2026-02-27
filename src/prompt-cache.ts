interface CacheEntry {
  content: string;
  managedPromptId: string;
  promptVersionId: string;
  version: number;
  expiresAt: number;
}

const DEFAULT_MAX_SIZE = 1000;

export class PromptCache {
  private cache = new Map<string, CacheEntry>();
  private readonly maxSize: number;

  constructor(maxSize: number = DEFAULT_MAX_SIZE) {
    this.maxSize = maxSize;
  }

  get(slug: string): CacheEntry | null {
    const entry = this.cache.get(slug);
    if (!entry) return null;
    if (Date.now() >= entry.expiresAt) return null;
    // LRU: move to end (most recently used)
    this.cache.delete(slug);
    this.cache.set(slug, entry);
    return entry;
  }

  /** Returns entry even if expired (for stale-while-error fallback) */
  getStale(slug: string): CacheEntry | null {
    return this.cache.get(slug) ?? null;
  }

  set(
    slug: string,
    data: { content: string; managedPromptId: string; promptVersionId: string; version: number },
    ttlMs: number,
  ): void {
    // If key already exists, delete first so it moves to end
    if (this.cache.has(slug)) {
      this.cache.delete(slug);
    }

    // Evict oldest entry if at capacity
    if (this.cache.size >= this.maxSize) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) {
        this.cache.delete(oldest);
      }
    }

    this.cache.set(slug, {
      ...data,
      expiresAt: Date.now() + ttlMs,
    });
  }

  invalidate(slug: string): void {
    this.cache.delete(slug);
  }

  invalidateAll(): void {
    this.cache.clear();
  }

  /** Current number of entries in the cache */
  get size(): number {
    return this.cache.size;
  }
}
