import { PromptCache } from './prompt-cache';

describe('PromptCache', () => {
  let cache: PromptCache;

  const sampleData = {
    content: 'You are helpful',
    managedPromptId: 'mp1',
    promptVersionId: 'pv1',
    version: 1,
  };

  beforeEach(() => {
    cache = new PromptCache();
  });

  it('set + get returns cached value', () => {
    cache.set('slug', sampleData, 60000);
    const result = cache.get('slug');
    expect(result).not.toBeNull();
    expect(result!.content).toBe('You are helpful');
    expect(result!.managedPromptId).toBe('mp1');
  });

  it('get returns null for missing key', () => {
    expect(cache.get('nonexistent')).toBeNull();
  });

  it('get returns null after TTL expires', () => {
    cache.set('slug', sampleData, 0); // expire immediately
    expect(cache.get('slug')).toBeNull();
  });

  it('set overwrites existing entry', () => {
    cache.set('slug', sampleData, 60000);
    cache.set('slug', { ...sampleData, content: 'Updated' }, 60000);
    expect(cache.get('slug')!.content).toBe('Updated');
  });

  it('invalidate removes specific key', () => {
    cache.set('a', sampleData, 60000);
    cache.set('b', sampleData, 60000);
    cache.invalidate('a');
    expect(cache.get('a')).toBeNull();
    expect(cache.get('b')).not.toBeNull();
  });

  it('invalidateAll clears everything', () => {
    cache.set('a', sampleData, 60000);
    cache.set('b', sampleData, 60000);
    cache.invalidateAll();
    expect(cache.get('a')).toBeNull();
    expect(cache.get('b')).toBeNull();
  });

  it('getStale returns expired entries', () => {
    cache.set('slug', sampleData, 0); // expire immediately
    expect(cache.get('slug')).toBeNull(); // normal get returns null
    const stale = cache.getStale('slug');
    expect(stale).not.toBeNull();
    expect(stale!.content).toBe('You are helpful');
  });

  it('size returns current entry count', () => {
    expect(cache.size).toBe(0);
    cache.set('a', sampleData, 60000);
    expect(cache.size).toBe(1);
    cache.set('b', sampleData, 60000);
    expect(cache.size).toBe(2);
    cache.invalidate('a');
    expect(cache.size).toBe(1);
  });

  describe('LRU eviction', () => {
    it('evicts oldest entry when at capacity', () => {
      const small = new PromptCache(3);
      small.set('a', { ...sampleData, content: 'A' }, 60000);
      small.set('b', { ...sampleData, content: 'B' }, 60000);
      small.set('c', { ...sampleData, content: 'C' }, 60000);

      // Cache full — adding 'd' evicts oldest 'a'
      small.set('d', { ...sampleData, content: 'D' }, 60000);
      expect(small.get('a')).toBeNull();
      expect(small.get('b')!.content).toBe('B');
      expect(small.get('d')!.content).toBe('D');
      expect(small.size).toBe(3);
    });

    it('get() refreshes LRU order', () => {
      const small = new PromptCache(3);
      small.set('a', { ...sampleData, content: 'A' }, 60000);
      small.set('b', { ...sampleData, content: 'B' }, 60000);
      small.set('c', { ...sampleData, content: 'C' }, 60000);

      // Access 'a' to make it most recently used
      small.get('a');

      // Adding 'd' now evicts 'b' (oldest non-accessed)
      small.set('d', { ...sampleData, content: 'D' }, 60000);
      expect(small.get('a')!.content).toBe('A'); // still alive
      expect(small.get('b')).toBeNull(); // evicted
    });

    it('overwriting existing key does not increase size', () => {
      const small = new PromptCache(3);
      small.set('a', sampleData, 60000);
      small.set('b', sampleData, 60000);
      small.set('a', { ...sampleData, content: 'Updated' }, 60000); // overwrite
      expect(small.size).toBe(2);
      expect(small.get('a')!.content).toBe('Updated');
    });
  });
});
