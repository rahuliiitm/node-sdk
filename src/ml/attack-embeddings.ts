/**
 * Attack pattern embedding index — cosine similarity search against
 * a curated corpus of ~180 known attack patterns.
 *
 * Patterns are loaded from `data/attack-patterns.json` and embedded
 * once on first use via the shared MLEmbeddingProvider.
 *
 * Usage:
 *   const index = await loadAttackIndex(embeddingProvider);
 *   const matches = matchAgainstIndex(inputEmbedding, index, 0.75);
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import type { MLEmbeddingProvider } from './embedding-provider';

// ── Types ──────────────────────────────────────────────────────────────────

export type AttackCategory =
  | 'injection'
  | 'jailbreak'
  | 'data_extraction'
  | 'manipulation'
  | 'role_escape'
  | 'social_engineering';

export interface AttackMatch {
  category: AttackCategory;
  pattern: string;
  similarity: number;
}

export interface AttackCategoryData {
  patterns: string[];
  embeddings: Float32Array[];
}

export interface AttackEmbeddingIndex {
  version: string;
  model: string;
  dimension: number;
  categories: Record<AttackCategory, AttackCategoryData>;
}

// ── Singleton cache ────────────────────────────────────────────────────────

let _cachedIndex: AttackEmbeddingIndex | null = null;

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Load (or return cached) the attack pattern embedding index.
 * Embeds all patterns on first call using the provided embedding provider.
 */
export async function loadAttackIndex(
  provider: MLEmbeddingProvider,
): Promise<AttackEmbeddingIndex> {
  if (_cachedIndex) return _cachedIndex;

  // Load raw patterns
  const rawPath = join(__dirname, 'data', 'attack-patterns.json');
  const raw = JSON.parse(readFileSync(rawPath, 'utf-8')) as {
    version: string;
    model: string;
    categories: Record<string, string[]>;
  };

  const categories: Record<string, AttackCategoryData> = {};
  let dimension = 0;

  // Embed all patterns by category
  for (const [category, patterns] of Object.entries(raw.categories)) {
    const embeddings = await provider.embedBatch(patterns);
    if (embeddings.length > 0) {
      dimension = embeddings[0].length;
    }
    categories[category] = { patterns, embeddings };
  }

  _cachedIndex = {
    version: raw.version,
    model: raw.model,
    dimension,
    categories: categories as Record<AttackCategory, AttackCategoryData>,
  };

  return _cachedIndex;
}

/**
 * Find attack patterns most similar to the given embedding.
 * Returns matches above the threshold, sorted by similarity (descending).
 */
export function matchAgainstIndex(
  embedding: Float32Array,
  index: AttackEmbeddingIndex,
  threshold = 0.75,
): AttackMatch[] {
  const matches: AttackMatch[] = [];

  for (const [category, data] of Object.entries(index.categories)) {
    for (let i = 0; i < data.patterns.length; i++) {
      const sim = cosine(embedding, data.embeddings[i]);
      if (sim >= threshold) {
        matches.push({
          category: category as AttackCategory,
          pattern: data.patterns[i],
          similarity: sim,
        });
      }
    }
  }

  return matches.sort((a, b) => b.similarity - a.similarity);
}

/**
 * Quick check: does the input match any attack pattern above threshold?
 */
export function hasAttackMatch(
  embedding: Float32Array,
  index: AttackEmbeddingIndex,
  threshold = 0.75,
): boolean {
  for (const data of Object.values(index.categories)) {
    for (let i = 0; i < data.embeddings.length; i++) {
      if (cosine(embedding, data.embeddings[i]) >= threshold) {
        return true;
      }
    }
  }
  return false;
}

/** Reset cached index (for testing). */
export function _resetCache(): void {
  _cachedIndex = null;
}

// ── Helpers ────────────────────────────────────────────────────────────────

function cosine(a: Float32Array, b: Float32Array): number {
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom === 0 ? 0 : dot / denom;
}
