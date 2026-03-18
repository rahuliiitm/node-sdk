/**
 * Context Engine — System prompt analysis and constraint extraction.
 * Parses a system prompt once, extracts structured constraints (topics, role,
 * forbidden actions, output format, knowledge boundaries), and caches the result.
 * @internal
 */

import { createHash } from 'crypto';

// ── Types ────────────────────────────────────────────────────────────────────

export type ConstraintType =
  | 'topic_boundary'
  | 'role_constraint'
  | 'action_restriction'
  | 'output_format'
  | 'knowledge_boundary'
  | 'persona_rule'
  | 'negative_instruction';

export interface Constraint {
  type: ConstraintType;
  description: string;
  keywords: string[];
  source: string;
  confidence: number;
}

export type GroundingMode = 'any' | 'documents_only' | 'system_only';

export interface ContextProfile {
  role: string | null;
  entity: string | null;
  allowedTopics: string[];
  restrictedTopics: string[];
  forbiddenActions: string[];
  outputFormat: string | null;
  groundingMode: GroundingMode;
  constraints: Constraint[];
  rawSystemPrompt: string;
  promptHash: string;
}

export interface ContextEngineOptions {
  /** Override automatic caching. Default: true. */
  cache?: boolean;
}

/** Provider interface for pluggable context extractors (e.g., ML-based). */
export interface ContextExtractorProvider {
  extract(systemPrompt: string): ContextProfile | Promise<ContextProfile>;
  readonly name: string;
}

/** User-facing security options for the context engine. */
export interface ContextEngineSecurityOptions {
  enabled?: boolean;
  /** Override system prompt — if omitted, auto-extracted from messages. */
  systemPrompt?: string;
  /** Pluggable ML extraction providers. */
  providers?: ContextExtractorProvider[];
  /** Cache extracted profiles by prompt hash. Default: true. */
  cacheProfiles?: boolean;
  /** Feed extracted context into injection detection for enhanced accuracy. Default: true. */
  enhanceInjection?: boolean;
}

// ── Cache ────────────────────────────────────────────────────────────────────

const profileCache = new Map<string, ContextProfile>();

/** Clear the internal profile cache. Useful for testing. */
export function clearContextCache(): void {
  profileCache.clear();
}

// ── Sentence Splitting ──────────────────────────────────────────────────────

const SENTENCE_SPLIT_RE = /(?<=[.!?\n])\s+/;

function splitSentences(text: string): string[] {
  return text
    .split(SENTENCE_SPLIT_RE)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// ── Keyword Extraction ──────────────────────────────────────────────────────

const STOP_WORDS = new Set([
  'a', 'an', 'the', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
  'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
  'should', 'may', 'might', 'must', 'shall', 'can', 'need', 'dare',
  'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by', 'from', 'as',
  'into', 'through', 'during', 'before', 'after', 'above', 'below',
  'between', 'out', 'off', 'over', 'under', 'again', 'further', 'then',
  'and', 'but', 'or', 'nor', 'not', 'so', 'yet', 'both', 'either',
  'neither', 'each', 'every', 'all', 'any', 'few', 'more', 'most',
  'other', 'some', 'such', 'no', 'only', 'own', 'same', 'than', 'too',
  'very', 'just', 'because', 'if', 'when', 'while', 'where', 'how',
  'what', 'which', 'who', 'whom', 'this', 'that', 'these', 'those',
  'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves',
  'you', 'your', 'yours', 'yourself', 'yourselves',
  'he', 'him', 'his', 'she', 'her', 'hers', 'it', 'its',
  'they', 'them', 'their', 'theirs', 'themselves',
  'about', 'up', 'also', 'well', 'back', 'even', 'still',
  'never', 'always', 'ever', 'already', 'now',
]);

const TOKEN_SPLIT_RE = /[\s,.!?;:()\[\]{}"']+/;

function extractKeywords(text: string): string[] {
  return text
    .toLowerCase()
    .split(TOKEN_SPLIT_RE)
    .filter((t) => t.length > 2 && !STOP_WORDS.has(t));
}

// ── Extraction Patterns ─────────────────────────────────────────────────────

// Role patterns: "You are a/an [ROLE]", "Act as [ROLE]", "You are [COMPANY]'s [ROLE]"
const ROLE_PATTERNS: RegExp[] = [
  /you\s+are\s+(?:a|an)\s+([^.,:;!?\n]{3,60})/i,
  /act\s+as\s+(?:a|an)?\s*([^.,:;!?\n]{3,60})/i,
  /your\s+role\s+is\s+(?:to\s+)?([^.,:;!?\n]{3,60})/i,
  /behave\s+as\s+(?:a|an)?\s*([^.,:;!?\n]{3,60})/i,
  /you\s+(?:will\s+)?serve\s+as\s+(?:a|an)?\s*([^.,:;!?\n]{3,60})/i,
];

// Entity patterns: "You are [COMPANY]'s assistant", "You work for [COMPANY]"
const ENTITY_PATTERNS: RegExp[] = [
  /you\s+are\s+([A-Z][A-Za-z0-9\s&'-]{1,40}?)(?:'s|'s)\s+/i,
  /you\s+work\s+for\s+([A-Z][A-Za-z0-9\s&'-]{1,40})/i,
  /you\s+represent\s+([A-Z][A-Za-z0-9\s&'-]{1,40})/i,
  /(?:built|created|developed|made)\s+by\s+([A-Z][A-Za-z0-9\s&'-]{1,40})/i,
];

// Allowed topic patterns: "Only discuss [TOPIC]", "Only answer questions about [TOPIC]"
const ALLOWED_TOPIC_PATTERNS: RegExp[] = [
  /only\s+(?:discuss|talk\s+about|answer\s+(?:questions?\s+)?(?:about|regarding|related\s+to))\s+([^.,:;!?\n]{3,80})/i,
  /(?:limit|restrict|confine)\s+(?:yourself|your\s+(?:responses?|answers?|discussions?))\s+to\s+([^.,:;!?\n]{3,80})/i,
  /you\s+(?:should\s+)?only\s+(?:respond|help)\s+(?:about|with|regarding)\s+([^.,:;!?\n]{3,80})/i,
  /your\s+(?:scope|domain|area)\s+is\s+(?:limited\s+to\s+)?([^.,:;!?\n]{3,80})/i,
  /focus\s+(?:exclusively\s+)?on\s+([^.,:;!?\n]{3,80})/i,
];

// Restricted topic patterns: "Never discuss [TOPIC]", "Do not provide advice on [TOPIC]"
const RESTRICTED_TOPIC_PATTERNS: RegExp[] = [
  /(?:never|don'?t|do\s+not|avoid)\s+(?:discuss|talk\s+about|mention|bring\s+up|address)\s+([^.,:;!?\n]{3,80})/i,
  /(?:do\s+not|don'?t|never)\s+provide\s+(?:(?:\w+\s+)?(?:advice|guidance|recommendations?|information))\s+(?:on|about|regarding|related\s+to)\s+([^.,:;!?\n]{3,80})/i,
  /(?:never|don'?t|do\s+not)\s+provide\s+([^.,:;!?\n]*?(?:advice|guidance|recommendations?|information)[^.,:;!?\n]{0,40})/i,
  /(?:stay\s+away|steer\s+clear)\s+(?:from|of)\s+(?:topics?\s+(?:like|such\s+as|including)\s+)?([^.,:;!?\n]{3,80})/i,
  /(?:off[- ]limits?|forbidden|prohibited)\s*(?:topics?)?\s*(?:include|are)?\s*:?\s*([^.!?\n]{3,80})/i,
];

// Forbidden action patterns: "Never [ACTION]", "Do not [ACTION]", "Under no circumstances [ACTION]"
const FORBIDDEN_ACTION_PATTERNS: RegExp[] = [
  /(?:never|don'?t|do\s+not)\s+([^.,:;!?\n]{3,80})/i,
  /under\s+no\s+circumstances?\s+(?:should\s+you\s+)?([^.,:;!?\n]{3,80})/i,
  /you\s+(?:must|should)\s+(?:not|never)\s+([^.,:;!?\n]{3,80})/i,
  /(?:refrain|abstain)\s+from\s+([^.,:;!?\n]{3,80})/i,
  /it\s+is\s+(?:strictly\s+)?(?:forbidden|prohibited)\s+(?:to|for\s+you\s+to)\s+([^.,:;!?\n]{3,80})/i,
];

// Output format patterns: "Always respond in [FORMAT]", "Format responses as [FORMAT]"
const OUTPUT_FORMAT_PATTERNS: RegExp[] = [
  /(?:always\s+)?respond\s+(?:in|using|with)\s+(JSON|json|XML|xml|markdown|Markdown|YAML|yaml|HTML|html|plain\s+text|csv|CSV)/i,
  /(?:format|structure)\s+(?:your\s+)?(?:responses?|answers?|output)\s+(?:as|in|using)\s+(JSON|json|XML|xml|markdown|Markdown|YAML|yaml|HTML|html|plain\s+text|csv|CSV)/i,
  /(?:output|return|give)\s+(?:only\s+)?(?:valid\s+)?(JSON|json|XML|xml|YAML|yaml)/i,
  /responses?\s+(?:should|must)\s+be\s+(?:in\s+)?(JSON|json|XML|xml|markdown|Markdown|YAML|yaml|HTML|html|plain\s+text|csv|CSV)/i,
];

// Knowledge boundary patterns: "Only answer from provided documents"
const KNOWLEDGE_BOUNDARY_PATTERNS: RegExp[] = [
  /only\s+(?:answer|respond|use\s+information)\s+(?:from|based\s+on)\s+(?:the\s+)?(?:provided|given|supplied|attached)\s+(?:documents?|context|data|sources?|information)/i,
  /(?:do\s+not|don'?t|never)\s+(?:use|rely\s+on|include)\s+(?:external|outside|your\s+own)\s+(?:knowledge|information|data|sources?)/i,
  /(?:ground|base)\s+(?:your\s+)?(?:responses?|answers?)\s+(?:only\s+)?(?:on|in)\s+(?:the\s+)?(?:provided|given|supplied)\s+(?:context|documents?|data|information)/i,
  /(?:stick|adhere)\s+(?:strictly\s+)?to\s+(?:the\s+)?(?:provided|given|supplied)\s+(?:context|documents?|data|information)/i,
  /(?:ground|base)\s+(?:your\s+)?(?:responses?|answers?)\s+(?:only\s+)?(?:on|in)\s+(?:the\s+)?(?:system\s+)?(?:context|information)\s+provided/i,
];

// Persona rule patterns: "Be [TONE]", "Maintain a [PERSONA] demeanor"
const PERSONA_PATTERNS: RegExp[] = [
  /(?:be|stay|remain)\s+(professional|friendly|polite|formal|casual|concise|brief|helpful|empathetic|neutral|objective|respectful|warm|enthusiastic)/i,
  /maintain\s+(?:a\s+)?(professional|friendly|polite|formal|casual|concise|brief|helpful|empathetic|neutral|objective|respectful|warm|enthusiastic)\s+(?:tone|demeanor|manner|attitude|style)/i,
  /(?:use|adopt|keep)\s+(?:a\s+)?(professional|friendly|polite|formal|casual|concise|brief|helpful|empathetic|neutral|objective|respectful|warm|enthusiastic)\s+(?:tone|voice|style)/i,
  /your\s+tone\s+(?:should|must)\s+be\s+(professional|friendly|polite|formal|casual|concise|brief|helpful|empathetic|neutral|objective|respectful|warm|enthusiastic)/i,
];

// ── Compound Constraint Splitting ──────────────────────────────────────────

/**
 * Split compound constraints like "politics, religion, or adult content"
 * into individual items: ["politics", "religion", "adult content"].
 */
function splitCompoundItems(text: string): string[] {
  // Normalize compound delimiters to pipe separator (order matters)
  const normalized = text
    .replace(/,\s+(?:and|or)\s+/gi, '|')    // "X, and Y" → "X|Y"
    .replace(/;\s+(?:and|or)\s+/gi, '|')    // "X; and Y" → "X|Y"
    .replace(/;\s+/g, '|')                   // "X; Y" → "X|Y"
    .replace(/,\s+/g, '|')                   // "X, Y" → "X|Y"
    .replace(/\s+(?:and|or)\s+/gi, '|');     // "X and Y" → "X|Y"

  return normalized
    .split('|')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Check if text contains list delimiters indicating multiple items.
 */
function isCompoundText(text: string): boolean {
  return /,\s+|\s+(?:and|or)\s+|;\s+/i.test(text);
}

// ── Extraction Functions ────────────────────────────────────────────────────

function extractRole(sentences: string[]): string | null {
  for (const sentence of sentences) {
    for (const pattern of ROLE_PATTERNS) {
      const match = pattern.exec(sentence);
      if (match && match[1]) {
        return match[1].trim().toLowerCase();
      }
    }
  }
  return null;
}

function extractEntity(text: string): string | null {
  for (const pattern of ENTITY_PATTERNS) {
    const match = pattern.exec(text);
    if (match && match[1]) {
      return match[1].trim();
    }
  }
  return null;
}

function extractAllowedTopics(sentences: string[]): { topics: string[]; constraints: Constraint[] } {
  const topics: string[] = [];
  const constraints: Constraint[] = [];

  for (const sentence of sentences) {
    for (const pattern of ALLOWED_TOPIC_PATTERNS) {
      const match = pattern.exec(sentence);
      if (match && match[1]) {
        const rawText = match[1].trim();
        const items = isCompoundText(rawText) ? splitCompoundItems(rawText) : [rawText.toLowerCase()];

        for (const item of items) {
          if (!topics.includes(item)) {
            topics.push(item);
          }
          constraints.push({
            type: 'topic_boundary',
            description: `Allowed topic: ${item}`,
            keywords: extractKeywords(item),
            source: sentence,
            confidence: 0.8,
          });
        }
      }
    }
  }

  return { topics, constraints };
}

function extractRestrictedTopics(sentences: string[]): { topics: string[]; constraints: Constraint[] } {
  const topics: string[] = [];
  const constraints: Constraint[] = [];

  for (const sentence of sentences) {
    for (const pattern of RESTRICTED_TOPIC_PATTERNS) {
      const match = pattern.exec(sentence);
      if (match && match[1]) {
        const rawText = match[1].trim();
        const items = isCompoundText(rawText) ? splitCompoundItems(rawText) : [rawText.toLowerCase()];

        for (const item of items) {
          if (!topics.includes(item)) {
            topics.push(item);
          }
          constraints.push({
            type: 'topic_boundary',
            description: `Restricted topic: ${item}`,
            keywords: extractKeywords(item),
            source: sentence,
            confidence: 0.8,
          });
        }
      }
    }
  }

  return { topics, constraints };
}

function extractForbiddenActions(sentences: string[]): { actions: string[]; constraints: Constraint[] } {
  const actions: string[] = [];
  const constraints: Constraint[] = [];

  // Filter sentences that actually contain negative instruction patterns
  // to avoid matching benign "don't worry" / "never mind" type patterns
  const negativePatterns = [
    /(?:never|don'?t|do\s+not|must\s+not|should\s+not|under\s+no\s+circumstances?|refrain|abstain|forbidden|prohibited)/i,
  ];

  for (const sentence of sentences) {
    // Only process sentences with clear negative instructions
    if (!negativePatterns.some((p) => p.test(sentence))) continue;

    for (const pattern of FORBIDDEN_ACTION_PATTERNS) {
      const match = pattern.exec(sentence);
      if (match && match[1]) {
        const rawText = match[1].trim();
        const items = isCompoundText(rawText) ? splitCompoundItems(rawText) : [rawText.toLowerCase()];

        for (const item of items) {
          // Filter out very short/generic matches
          if (item.length < 5) continue;
          if (!actions.includes(item)) {
            actions.push(item);
          }
          constraints.push({
            type: 'action_restriction',
            description: `Forbidden: ${item}`,
            keywords: extractKeywords(item),
            source: sentence,
            confidence: 0.75,
          });
        }
      }
    }
  }

  return { actions, constraints };
}

function extractOutputFormat(sentences: string[]): { format: string | null; constraints: Constraint[] } {
  const constraints: Constraint[] = [];

  for (const sentence of sentences) {
    for (const pattern of OUTPUT_FORMAT_PATTERNS) {
      const match = pattern.exec(sentence);
      if (match && match[1]) {
        const format = match[1].trim().toUpperCase();
        constraints.push({
          type: 'output_format',
          description: `Output format: ${format}`,
          keywords: [format.toLowerCase()],
          source: sentence,
          confidence: 0.9,
        });
        return { format, constraints };
      }
    }
  }

  return { format: null, constraints };
}

function extractGroundingMode(sentences: string[]): { mode: GroundingMode; constraints: Constraint[] } {
  const constraints: Constraint[] = [];

  for (const sentence of sentences) {
    for (const pattern of KNOWLEDGE_BOUNDARY_PATTERNS) {
      if (pattern.test(sentence)) {
        const isDocOnly = /(?:provided|given|supplied|attached)\s+(?:documents?|context|sources?)/i.test(sentence);
        const mode: GroundingMode = isDocOnly ? 'documents_only' : 'system_only';
        constraints.push({
          type: 'knowledge_boundary',
          description: `Knowledge restricted to ${mode === 'documents_only' ? 'provided documents' : 'system context'}`,
          keywords: extractKeywords(sentence),
          source: sentence,
          confidence: 0.85,
        });
        return { mode, constraints };
      }
    }
  }

  return { mode: 'any', constraints };
}

function extractPersonaRules(sentences: string[]): Constraint[] {
  const constraints: Constraint[] = [];

  for (const sentence of sentences) {
    for (const pattern of PERSONA_PATTERNS) {
      const match = pattern.exec(sentence);
      if (match && match[1]) {
        const trait = match[1].trim().toLowerCase();
        constraints.push({
          type: 'persona_rule',
          description: `Persona: ${trait}`,
          keywords: [trait],
          source: sentence,
          confidence: 0.7,
        });
      }
    }
  }

  return constraints;
}

// ── Conflict Detection ────────────────────────────────────────────────────

export interface ConstraintConflict {
  constraintA: Constraint;
  constraintB: Constraint;
  conflictType: 'contradiction' | 'ambiguity' | 'redundancy';
  description: string;
}

const CONTRADICTORY_PERSONA_PAIRS: [string, string][] = [
  ['formal', 'casual'],
  ['professional', 'casual'],
  ['concise', 'detailed'],
  ['brief', 'detailed'],
  ['neutral', 'enthusiastic'],
  ['objective', 'empathetic'],
];

const EXPANSIVE_ROLE_INDICATORS = ['general', 'any', 'all', 'everything', 'anything', 'universal'];

/**
 * Detect logical conflicts between extracted constraints.
 *
 * Checks:
 * - Allowed topic keywords that overlap with restricted topic keywords (contradiction)
 * - Expansive role definitions alongside restrictive constraints (ambiguity)
 * - Contradictory persona traits (contradiction)
 */
export function detectConflicts(profile: ContextProfile): ConstraintConflict[] {
  const conflicts: ConstraintConflict[] = [];

  const allowedConstraints = profile.constraints.filter(
    (c) => c.type === 'topic_boundary' && c.description.startsWith('Allowed'),
  );
  const restrictedConstraints = profile.constraints.filter(
    (c) => c.type === 'topic_boundary' && c.description.startsWith('Restricted'),
  );
  const personaConstraints = profile.constraints.filter((c) => c.type === 'persona_rule');
  const roleConstraint = profile.constraints.find((c) => c.type === 'role_constraint');

  // 1. Allowed vs restricted topic keyword overlap
  for (const allowed of allowedConstraints) {
    for (const restricted of restrictedConstraints) {
      const overlap = allowed.keywords.filter((k) => restricted.keywords.includes(k));
      if (overlap.length > 0) {
        conflicts.push({
          constraintA: allowed,
          constraintB: restricted,
          conflictType: 'contradiction',
          description: `Allowed topic "${allowed.description}" overlaps with restricted topic "${restricted.description}" on keywords: ${overlap.join(', ')}`,
        });
      }
    }
  }

  // 2. Expansive role vs restrictive constraints
  if (roleConstraint && (restrictedConstraints.length > 0 || profile.forbiddenActions.length > 0)) {
    const roleText = roleConstraint.description.toLowerCase();
    const isExpansive = EXPANSIVE_ROLE_INDICATORS.some((ind) => roleText.includes(ind));
    if (isExpansive) {
      const restrictive = restrictedConstraints[0] || profile.constraints.find((c) => c.type === 'action_restriction');
      if (restrictive) {
        conflicts.push({
          constraintA: roleConstraint,
          constraintB: restrictive,
          conflictType: 'ambiguity',
          description: `Expansive role "${roleConstraint.description}" may conflict with restrictive constraint "${restrictive.description}"`,
        });
      }
    }
  }

  // 3. Contradictory persona traits
  for (let i = 0; i < personaConstraints.length; i++) {
    for (let j = i + 1; j < personaConstraints.length; j++) {
      const traitA = personaConstraints[i].keywords[0]?.toLowerCase();
      const traitB = personaConstraints[j].keywords[0]?.toLowerCase();
      if (!traitA || !traitB) continue;

      const isContradictory = CONTRADICTORY_PERSONA_PAIRS.some(
        ([a, b]) => (traitA === a && traitB === b) || (traitA === b && traitB === a),
      );
      if (isContradictory) {
        conflicts.push({
          constraintA: personaConstraints[i],
          constraintB: personaConstraints[j],
          conflictType: 'contradiction',
          description: `Persona trait "${traitA}" contradicts "${traitB}"`,
        });
      }
    }
  }

  return conflicts;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Extract a structured context profile from a system prompt.
 *
 * Parses the prompt into sentences and applies regex-based extraction for:
 * - Role identification (e.g., "You are a customer support agent")
 * - Entity/company detection (e.g., "You work for Acme Corp")
 * - Allowed/restricted topics
 * - Forbidden actions
 * - Output format requirements
 * - Knowledge boundaries (grounding mode)
 * - Persona rules
 *
 * Results are cached by prompt hash — extraction runs once per unique prompt.
 */
export function extractContext(systemPrompt: string, options?: ContextEngineOptions): ContextProfile {
  if (!systemPrompt || systemPrompt.trim().length === 0) {
    return {
      role: null,
      entity: null,
      allowedTopics: [],
      restrictedTopics: [],
      forbiddenActions: [],
      outputFormat: null,
      groundingMode: 'any',
      constraints: [],
      rawSystemPrompt: systemPrompt || '',
      promptHash: '',
    };
  }

  const promptHash = createHash('sha256').update(systemPrompt).digest('hex');
  const useCache = options?.cache !== false;

  if (useCache) {
    const cached = profileCache.get(promptHash);
    if (cached) return cached;
  }

  const sentences = splitSentences(systemPrompt);
  const allConstraints: Constraint[] = [];

  // Extract role
  const role = extractRole(sentences);
  if (role) {
    allConstraints.push({
      type: 'role_constraint',
      description: `Role: ${role}`,
      keywords: extractKeywords(role),
      source: sentences.find((s) => ROLE_PATTERNS.some((p) => p.test(s))) || '',
      confidence: 0.85,
    });
  }

  // Extract entity
  const entity = extractEntity(systemPrompt);

  // Extract allowed topics
  const allowed = extractAllowedTopics(sentences);
  allConstraints.push(...allowed.constraints);

  // Extract restricted topics
  const restricted = extractRestrictedTopics(sentences);
  allConstraints.push(...restricted.constraints);

  // Extract forbidden actions
  const forbidden = extractForbiddenActions(sentences);
  allConstraints.push(...forbidden.constraints);

  // Extract output format
  const format = extractOutputFormat(sentences);
  allConstraints.push(...format.constraints);

  // Extract grounding mode
  const grounding = extractGroundingMode(sentences);
  allConstraints.push(...grounding.constraints);

  // Extract persona rules
  const personaConstraints = extractPersonaRules(sentences);
  allConstraints.push(...personaConstraints);

  const profile: ContextProfile = {
    role,
    entity,
    allowedTopics: allowed.topics,
    restrictedTopics: restricted.topics,
    forbiddenActions: forbidden.actions,
    outputFormat: format.format,
    groundingMode: grounding.mode,
    constraints: allConstraints,
    rawSystemPrompt: systemPrompt,
    promptHash,
  };

  if (useCache) {
    profileCache.set(promptHash, profile);
  }

  return profile;
}

/**
 * Extract context using regex baseline + optional ML providers.
 *
 * Runs sync `extractContext()` for the regex baseline, then calls each
 * provider's `extract()` in parallel. Results are merged: regex findings
 * are preferred for explicitly matched patterns, ML findings fill gaps.
 */
export async function extractContextWithProviders(
  systemPrompt: string,
  providers: ContextExtractorProvider[],
  options?: ContextEngineOptions,
): Promise<ContextProfile> {
  const regexProfile = extractContext(systemPrompt, options);
  if (!providers.length) return regexProfile;

  const mlProfiles = await Promise.all(
    providers.map((p) => Promise.resolve(p.extract(systemPrompt))),
  );

  return mergeProfiles(regexProfile, mlProfiles);
}

/**
 * Merge regex profile with ML provider profiles.
 *
 * Strategy:
 * - Role/entity/outputFormat/groundingMode: prefer regex (explicit match), ML fallback
 * - Topics/actions: union (deduplicated)
 * - Constraints: merge all, dedup by source+type, keep higher confidence
 */
function mergeProfiles(
  regexProfile: ContextProfile,
  mlProfiles: ContextProfile[],
): ContextProfile {
  const merged = { ...regexProfile };

  for (const ml of mlProfiles) {
    // Scalars: regex wins if present, otherwise take ML
    if (!merged.role && ml.role) merged.role = ml.role;
    if (!merged.entity && ml.entity) merged.entity = ml.entity;
    if (!merged.outputFormat && ml.outputFormat) merged.outputFormat = ml.outputFormat;
    if (merged.groundingMode === 'any' && ml.groundingMode !== 'any') {
      merged.groundingMode = ml.groundingMode;
    }

    // Topics: union with deduplication
    for (const topic of ml.allowedTopics) {
      if (!merged.allowedTopics.includes(topic)) {
        merged.allowedTopics.push(topic);
      }
    }
    for (const topic of ml.restrictedTopics) {
      if (!merged.restrictedTopics.includes(topic)) {
        merged.restrictedTopics.push(topic);
      }
    }

    // Forbidden actions: union
    for (const action of ml.forbiddenActions) {
      if (!merged.forbiddenActions.includes(action)) {
        merged.forbiddenActions.push(action);
      }
    }

    // Constraints: merge by source+type, keep higher confidence
    for (const mlConstraint of ml.constraints) {
      const existing = merged.constraints.find(
        (c) => c.type === mlConstraint.type && c.source === mlConstraint.source,
      );
      if (existing) {
        if (mlConstraint.confidence > existing.confidence) {
          existing.confidence = mlConstraint.confidence;
          existing.description = mlConstraint.description;
          existing.keywords = mlConstraint.keywords;
        }
      } else {
        merged.constraints.push(mlConstraint);
      }
    }
  }

  return merged;
}
