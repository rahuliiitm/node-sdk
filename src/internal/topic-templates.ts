/**
 * Pre-built topic definitions for common use cases.
 * Use these with the topic guard to block or allow specific content categories.
 * @module
 */

import type { TopicDefinition } from './topic-guard';

/**
 * Detects when LLM output recommends or endorses competitor products.
 * Add your competitors' names to the keywords list.
 *
 * Usage:
 * ```ts
 * const lp = new LaunchPromptly({
 *   security: {
 *     topicGuard: {
 *       blockedTopics: [COMPETITOR_ENDORSEMENT({
 *         competitors: ['CompetitorA', 'CompetitorB'],
 *       })],
 *     },
 *   },
 * });
 * ```
 */
export function COMPETITOR_ENDORSEMENT(opts: { competitors: string[]; threshold?: number }): TopicDefinition {
  const keywords = [
    // Intent keywords — paired with competitor names in text matching
    'recommend', 'switch to', 'try using', 'better alternative',
    'you should use', 'consider using', 'migrate to', 'upgrade to',
    ...opts.competitors.map(c => c.toLowerCase()),
  ];
  return {
    name: 'competitor_endorsement',
    keywords,
    threshold: opts.threshold ?? 0.03,
  };
}

/**
 * Detects when LLM output takes political stances or promotes political content.
 */
export const POLITICAL_BIAS: TopicDefinition = {
  name: 'political_bias',
  keywords: [
    'vote for', 'vote against', 'liberal agenda', 'conservative agenda',
    'left-wing', 'right-wing', 'democrat', 'republican',
    'socialism is', 'capitalism is', 'communism is',
    'political party', 'election fraud', 'stolen election',
    'gun control', 'second amendment', 'pro-choice', 'pro-life',
    'immigration policy', 'border wall', 'defund the police',
    'climate hoax', 'green new deal', 'woke',
  ],
  threshold: 0.04,
};

/**
 * Detects unauthorized medical advice in LLM output.
 */
export const MEDICAL_ADVICE: TopicDefinition = {
  name: 'medical_advice',
  keywords: [
    'take this medication', 'stop taking your', 'increase your dosage',
    'you have', 'diagnosis is', 'you are suffering from',
    'prescribe', 'prescription', 'my medical opinion',
    'this will cure', 'guaranteed to heal',
    'self-medicate', 'skip your doctor',
    'no need to see a doctor', 'don\'t need medical attention',
  ],
  threshold: 0.03,
};

/**
 * Detects unauthorized legal advice in LLM output.
 */
export const LEGAL_ADVICE: TopicDefinition = {
  name: 'legal_advice',
  keywords: [
    'you should sue', 'file a lawsuit', 'legal action',
    'my legal opinion', 'legally you must', 'legally you should',
    'plead guilty', 'plead not guilty', 'settle out of court',
    'skip the lawyer', 'no need for a lawyer',
    'this is legal advice', 'in my legal capacity',
  ],
  threshold: 0.03,
};

/**
 * Detects unauthorized financial advice in LLM output.
 */
export const FINANCIAL_ADVICE: TopicDefinition = {
  name: 'financial_advice',
  keywords: [
    'you should invest', 'buy this stock', 'sell your shares',
    'guaranteed returns', 'risk-free investment', 'can\'t lose money',
    'financial advice', 'my investment recommendation',
    'put all your money', 'this stock will', 'crypto will',
    'insider tip', 'hot stock tip', 'get rich',
  ],
  threshold: 0.03,
};
