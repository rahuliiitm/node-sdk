/**
 * Pre-built compliance configurations for regulated industries.
 * Each template returns a partial SecurityOptions object that can be spread
 * into your LaunchPromptly config.
 * @module
 */

import type { TopicDefinition } from './topic-guard';
import { MEDICAL_ADVICE, LEGAL_ADVICE, FINANCIAL_ADVICE } from './topic-templates';

// ── Types ────────────────────────────────────────────────────────────────────

export interface ComplianceTemplate {
  name: string;
  description: string;
  pii: { enabled: true; blockOnDetection: true };
  contentFilter: { enabled: true; blockOnViolation: true; categories: string[] };
  topicGuard: { blockedTopics: TopicDefinition[] };
  secretDetection: { enabled: true };
  outputSafety: { enabled: true };
}

// ── Healthcare (HIPAA-aligned) ────────────────────────────────────────────────

export const HEALTHCARE_COMPLIANCE: ComplianceTemplate = {
  name: 'healthcare',
  description: 'HIPAA-aligned guardrails: blocks PII, medical advice, and sensitive content in LLM interactions.',
  pii: { enabled: true, blockOnDetection: true },
  contentFilter: {
    enabled: true,
    blockOnViolation: true,
    categories: ['hate_speech', 'sexual', 'violence', 'self_harm', 'bias'],
  },
  topicGuard: {
    blockedTopics: [
      MEDICAL_ADVICE,
      {
        name: 'phi_disclosure',
        keywords: [
          'patient name', 'medical record', 'health record',
          'diagnosis of', 'treatment plan for', 'prescription for',
          'insurance number', 'social security', 'date of birth',
          'medical history', 'lab results for',
        ],
        threshold: 0.03,
      },
    ],
  },
  secretDetection: { enabled: true },
  outputSafety: { enabled: true },
};

// ── Finance (SOX / financial regulation aligned) ─────────────────────────────

export const FINANCE_COMPLIANCE: ComplianceTemplate = {
  name: 'finance',
  description: 'Financial regulation guardrails: blocks PII, investment advice, and unauthorized financial guidance.',
  pii: { enabled: true, blockOnDetection: true },
  contentFilter: {
    enabled: true,
    blockOnViolation: true,
    categories: ['hate_speech', 'sexual', 'violence', 'self_harm', 'bias', 'illegal'],
  },
  topicGuard: {
    blockedTopics: [
      FINANCIAL_ADVICE,
      LEGAL_ADVICE,
      {
        name: 'insider_trading',
        keywords: [
          'insider information', 'insider trading', 'material non-public',
          'front-running', 'pump and dump', 'market manipulation',
          'wash trading', 'spoofing',
        ],
        threshold: 0.02,
      },
    ],
  },
  secretDetection: { enabled: true },
  outputSafety: { enabled: true },
};

// ── E-commerce (consumer protection aligned) ─────────────────────────────────

export const ECOMMERCE_COMPLIANCE: ComplianceTemplate = {
  name: 'ecommerce',
  description: 'Consumer protection guardrails: blocks PII, deceptive practices, and bias in product interactions.',
  pii: { enabled: true, blockOnDetection: true },
  contentFilter: {
    enabled: true,
    blockOnViolation: true,
    categories: ['hate_speech', 'sexual', 'violence', 'bias'],
  },
  topicGuard: {
    blockedTopics: [
      {
        name: 'deceptive_practices',
        keywords: [
          'fake review', 'write a review', 'generate reviews',
          'fake discount', 'bait and switch', 'hidden fees',
          'misleading price', 'false advertising', 'counterfeit',
        ],
        threshold: 0.03,
      },
      {
        name: 'pricing_manipulation',
        keywords: [
          'charge more', 'price discrimination', 'dynamic pricing based on',
          'raise the price for', 'different price for', 'surge pricing',
        ],
        threshold: 0.03,
      },
    ],
  },
  secretDetection: { enabled: true },
  outputSafety: { enabled: true },
};

// ── Insurance ────────────────────────────────────────────────────────────────

export const INSURANCE_COMPLIANCE: ComplianceTemplate = {
  name: 'insurance',
  description: 'Insurance regulation guardrails: blocks PII, unauthorized claim decisions, and discriminatory practices.',
  pii: { enabled: true, blockOnDetection: true },
  contentFilter: {
    enabled: true,
    blockOnViolation: true,
    categories: ['hate_speech', 'sexual', 'violence', 'bias'],
  },
  topicGuard: {
    blockedTopics: [
      MEDICAL_ADVICE,
      LEGAL_ADVICE,
      {
        name: 'claim_decision',
        keywords: [
          'your claim is denied', 'claim approved', 'claim rejected',
          'coverage denied', 'not covered', 'policy void',
          'cancel your policy', 'terminate coverage',
          'pre-existing condition',
        ],
        threshold: 0.03,
      },
    ],
  },
  secretDetection: { enabled: true },
  outputSafety: { enabled: true },
};
