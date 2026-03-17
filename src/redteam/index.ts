/**
 * Red Team Engine — public exports.
 * @module
 */

export { runRedTeam } from './runner';
export { analyzeAttackResult } from './analyzer';
export { generateReport } from './reporter';
export { getBuiltInAttacks, injectSystemPrompt, BUILT_IN_ATTACKS } from './attacks';

export type {
  AttackCategory,
  AttackPayload,
  AttackOutcome,
  AttackResult,
  GuardrailEventCapture,
  RedTeamOptions,
  RedTeamProgress,
  RedTeamReport,
  CategoryScore,
  Vulnerability,
} from './types';

export type { AnalysisInput, AnalysisResult } from './analyzer';
