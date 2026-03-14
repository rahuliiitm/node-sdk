/**
 * Sensitivity presets for quick security configuration.
 * @internal
 */

import type { SecurityOptions } from '../types';

export type SensitivityPreset = 'strict' | 'balanced' | 'permissive';

/**
 * Preset definitions — each provides reasonable defaults for all security modules.
 * User-specified values always override preset values (shallow per-module merge).
 */
const PRESETS: Record<SensitivityPreset, Partial<SecurityOptions>> = {
  strict: {
    injection: { blockThreshold: 0.5, blockOnHighRisk: true },
    jailbreak: { blockThreshold: 0.5, warnThreshold: 0.2, blockOnDetection: true },
    contentFilter: { blockOnViolation: true },
    pii: { redaction: 'placeholder', scanResponse: true },
    secretDetection: { action: 'block', scanResponse: true },
    unicodeSanitizer: { action: 'block', detectHomoglyphs: true },
  },
  balanced: {
    injection: { blockThreshold: 0.7, blockOnHighRisk: true },
    jailbreak: { blockThreshold: 0.7, warnThreshold: 0.3, blockOnDetection: true },
    contentFilter: { blockOnViolation: true },
    pii: { redaction: 'placeholder', scanResponse: true },
    secretDetection: { action: 'redact', scanResponse: true },
    unicodeSanitizer: { action: 'strip', detectHomoglyphs: true },
  },
  permissive: {
    injection: { blockThreshold: 0.85, blockOnHighRisk: false },
    jailbreak: { blockThreshold: 0.85, warnThreshold: 0.5, blockOnDetection: false },
    contentFilter: { blockOnViolation: false },
    pii: { redaction: 'placeholder', scanResponse: false },
    secretDetection: { action: 'warn' },
    unicodeSanitizer: { action: 'warn' },
  },
};

/**
 * Deep-merge preset defaults with user overrides.
 * User values always win. Only fills in gaps.
 */
function deepMergeOptions(
  preset: Partial<SecurityOptions>,
  user: SecurityOptions,
): SecurityOptions {
  const result = { ...user };

  for (const key of Object.keys(preset) as (keyof SecurityOptions)[]) {
    const presetVal = preset[key];
    const userVal = user[key];

    if (presetVal === undefined) continue;

    if (userVal === undefined) {
      // User didn't set this module — use preset
      (result as any)[key] = presetVal;
    } else if (
      typeof presetVal === 'object' &&
      presetVal !== null &&
      typeof userVal === 'object' &&
      userVal !== null &&
      !Array.isArray(presetVal)
    ) {
      // Both are objects — shallow merge, user wins
      (result as any)[key] = { ...presetVal, ...userVal };
    }
    // else: user set a primitive or array — keep user value
  }

  return result;
}

/**
 * Resolve security options by applying preset defaults, then user overrides.
 * If no preset is specified, returns options unchanged.
 */
export function resolveSecurityOptions(options: SecurityOptions): SecurityOptions {
  if (!options.preset) return options;
  const presetDefaults = PRESETS[options.preset];
  if (!presetDefaults) return options;
  return deepMergeOptions(presetDefaults, options);
}
