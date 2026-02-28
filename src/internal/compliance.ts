/**
 * Compliance module — GDPR/CCPA/HIPAA helpers.
 * Consent tracking, data retention, and geofencing.
 * @internal
 */

export interface ComplianceOptions {
  dataRetention?: {
    enabled?: boolean;
    maxAgeDays?: number;
  };
  consentTracking?: {
    enabled?: boolean;
    /** If true, block LLM calls when no consent is recorded in context. */
    requireConsent?: boolean;
    /** Field name in context metadata that indicates consent. Default: 'consent' */
    consentField?: string;
  };
  geofencing?: {
    allowedRegions?: string[];
    blockOnViolation?: boolean;
  };
}

export interface ComplianceCheckResult {
  passed: boolean;
  violations: ComplianceViolation[];
}

export interface ComplianceViolation {
  type: 'missing_consent' | 'region_blocked' | 'retention_exceeded';
  message: string;
}

export interface ComplianceEventData {
  consentRecorded: boolean;
  dataRegion?: string;
  retentionDays?: number;
}

/**
 * Check compliance requirements before an LLM call.
 */
export function checkCompliance(
  options: ComplianceOptions | undefined,
  context: {
    metadata?: Record<string, string>;
    region?: string;
  },
): ComplianceCheckResult {
  if (!options) {
    return { passed: true, violations: [] };
  }

  const violations: ComplianceViolation[] = [];

  // Consent tracking
  if (options.consentTracking?.enabled && options.consentTracking.requireConsent) {
    const consentField = options.consentTracking.consentField ?? 'consent';
    const consentValue = context.metadata?.[consentField];

    if (!consentValue || consentValue === 'false' || consentValue === '0') {
      violations.push({
        type: 'missing_consent',
        message: `Consent not recorded. Set metadata.${consentField} = "true" in request context.`,
      });
    }
  }

  // Geofencing
  if (options.geofencing?.allowedRegions && context.region) {
    const allowed = options.geofencing.allowedRegions.map((r) =>
      r.toLowerCase(),
    );
    if (!allowed.includes(context.region.toLowerCase())) {
      violations.push({
        type: 'region_blocked',
        message: `Region "${context.region}" is not in allowed regions: ${allowed.join(', ')}.`,
      });
    }
  }

  return {
    passed: violations.length === 0,
    violations,
  };
}

/**
 * Build compliance event data for the event payload.
 */
export function buildComplianceEventData(
  options: ComplianceOptions | undefined,
  context: { metadata?: Record<string, string>; region?: string },
): ComplianceEventData {
  if (!options) {
    return { consentRecorded: false };
  }

  const consentField = options.consentTracking?.consentField ?? 'consent';
  const consentValue = context.metadata?.[consentField];
  const consentRecorded = !!consentValue && consentValue !== 'false' && consentValue !== '0';

  return {
    consentRecorded,
    dataRegion: context.region,
    retentionDays: options.dataRetention?.maxAgeDays,
  };
}
