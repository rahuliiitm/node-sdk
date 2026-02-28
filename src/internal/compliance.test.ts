import { checkCompliance, buildComplianceEventData } from './compliance';

describe('Compliance', () => {
  // ── Consent tracking ──────────────────────────────────────────────────────

  describe('consent tracking', () => {
    it('passes when consent is recorded', () => {
      const result = checkCompliance(
        {
          consentTracking: { enabled: true, requireConsent: true },
        },
        { metadata: { consent: 'true' } },
      );
      expect(result.passed).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('fails when consent is missing', () => {
      const result = checkCompliance(
        {
          consentTracking: { enabled: true, requireConsent: true },
        },
        { metadata: {} },
      );
      expect(result.passed).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].type).toBe('missing_consent');
    });

    it('fails when consent is "false"', () => {
      const result = checkCompliance(
        {
          consentTracking: { enabled: true, requireConsent: true },
        },
        { metadata: { consent: 'false' } },
      );
      expect(result.passed).toBe(false);
    });

    it('uses custom consent field', () => {
      const result = checkCompliance(
        {
          consentTracking: { enabled: true, requireConsent: true, consentField: 'user_agreed' },
        },
        { metadata: { user_agreed: 'yes' } },
      );
      expect(result.passed).toBe(true);
    });

    it('skips when not enabled', () => {
      const result = checkCompliance(
        {
          consentTracking: { enabled: false, requireConsent: true },
        },
        { metadata: {} },
      );
      expect(result.passed).toBe(true);
    });
  });

  // ── Geofencing ────────────────────────────────────────────────────────────

  describe('geofencing', () => {
    it('passes for allowed region', () => {
      const result = checkCompliance(
        {
          geofencing: { allowedRegions: ['us', 'eu'] },
        },
        { region: 'us' },
      );
      expect(result.passed).toBe(true);
    });

    it('fails for blocked region', () => {
      const result = checkCompliance(
        {
          geofencing: { allowedRegions: ['us', 'eu'] },
        },
        { region: 'cn' },
      );
      expect(result.passed).toBe(false);
      expect(result.violations[0].type).toBe('region_blocked');
    });

    it('is case insensitive', () => {
      const result = checkCompliance(
        {
          geofencing: { allowedRegions: ['US'] },
        },
        { region: 'us' },
      );
      expect(result.passed).toBe(true);
    });

    it('skips when no region provided', () => {
      const result = checkCompliance(
        {
          geofencing: { allowedRegions: ['us'] },
        },
        {},
      );
      expect(result.passed).toBe(true);
    });
  });

  // ── Multiple violations ───────────────────────────────────────────────────

  describe('multiple violations', () => {
    it('reports all violations at once', () => {
      const result = checkCompliance(
        {
          consentTracking: { enabled: true, requireConsent: true },
          geofencing: { allowedRegions: ['us'] },
        },
        { metadata: {}, region: 'cn' },
      );
      expect(result.passed).toBe(false);
      expect(result.violations).toHaveLength(2);
    });
  });

  // ── No options ────────────────────────────────────────────────────────────

  describe('no options', () => {
    it('passes when options is undefined', () => {
      const result = checkCompliance(undefined, {});
      expect(result.passed).toBe(true);
    });

    it('passes when options is empty', () => {
      const result = checkCompliance({}, {});
      expect(result.passed).toBe(true);
    });
  });

  // ── buildComplianceEventData ──────────────────────────────────────────────

  describe('buildComplianceEventData', () => {
    it('records consent status', () => {
      const data = buildComplianceEventData(
        { consentTracking: { enabled: true } },
        { metadata: { consent: 'true' } },
      );
      expect(data.consentRecorded).toBe(true);
    });

    it('records no consent', () => {
      const data = buildComplianceEventData(
        { consentTracking: { enabled: true } },
        { metadata: {} },
      );
      expect(data.consentRecorded).toBe(false);
    });

    it('includes region and retention days', () => {
      const data = buildComplianceEventData(
        { dataRetention: { enabled: true, maxAgeDays: 30 } },
        { region: 'eu' },
      );
      expect(data.dataRegion).toBe('eu');
      expect(data.retentionDays).toBe(30);
    });

    it('handles undefined options', () => {
      const data = buildComplianceEventData(undefined, {});
      expect(data.consentRecorded).toBe(false);
    });
  });
});
