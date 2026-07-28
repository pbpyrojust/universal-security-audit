// ── Single dial controlling concurrency/delay/probe-list-size across every active check, so the
// speed-vs-footprint tradeoff is one explicit flag (--intensity) instead of a dozen separate ones. ──
import { INTENSITY_PORT_PROFILES } from './port-scan.mjs';

const PROFILES = {
  light: {
    exposedPathConcurrency: 3, exposedPathDelayMs: 400,
    portScan: INTENSITY_PORT_PROFILES.light,
    subdomainLivenessLimit: 5,
  },
  normal: {
    exposedPathConcurrency: 4, exposedPathDelayMs: 150,
    portScan: INTENSITY_PORT_PROFILES.normal,
    subdomainLivenessLimit: 15,
  },
  aggressive: {
    exposedPathConcurrency: 10, exposedPathDelayMs: 50,
    portScan: INTENSITY_PORT_PROFILES.aggressive,
    subdomainLivenessLimit: 40,
  },
};

export function resolveIntensity(name) {
  const key = String(name || 'normal').toLowerCase();
  if (!PROFILES[key]) {
    console.error(`Warning: unknown --intensity "${name}", falling back to "normal". Valid values: light, normal, aggressive.`);
    return PROFILES.normal;
  }
  return PROFILES[key];
}
