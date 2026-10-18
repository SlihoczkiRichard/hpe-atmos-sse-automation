/**
 * Pillar 1: Configurable k6 Stepped Virtual User (VU) Simulation
 * Supports configurable trend percentiles (e.g., p50, p75, p90, p95, p99),
 * dynamic VU stages, and customizable SLA thresholds via environment variables.
 *
 * Example custom run:
 * k6 run -e TREND_STATS="avg,min,med,max,p(50),p(75),p(90),p(95),p(99)" -e STAGE_VUS="20,100,300" 01-load-test/k6_workload.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';

const TARGET_URL = __ENV.TARGET_APP_URL || 'https://richard-internal-web.local';

// Configurable VU plateaus (default: 50 -> 200 -> 500)
const vuList = (__ENV.STAGE_VUS || '50,200,500').split(',').map((v) => parseInt(v.trim(), 10));
const rampDuration = __ENV.RAMP_DURATION || '30s';
const holdDuration = __ENV.HOLD_DURATION || '1m';

// Dynamically build stages from configurable parameters
const dynamicStages = [];
for (const vus of vuList) {
  dynamicStages.push({ duration: rampDuration, target: vus });
  dynamicStages.push({ duration: holdDuration, target: vus });
}
dynamicStages.push({ duration: rampDuration, target: 0 });

// Configurable percentiles displayed in the report (supports any p(X) value!)
const summaryStats = (__ENV.TREND_STATS || 'avg,min,med,max,p(50),p(75),p(90),p(95),p(99)')
  .split(',')
  .map((s) => s.trim());

// Configurable SLA thresholds
const p1Metric = __ENV.K6_TARGET_PERCENTILE_1 || 'p(90)';
const p1Limit  = __ENV.K6_LIMIT_MS_1 || '300';
const p2Metric = __ENV.K6_TARGET_PERCENTILE_2 || 'p(95)';
const p2Limit  = __ENV.K6_LIMIT_MS_2 || '500';
const maxErr   = __ENV.K6_MAX_ERROR_RATE || '0.01';

export const options = {
  insecureSkipTLSVerify: true,
  stages: dynamicStages,
  summaryTrendStats: summaryStats,
  thresholds: {
    http_req_failed: [`rate<${maxErr}`],
    http_req_duration: [`${p1Metric}<${p1Limit}`, `${p2Metric}<${p2Limit}`],
  },
};

export default function () {
  const res = http.get(TARGET_URL);

  check(res, {
    'status is 200': (r) => r.status === 200,
    [`duration < ${p2Limit}ms`]: (r) => r.timings.duration < parseInt(p2Limit, 10),
  });

  sleep(parseFloat(__ENV.THINK_TIME_SEC || '0.1'));
}