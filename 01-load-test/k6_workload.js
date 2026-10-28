/**
 * Pillar 1: k6 stepped virtual-user (VU) workload with a JSON summary export.
 *
 * Author: Slihoczki Richárd Alex (BME BSc Thesis)
 * Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.
 *
 * Success follows SUCCESS_STATUSES (default "200"), the same setting as run_hey_stepped.py.
 * It is applied with http.setResponseCallback(http.expectedStatuses(...)), so k6's default
 * 200-399 "expected response" range is NOT used. Consequently:
 *   http_req_duration{expected_response:true}     = latency of successful final responses
 *   success_request_chain_duration                = wall time of successful http.get() calls incl.
 *                                                   redirect hops (custom Trend, 1 ms resolution)
 * The primary error rate, successful RPS and status counts are derived per request attempt in
 * k6_summary.js from this script's own counters (see there why http_req_failed is not used).
 *
 * Redirects: k6 follows up to 10 redirects by default and evaluates the final response.
 * LOAD_FOLLOW_REDIRECTS=false sets maxRedirects=0, so a 3xx is then a non-success response.
 * TLS certificates are verified unless K6_INSECURE_SKIP_TLS=true is set explicitly.
 * Both settings are written to the summary's "config" block.
 *
 * Output: ${K6_RESULTS_DIR}/k6_${RUN_ID}_summary.<UTC timestamp, ms>.json (valid / invalid_reason,
 * derived results and k6's raw summary metrics). For per-request raw data add:
 * --out json=<dir>/k6_<RUN_ID>_raw.json
 * Overwrite protection is best effort: k6 cannot create files exclusively, so the summary name
 * carries the end time in milliseconds (an earlier summary is only replaced if two runs with the same
 * RUN_ID end in the same millisecond). The --out json file is written by k6 itself and WILL be
 * overwritten if its name is reused; only a launcher that checks the path before starting k6 could
 * guarantee that (not part of this repository). Use a new RUN_ID for every run.
 *
 * Stage-level results: every attempt is tagged with the planned stage in which it STARTED (see
 * k6_summary.js: stagePlan / stageAt / stageThresholds / buildStageResults). The thresholds named
 * "...{stage:...}" are selector thresholds that always pass; they only make k6 report the stage
 * submetrics in handleSummary and are not SLA/acceptance criteria. HOLD_WARMUP (default 0s) excludes
 * the first part of every hold from the hold result (it is reported as its own hold_warmup stage).
 * STAGE_EVIDENCE_TOLERANCE_MS (default 2000) is the completeness tolerance for observed request starts.
 * Needs k6/execution (exec.scenario.startTime, exec.instance.vusActive); record `k6 version`.
 *
 * Example:
 *   k6 run -e RUN_ID=20261026T120000Z-k6 -e TARGET_APP_URL=https://app.example/ \
 *          -e STAGE_VUS="50,200,500" -e K6_RESULTS_DIR=01-load-test/results 01-load-test/k6_workload.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import exec from 'k6/execution';
import { Counter, Gauge, Rate, Trend } from 'k6/metrics';
import { buildSummary, durationToMs, stageAt, stagePlan, stageThresholds } from './k6_summary.js';

const TARGET_URL = __ENV.TARGET_APP_URL;
const RUN_ID = __ENV.RUN_ID || 'k6-adhoc';
if (!/^[A-Za-z0-9._-]{1,80}$/.test(RUN_ID)) {
  throw new Error('RUN_ID may contain only letters, digits, ".", "_" and "-"');
}
// The directory must exist; k6 does not create it.
const RESULTS_DIR = __ENV.K6_RESULTS_DIR || '01-load-test/results';

const SUCCESS_STATUSES = (__ENV.SUCCESS_STATUSES || '200')
  .split(',')
  .map((s) => s.trim())
  .filter((s) => s.length > 0)
  .map((s) => parseInt(s, 10));
if (SUCCESS_STATUSES.length === 0 || SUCCESS_STATUSES.some((c) => isNaN(c) || c < 100 || c > 599)) {
  throw new Error(`invalid SUCCESS_STATUSES: ${__ENV.SUCCESS_STATUSES}`);
}
http.setResponseCallback(http.expectedStatuses(...SUCCESS_STATUSES));

const FOLLOW_REDIRECTS = (__ENV.LOAD_FOLLOW_REDIRECTS || 'true').toLowerCase() !== 'false';
const INSECURE_SKIP_TLS = (__ENV.K6_INSECURE_SKIP_TLS || 'false').toLowerCase() === 'true';

// Configurable VU plateaus (default: 50 -> 200 -> 500)
const vuList = (__ENV.STAGE_VUS || '50,200,500').split(',').map((v) => parseInt(v.trim(), 10));
const rampDuration = __ENV.RAMP_DURATION || '30s';
const holdDuration = __ENV.HOLD_DURATION || '1m';

const dynamicStages = [];
for (const vus of vuList) {
  dynamicStages.push({ duration: rampDuration, target: vus });
  dynamicStages.push({ duration: holdDuration, target: vus });
}
dynamicStages.push({ duration: rampDuration, target: 0 });

const holdWarmupMs = durationToMs(__ENV.HOLD_WARMUP || '0s');
if (holdWarmupMs === null) {
  throw new Error(`invalid HOLD_WARMUP: ${__ENV.HOLD_WARMUP}`);
}
const STAGE_PLAN = stagePlan(dynamicStages, holdWarmupMs);
const stageTolMs = parseInt(__ENV.STAGE_EVIDENCE_TOLERANCE_MS || '2000', 10);

const summaryStats = (__ENV.TREND_STATS || 'avg,min,med,max,p(50),p(75),p(90),p(95),p(99)')
  .split(',')
  .map((s) => s.trim());

// SLA-style thresholds (reported, not the capacity acceptance rule of run_hey_stepped.py)
const p1Metric = __ENV.K6_TARGET_PERCENTILE_1 || 'p(90)';
const p1Limit = __ENV.K6_LIMIT_MS_1 || '300';
const p2Metric = __ENV.K6_TARGET_PERCENTILE_2 || 'p(95)';
const p2Limit = __ENV.K6_LIMIT_MS_2 || '500';
const maxErr = __ENV.ACCEPT_MAX_ERROR_RATE || '0.01';

// Status classes (k6 reports status 0 for transport errors)
const statusClass = {
  transport_error: new Counter('responses_transport_error'),
  '1xx': new Counter('responses_1xx'),
  '2xx': new Counter('responses_2xx'),
  '3xx': new Counter('responses_3xx'),
  '4xx': new Counter('responses_4xx'),
  '5xx': new Counter('responses_5xx'),
};
const successResponses = new Counter('responses_success');
const requestAttempts = new Counter('request_attempts');
// per attempt (not per redirect hop): true = not a success
const attemptFailed = new Rate('attempt_failed');
const successChain = new Trend('success_request_chain_duration', true);
// observed execution evidence per stage (min/max in the summary)
const requestStartElapsed = new Gauge('request_start_elapsed_ms');
const vusAtRequestStart = new Gauge('vus_at_request_start');

export const options = {
  insecureSkipTLSVerify: INSECURE_SKIP_TLS,
  maxRedirects: FOLLOW_REDIRECTS ? 10 : 0,
  stages: dynamicStages,
  summaryTrendStats: summaryStats,
  thresholds: {
    attempt_failed: [`rate<${maxErr}`],
    'http_req_duration{expected_response:true}': [`${p1Metric}<${p1Limit}`, `${p2Metric}<${p2Limit}`],
    ...stageThresholds(STAGE_PLAN), // selector thresholds (always pass), see the header
  },
};

export function setup() {
  if (!TARGET_URL) {
    throw new Error('TARGET_APP_URL is required');
  }
}

export default function () {
  const t0 = Date.now();
  const elapsed = t0 - exec.scenario.startTime;
  const tags = { stage: stageAt(STAGE_PLAN, elapsed) }; // attributed by request start
  requestStartElapsed.add(elapsed, tags);
  vusAtRequestStart.add(exec.instance.vusActive, tags);
  const res = http.get(TARGET_URL, { tags });
  const chainMs = Date.now() - t0;
  requestAttempts.add(1, tags);

  const cls = res.status === 0 ? 'transport_error' : `${Math.floor(res.status / 100)}xx`;
  if (statusClass[cls]) {
    statusClass[cls].add(1, tags);
  }
  const ok = SUCCESS_STATUSES.includes(res.status);
  if (ok) {
    successResponses.add(1, tags);
    successChain.add(chainMs, tags);
  }
  attemptFailed.add(!ok, tags);
  check(res, { 'status in SUCCESS_STATUSES': () => ok });

  sleep(parseFloat(__ENV.THINK_TIME_SEC || '0.1'));
}

export function handleSummary(data) {
  const out = buildSummary(data, {
    run_id: RUN_ID,
    target_url: TARGET_URL,
    success_statuses: SUCCESS_STATUSES,
    follow_redirects: FOLLOW_REDIRECTS,
    max_redirects: FOLLOW_REDIRECTS ? 10 : 0,
    tls_certificate_verification: !INSECURE_SKIP_TLS,
    stage_vus: vuList,
    ramp_duration: rampDuration,
    hold_duration: holdDuration,
    stages: dynamicStages,
    stage_plan: STAGE_PLAN,
    hold_warmup_ms: holdWarmupMs,
    stage_evidence_tolerance_ms: stageTolMs,
    think_time_sec: parseFloat(__ENV.THINK_TIME_SEC || '0.1'),
  }, new Date().toISOString());
  const stamp = new Date().toISOString().replace(/[-:.]/g, '');   // e.g. 20261101T101500123Z
  const path = `${RESULTS_DIR}/k6_${RUN_ID}_summary.${stamp}.json`;
  return {
    [path]: JSON.stringify(out, null, 2),
    stdout: `k6 summary written to ${path} (valid=${out.valid}${out.valid ? '' : `: ${out.invalid_reason}`})\n`,
  };
}
