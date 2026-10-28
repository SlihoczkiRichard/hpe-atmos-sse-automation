/**
 * Pillar 1: derived k6 results (pure functions, no k6 imports, so they can be tested with node).
 *
 * Author: Slihoczki Richárd Alex (BME BSc Thesis)
 * Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.
 *
 * Request attempt = one http.get() call of the default function. Its outcome is counted exactly
 * once in one of the responses_<class> counters (transport_error = status 0). The derived
 * numbers below are built from these counters, not from http_reqs / http_req_failed, because k6
 * records every hop of a followed redirect chain as its own request in those built-in metrics.
 *
 * Every attempt also increments request_attempts. A k6 counter that never received a sample may be
 * absent from the summary; an absent class counter is read as 0 only after checking that the
 * present class counters add up to request_attempts. Otherwise the result is invalid and no zero
 * is assumed.
 */

const CLASSES = ['transport_error', '1xx', '2xx', '3xx', '4xx', '5xx'];

function value(metrics, name, key) {
  const m = metrics[name];
  if (!m || !m.values || m.values[key] === undefined || m.values[key] === null) {
    return null;
  }
  return m.values[key];
}

/** "30s", "1m", "1m30s", "500ms", "1h" -> milliseconds; null if not understood. */
export function durationToMs(text) {
  const s = String(text).trim();
  if (!/^(\d+(\.\d+)?(ms|h|m|s))+$/.test(s)) {
    return null;
  }
  const factor = { ms: 1, s: 1000, m: 60000, h: 3600000 };
  let total = 0;
  for (const part of s.matchAll(/(\d+(?:\.\d+)?)(ms|h|m|s)/g)) {
    total += parseFloat(part[1]) * factor[part[2]];
  }
  return total;
}

export function plannedDurationMs(stages) {
  let total = 0;
  for (const st of stages) {
    const ms = durationToMs(st.duration);
    if (ms === null) {
      return null;
    }
    total += ms;
  }
  return total;
}

// ---------------------------------------------------------------------------------------------
// Stage-level results
//
// Stage plan (PLANNED times, from the script's own options.stages): each configured stage becomes one
// entry with kind ramp (VU target changes), hold (target equals the previous target) or ramp_down
// (target 0, the last stage). An optional hold warm-up (HOLD_WARMUP) splits the first part of every
// hold into its own hold_warmup entry. Times are ms since the scenario start (exec.scenario.startTime).
// Requests that start at or after the planned end are tagged after_planned_end (graceful ramp-down /
// graceful stop) and are reported, never dropped.
//
// Attribution: by request START. The workload computes elapsed = Date.now() - exec.scenario.startTime
// immediately before http.get() and tags the request and every custom sample of that attempt with
// the stage active at that instant; a request crossing a stage boundary belongs to the stage in which
// it started. Rates are therefore "per request start": successful_rps = successful attempts STARTED in
// the hold / hold duration (end_ms - start_ms), used only when the hold is complete.
//
// Required stage submetrics (k6 puts a tagged submetric into handleSummary only when a threshold
// references it, so stageThresholds() defines "selector thresholds" that always pass; they are not
// SLA or acceptance criteria and are marked as such in the summary):
//   request_attempts{stage:S}                      count   attempts started in S
//   responses_success{stage:S}                     count   successes among them
//   responses_transport_error{stage:S}             count   status 0
//   responses_5xx{stage:S}                         count
//   success_request_chain_duration{stage:S}        trend   latency of successful attempts
//   request_start_elapsed_ms{stage:S}              gauge   min / max = first / last observed request start
//   vus_at_request_start{stage:S}                  gauge   min / max of exec.instance.vusActive at request starts
//
// OBSERVED evidence is kept apart from the plan. A stage is complete only if the run did not end early
// AND a request start was observed at or after (stage end - tolerance) anywhere in the run (the
// execution demonstrably passed the stage). A hold counts as a constant-VU result only if it is
// complete and vus_at_request_start min == max == target (sampled at request starts only, so short
// dips between requests are not visible). Undefined values are null with a reason; zero attempts are
// recorded only for a complete stage.
// ---------------------------------------------------------------------------------------------

export const STAGE_SUBMETRICS = [
  { metric: 'request_attempts', type: 'counter', selector: 'count>=0' },
  { metric: 'responses_success', type: 'counter', selector: 'count>=0' },
  { metric: 'responses_transport_error', type: 'counter', selector: 'count>=0' },
  { metric: 'responses_5xx', type: 'counter', selector: 'count>=0' },
  { metric: 'success_request_chain_duration', type: 'trend', selector: 'max>=0' },
  { metric: 'request_start_elapsed_ms', type: 'gauge', selector: 'value>=0' },
  { metric: 'vus_at_request_start', type: 'gauge', selector: 'value>=0' },
];
export const SELECTOR_THRESHOLD_NOTE = 'stage submetric selector thresholds (always pass): their only purpose is ' +
  'to make k6 report the tagged stage submetrics in handleSummary; they are not SLA or acceptance criteria';
export const AFTER_END = 'after_planned_end';

function pad(n) {
  return String(n).padStart(2, '0');
}

/** stages: [{duration, target}]; holdWarmupMs >= 0. Returns the planned stage entries or throws. */
export function stagePlan(stages, holdWarmupMs = 0) {
  const plan = [];
  let t = 0;
  let previous = 0;
  stages.forEach((st, i) => {
    const ms = durationToMs(st.duration);
    if (ms === null || ms <= 0) {
      throw new Error(`stage ${i + 1}: duration ${st.duration} not understood`);
    }
    const last = i === stages.length - 1;
    let kind = st.target === previous ? 'hold' : 'ramp';
    if (last && st.target === 0) {
      kind = 'ramp_down';
    }
    const base = { index: i + 1, from_vus: previous, target_vus: st.target };
    if (kind === 'hold' && holdWarmupMs > 0) {
      const w = Math.min(holdWarmupMs, ms);
      plan.push({ ...base, label: `s${pad(i + 1)}_hold_warmup_${st.target}`, kind: 'hold_warmup', start_ms: t,
        end_ms: t + w });
      if (w < ms) {
        plan.push({ ...base, label: `s${pad(i + 1)}_hold_${st.target}`, kind: 'hold', start_ms: t + w, end_ms: t + ms });
      }
    } else {
      const label = kind === 'hold' ? `s${pad(i + 1)}_hold_${st.target}`
        : kind === 'ramp_down' ? `s${pad(i + 1)}_ramp_down` : `s${pad(i + 1)}_ramp_to_${st.target}`;
      plan.push({ ...base, label, kind, start_ms: t, end_ms: t + ms });
    }
    t += ms;
    previous = st.target;
  });
  return plan;
}

/** Stage label for a request starting elapsedMs after the scenario start. */
export function stageAt(plan, elapsedMs) {
  for (const st of plan) {
    if (elapsedMs >= st.start_ms && elapsedMs < st.end_ms) {
      return st.label;
    }
  }
  return elapsedMs < 0 ? plan[0].label : AFTER_END;
}

/** The thresholds that make k6 emit every required stage submetric (incl. after_planned_end). */
export function stageThresholds(plan) {
  const out = {};
  for (const label of plan.map((s) => s.label).concat([AFTER_END])) {
    for (const s of STAGE_SUBMETRICS) {
      out[`${s.metric}{stage:${label}}`] = [s.selector];
    }
  }
  return out;
}

function sub(metrics, metric, label) {
  const m = metrics[`${metric}{stage:${label}}`];
  return m && m.values ? m.values : null;
}

/**
 * Per-stage results from the stage submetrics. plan: stagePlan(); endedEarly: the whole run ended
 * before its planned duration; totalAttempts: request_attempts count; tolMs: completeness tolerance.
 */
export function buildStageResults(metrics, plan, endedEarly, totalAttempts, tolMs) {
  const entries = plan.concat([{ label: AFTER_END, kind: 'after_planned_end', start_ms: plan.length
    ? plan[plan.length - 1].end_ms : 0, end_ms: null, target_vus: 0, from_vus: 0, index: null }]);
  const lastStartMs = Math.max(-1, ...entries.map((st) => {
    const g = sub(metrics, 'request_start_elapsed_ms', st.label);
    return g && typeof g.max === 'number' ? g.max : -1;
  }));
  const counts = entries.map((st) => {
    const c = {};
    for (const m of ['request_attempts', 'responses_success', 'responses_transport_error', 'responses_5xx']) {
      const v = sub(metrics, m, st.label);
      c[m] = v && typeof v.count === 'number' ? v.count : null;
    }
    return c;
  });
  const presentSum = counts.reduce((acc, c) => acc + (c.request_attempts || 0), 0);
  const sumOk = totalAttempts !== null && presentSum === totalAttempts;
  const problems = [];
  if (!sumOk) {
    problems.push(`stage-tagged attempts (${presentSum}) do not add up to request_attempts (${totalAttempts})`);
  }

  const stages = entries.map((st, i) => {
    const reasons = {};
    const planned = { kind: st.kind, label: st.label, index: st.index, from_vus: st.from_vus,
      target_vus: st.target_vus, start_ms: st.start_ms, end_ms: st.end_ms };
    const g = sub(metrics, 'request_start_elapsed_ms', st.label);
    const v = sub(metrics, 'vus_at_request_start', st.label);
    let complete;
    let completeReason;
    if (st.kind === 'after_planned_end') {
      complete = !endedEarly;
      completeReason = complete ? 'run reached its planned end' : 'run ended early';
    } else if (endedEarly) {
      complete = false;
      completeReason = 'run ended before its planned duration';
    } else if (lastStartMs >= st.end_ms - tolMs) {
      complete = true;
      completeReason = `a request start was observed at ${lastStartMs} ms >= stage end - ${tolMs} ms`;
    } else {
      complete = false;
      completeReason = `no request start observed after ${st.end_ms - tolMs} ms (last: ${lastStartMs} ms)`;
    }
    const observed = {
      first_request_start_ms: g && typeof g.min === 'number' ? g.min : null,
      last_request_start_ms: g && typeof g.max === 'number' ? g.max : null,
      vus_at_request_start_min: v && typeof v.min === 'number' ? v.min : null,
      vus_at_request_start_max: v && typeof v.max === 'number' ? v.max : null,
      complete,
      complete_reason: completeReason,
    };
    // counts: an observed count > 0 is kept; zero is recorded only for a complete stage (an absent
    // submetric counts as zero only if the stage sums match request_attempts)
    const value0 = (raw, name) => {
      if (raw === null) {
        if (complete && sumOk) {
          return 0;
        }
        reasons[name] = sumOk ? 'submetric absent and stage not complete' : 'submetric absent; stage sums do not match';
        return null;
      }
      if (raw === 0 && !complete) {
        reasons[name] = 'no observation and stage not complete';
        return null;
      }
      return raw;
    };
    const c = counts[i];
    const attempts = value0(c.request_attempts, 'attempts');
    const success = attempts === null ? null : value0(c.responses_success, 'success_responses');
    const transport = attempts === null ? null : value0(c.responses_transport_error, 'transport_errors');
    const r5xx = attempts === null ? null : value0(c.responses_5xx, 'responses_5xx');
    const derived = {};
    if (attempts === null || success === null) {
      derived.primary_error_rate = null;
      reasons.primary_error_rate = reasons.attempts || reasons.success_responses;
    } else if (attempts === 0) {
      derived.primary_error_rate = null;
      reasons.primary_error_rate = 'no attempts in this stage';
    } else {
      derived.primary_error_rate = (attempts - success) / attempts;
    }
    derived.err5xx_transport_error_rate = attempts > 0 && transport !== null && r5xx !== null
      ? (r5xx + transport) / attempts : null;
    if (derived.err5xx_transport_error_rate === null) {
      reasons.err5xx_transport_error_rate = attempts > 0 ? 'class counts undefined' : 'no attempts in this stage';
    }
    const lat = sub(metrics, 'success_request_chain_duration', st.label);
    if (success > 0 && lat) {
      derived.latency_success_request_chain_ms = lat;
    } else {
      derived.latency_success_request_chain_ms = null;
      reasons.latency_success_request_chain_ms = success > 0 ? 'stage trend submetric absent'
        : 'no successful attempts in this stage';
    }
    const isHold = st.kind === 'hold';
    const maintained = isHold && observed.vus_at_request_start_min === st.target_vus
      && observed.vus_at_request_start_max === st.target_vus;
    derived.target_vus_observed = !isHold ? 'not_applicable'
      : (observed.vus_at_request_start_min === null ? 'no_evidence' : (maintained ? 'maintained_at_request_starts'
        : 'not_maintained'));
    derived.constant_vu_result = isHold && complete && maintained && sumOk;
    if (derived.constant_vu_result && success !== null) {
      derived.successful_rps = success / ((st.end_ms - st.start_ms) / 1000);
    } else {
      derived.successful_rps = null;
      reasons.successful_rps = !isHold ? `${st.kind}: the VU count is not constant; no constant-VU rate`
        : (!complete ? `hold not complete (${completeReason}); the planned duration is not used`
          : (!maintained ? `target VU count not observed throughout the hold (${derived.target_vus_observed})`
            : (!sumOk ? 'stage sums do not match request_attempts' : 'success count undefined')));
    }
    return { planned, observed, counts: { attempts, success_responses: success, transport_errors: transport,
      responses_5xx: r5xx }, derived, null_reasons: reasons };
  });
  return {
    valid: sumOk,
    problems,
    attribution: 'request start (elapsed since exec.scenario.startTime, taken immediately before http.get())',
    rate_basis: 'successful attempts started in the hold / planned hold duration; only for complete holds ' +
      'with the target VU count observed at every request start',
    completeness_rule: `run not ended early and a request start observed at or after stage end - ${tolMs} ms`,
    selector_threshold_note: SELECTOR_THRESHOLD_NOTE,
    stages,
  };
}

/**
 * data: the object k6 passes to handleSummary; config: the script's effective settings;
 * endedUtc: ISO time when the summary was produced. Returns the JSON-ready result object.
 */
export function buildSummary(data, config, endedUtc, toleranceMs = 5000) {
  const metrics = (data && data.metrics) || {};
  const durationMs = data && data.state ? data.state.testRunDurationMs : null;
  const attemptsCounter = value(metrics, 'request_attempts', 'count');

  const classCounts = {};
  for (const c of CLASSES) {
    classCounts[c] = value(metrics, `responses_${c}`, 'count');
  }
  const presentSum = CLASSES.reduce((acc, c) => acc + (classCounts[c] || 0), 0);
  const plannedMs = plannedDurationMs(config.stages || []);

  const invalid = [];
  if (durationMs === null || durationMs === undefined || !(durationMs > 0)) {
    invalid.push('k6 testRunDurationMs missing');
  }
  if (attemptsCounter === null || attemptsCounter === 0) {
    invalid.push('no request attempts recorded');
  } else if (presentSum !== attemptsCounter) {
    invalid.push(`status class counters (${presentSum}) do not add up to request_attempts (${attemptsCounter})`);
  }
  if (plannedMs !== null && durationMs > 0 && durationMs + toleranceMs < plannedMs) {
    invalid.push(`run ended early: ${durationMs} ms of planned ${plannedMs} ms`);
  }
  const valid = invalid.length === 0;

  let derived = null;
  if (valid) {
    for (const c of CLASSES) {
      if (classCounts[c] === null) {
        classCounts[c] = 0; // justified: present class counters add up to request_attempts (checked above)
      }
    }
    const attempts = presentSum;
    const success = value(metrics, 'responses_success', 'count') || 0;
    const seconds = durationMs / 1000;
    const statsOf = (name) => {
      const m = metrics[name];
      return m && m.values ? m.values : null;
    };
    derived = {
      attempts,
      success_responses: success,
      non_success_http_responses: attempts - success - classCounts.transport_error,
      transport_errors: classCounts.transport_error,
      status_class_counts: classCounts,
      primary_error_rate: (attempts - success) / attempts,
      err5xx_transport_error_rate: (classCounts['5xx'] + classCounts.transport_error) / attempts,
      successful_rps_whole_test: success / seconds,
      latency_success_final_hop_ms: statsOf('http_req_duration{expected_response:true}'),
      latency_success_request_chain_ms: statsOf('success_request_chain_duration'),
      k6_http_reqs_including_redirect_hops: value(metrics, 'http_reqs', 'count'),
      k6_http_req_failed_rate_per_hop: value(metrics, 'http_req_failed', 'rate'),
    };
  }

  const endedEarly = !(durationMs > 0) || (plannedMs !== null && durationMs + toleranceMs < plannedMs);
  let stageResults = null;
  if (config.stage_plan) {
    stageResults = buildStageResults(metrics, config.stage_plan, endedEarly, attemptsCounter,
      config.stage_evidence_tolerance_ms === undefined ? 2000 : config.stage_evidence_tolerance_ms);
  }

  const startedMs = Date.parse(endedUtc) - (durationMs > 0 ? durationMs : 0);
  return {
    run_id: config.run_id,
    tool: 'k6',
    mode: 'measurement',
    valid,
    invalid_reason: invalid.join('; '),
    ended_utc: endedUtc,
    started_utc_derived: durationMs > 0 ? new Date(startedMs).toISOString() : null,
    test_run_duration_ms: durationMs > 0 ? durationMs : null,
    planned_duration_ms: plannedMs,
    timing_note: 'test_run_duration_ms is k6\'s own run timer; started_utc_derived = ended_utc - duration',
    config,
    definitions: {
      request_attempt: 'one http.get() call; ends with an HTTP response or a transport error (status 0)',
      success: 'HTTP status in success_statuses',
      primary_error_rate: '(non-success HTTP responses + transport errors) / attempts',
      err5xx_transport_error_rate: '(HTTP 5xx + transport errors) / attempts; comparison only',
      successful_rps_whole_test: 'successful responses / whole test duration incl. ramps; not per plateau',
      latency_success_final_hop_ms: 'http_req_duration{expected_response:true}: final response of a success, ' +
        'excluding earlier redirect hops',
      latency_success_request_chain_ms: 'wall time of http.get() incl. redirect hops for successful attempts ' +
        '(Date.now() resolution: 1 ms)',
      k6_builtin_metrics: 'http_reqs and http_req_failed count every redirect hop separately; reported only',
      acceptance: 'not applied here; the capacity acceptance rule is evaluated per level by run_hey_stepped.py',
      stage_results: 'per planned stage, attributed by request start; see stage_results.attribution / rate_basis',
    },
    derived,
    stage_results: stageResults,
    metrics,
  };
}
