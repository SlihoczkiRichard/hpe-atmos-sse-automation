"""k6 workload: static checks of k6_workload.js and node-executed tests of k6_summary.js.

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

k6 itself is not installed here, so k6_workload.js is only parsed (node --check). The derived
results in k6_summary.js have no k6 imports and are executed with node on synthetic summary data.
Without node these tests are skipped, not replaced by a mock.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from _helpers import ROOT, OfflineTestCase

K6_DIR = os.path.join(ROOT, "01-load-test")
K6_SCRIPT = os.path.join(K6_DIR, "k6_workload.js")
K6_SUMMARY = os.path.join(K6_DIR, "k6_summary.js")
NODE = shutil.which("node")

DRIVER = """
import { readFileSync } from 'node:fs';
import { buildSummary, durationToMs, stageAt, stagePlan, stageThresholds } from './k6_summary.mjs';
const input = JSON.parse(readFileSync(process.argv[2], 'utf8'));
let out;
if (input.durations) {
  out = input.durations.map((d) => durationToMs(d));
} else if (input.plan) {
  const plan = stagePlan(input.plan, input.warmup_ms || 0);
  out = input.at ? input.at.map((ms) => stageAt(plan, ms)) : (input.thresholds ? stageThresholds(plan) : plan);
} else {
  out = buildSummary(input.data, input.config, input.ended_utc);
}
process.stdout.write(JSON.stringify(out));
"""

CONFIG = {"run_id": "K6-T", "success_statuses": [200], "follow_redirects": True,
          "stages": [{"duration": "30s", "target": 50}, {"duration": "1m", "target": 50}]}


def counter(n):
    return {"type": "counter", "values": {"count": n, "rate": n / 90.0}}


def k6_data(duration_ms=90000, **counts):
    metrics = {f"responses_{k}": counter(v) for k, v in counts.items() if k != "attempts"}
    if "attempts" in counts:
        metrics["request_attempts"] = counter(counts["attempts"])
    metrics["http_reqs"] = counter(counts.get("attempts", 0) + 40)   # incl. redirect hops
    metrics["http_req_duration{expected_response:true}"] = {"type": "trend",
                                                             "values": {"p(95)": 120.0, "p(99)": 300.0}}
    return {"metrics": metrics, "state": {"testRunDurationMs": duration_ms}}


class K6ScriptStaticTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        with open(K6_SCRIPT, encoding="utf-8") as f:
            self.src = f.read()

    def test_success_follows_success_statuses_not_k6_default(self):
        self.assertIn("http.setResponseCallback(http.expectedStatuses(...SUCCESS_STATUSES))", self.src)
        self.assertIn("__ENV.SUCCESS_STATUSES || '200'", self.src)
        self.assertIn("'http_req_duration{expected_response:true}'", self.src)

    def test_tls_verified_and_redirects_configurable_and_recorded(self):
        self.assertIn("(__ENV.K6_INSECURE_SKIP_TLS || 'false').toLowerCase() === 'true'", self.src)
        self.assertIn("maxRedirects: FOLLOW_REDIRECTS ? 10 : 0", self.src)
        self.assertNotIn("insecureSkipTLSVerify: true", self.src)
        self.assertIn("tls_certificate_verification: !INSECURE_SKIP_TLS", self.src)
        self.assertIn("follow_redirects: FOLLOW_REDIRECTS", self.src)

    def test_every_attempt_is_counted_once(self):
        body = self.src[self.src.index("export default function"):self.src.index("export function handleSummary")]
        self.assertEqual(body.count("requestAttempts.add(1, tags)"), 1)
        self.assertEqual(body.count("requestAttempts.add("), 1)
        self.assertEqual(body.count("statusClass[cls].add(1, tags)"), 1)
        self.assertEqual(body.count("statusClass[cls].add("), 1)
        self.assertIn("attemptFailed.add(!ok, tags)", body)
        self.assertIn("attempt_failed: [`rate<${maxErr}`]", self.src)   # threshold per attempt, not per hop

    def test_summary_export_and_only_local_or_k6_imports(self):
        self.assertIn("export function handleSummary(data)", self.src)
        self.assertIn("k6_${RUN_ID}_summary.${stamp}.json", self.src)   # timestamped: no silent overwrite
        imports = re.findall(r"^import .* from '([^']+)';", self.src, flags=re.M)
        self.assertIn("./k6_summary.js", imports)
        self.assertTrue(all(i.startswith("k6") or i == "./k6_summary.js" for i in imports), imports)
        with open(K6_SUMMARY, encoding="utf-8") as f:
            self.assertNotRegex(f.read(), r"^import ", "k6_summary.js must stay free of imports")


@unittest.skipUnless(NODE, "node not installed; JavaScript is not executed")
class K6NodeTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        shutil.copy(K6_SUMMARY, os.path.join(self.dir, "k6_summary.mjs"))
        with open(os.path.join(self.dir, "driver.mjs"), "w", encoding="utf-8") as f:
            f.write(DRIVER)

    def node(self, payload):
        path = os.path.join(self.dir, "input.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        res = subprocess.run([NODE, os.path.join(self.dir, "driver.mjs"), path], capture_output=True,
                             encoding="utf-8", timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(res.stdout)

    def summary(self, data):
        return self.node({"data": data, "config": CONFIG, "ended_utc": "2026-10-26T12:01:30.000Z"})

    def test_syntax_of_both_files(self):
        for src in (K6_SCRIPT, K6_SUMMARY):
            copy = os.path.join(self.dir, "check_" + os.path.basename(src).replace(".js", ".mjs"))
            shutil.copy(src, copy)
            res = subprocess.run([NODE, "--check", copy], capture_output=True, encoding="utf-8", timeout=60)
            self.assertEqual(res.returncode, 0, res.stderr)

    def test_derived_metrics_per_attempt(self):
        # 2xx = 985 x 200 + 5 x 201 (201 is not in success_statuses); absent 1xx/3xx/4xx counters
        out = self.summary(k6_data(attempts=1000, success=985, **{"2xx": 990, "5xx": 6, "transport_error": 4}))
        self.assertTrue(out["valid"], out["invalid_reason"])
        d = out["derived"]
        self.assertEqual((d["attempts"], d["success_responses"], d["transport_errors"]), (1000, 985, 4))
        self.assertEqual(d["non_success_http_responses"], 11)
        self.assertAlmostEqual(d["primary_error_rate"], 0.015)
        self.assertAlmostEqual(d["err5xx_transport_error_rate"], 0.010)
        self.assertAlmostEqual(d["successful_rps_whole_test"], 985 / 90.0)
        self.assertEqual(d["status_class_counts"]["3xx"], 0)
        self.assertEqual(d["latency_success_final_hop_ms"]["p(99)"], 300.0)
        self.assertIsNone(d["latency_success_request_chain_ms"])          # absent trend stays absent
        self.assertEqual(d["k6_http_reqs_including_redirect_hops"], 1040)
        self.assertEqual((out["started_utc_derived"], out["planned_duration_ms"]),
                         ("2026-10-26T12:00:00.000Z", 90000))
        self.assertEqual(out["config"]["run_id"], "K6-T")

    def test_inconsistent_counters_are_invalid_not_zero(self):
        out = self.summary(k6_data(attempts=1000, success=980, **{"2xx": 980}))
        self.assertFalse(out["valid"])
        self.assertIn("do not add up to request_attempts", out["invalid_reason"])
        self.assertIsNone(out["derived"])

    def test_no_attempts_is_invalid(self):
        out = self.summary(k6_data())
        self.assertFalse(out["valid"])
        self.assertIn("no request attempts", out["invalid_reason"])

    def test_early_end_is_invalid(self):
        out = self.summary(k6_data(duration_ms=60000, attempts=10, success=10, **{"2xx": 10}))
        self.assertFalse(out["valid"])
        self.assertIn("ended early: 60000 ms of planned 90000 ms", out["invalid_reason"])

    def test_missing_duration_is_invalid(self):
        data = k6_data(attempts=10, success=10, **{"2xx": 10})
        data["state"] = {}
        out = self.summary(data)
        self.assertFalse(out["valid"])
        self.assertIn("testRunDurationMs missing", out["invalid_reason"])
        self.assertIsNone(out["started_utc_derived"])

    def test_duration_parsing(self):
        self.assertEqual(self.node({"durations": ["30s", "1m30s", "500ms", "1h", "2x", ""]}),
                         [30000, 90000, 500, 3600000, None, None])


STAGES = [{"duration": "30s", "target": 50}, {"duration": "1m", "target": 50}, {"duration": "30s", "target": 200},
          {"duration": "1m", "target": 200}, {"duration": "30s", "target": 0}]   # planned end 210 s


def stage_metrics(label, attempts=None, success=None, transport=None, r5xx=None, first=None, last=None, vmin=None,
                  vmax=None, lat=None):
    """Synthetic stage submetrics as k6 would put them into handleSummary (None = submetric absent)."""
    m = {}
    for name, v in (("request_attempts", attempts), ("responses_success", success),
                    ("responses_transport_error", transport), ("responses_5xx", r5xx)):
        if v is not None:
            m[f"{name}{{stage:{label}}}"] = {"type": "counter", "values": {"count": v, "rate": 0}}
    if first is not None:
        m[f"request_start_elapsed_ms{{stage:{label}}}"] = {"type": "gauge", "values": {"value": last, "min": first,
                                                                                       "max": last}}
    if vmin is not None:
        m[f"vus_at_request_start{{stage:{label}}}"] = {"type": "gauge", "values": {"value": vmax, "min": vmin,
                                                                                   "max": vmax}}
    if lat is not None:
        m[f"success_request_chain_duration{{stage:{label}}}"] = {"type": "trend", "values": lat}
    return m


def full_run_metrics(**overrides):
    """A complete run: ramp 0->50, hold 50, ramp 50->200, hold 200, ramp-down; overall trend values
    deliberately differ from every stage trend (stage percentiles must not come from the overall summary)."""
    parts = {
        "s01_ramp_to_50": dict(attempts=400, success=400, transport=0, r5xx=0, first=5, last=29990, vmin=1, vmax=50,
                               lat={"p(95)": 20.0, "p(99)": 25.0}),
        "s02_hold_50": dict(attempts=3000, success=2970, transport=10, r5xx=20, first=30000, last=89995, vmin=50,
                            vmax=50, lat={"p(95)": 40.0, "p(99)": 55.0}),
        "s03_ramp_to_200": dict(attempts=3500, success=3400, transport=50, r5xx=50, first=90001, last=119990,
                                vmin=50, vmax=200, lat={"p(95)": 90.0, "p(99)": 140.0}),
        "s04_hold_200": dict(attempts=9000, success=8100, transport=300, r5xx=600, first=120000, last=179998,
                             vmin=200, vmax=200, lat={"p(95)": 250.0, "p(99)": 400.0}),
        "s05_ramp_down": dict(attempts=1500, success=1450, transport=20, r5xx=30, first=180000, last=209500,
                              vmin=1, vmax=200, lat={"p(95)": 120.0, "p(99)": 200.0}),
        "after_planned_end": dict(attempts=3, success=3, transport=0, r5xx=0, first=210010, last=210400, vmin=1,
                                  vmax=2, lat={"p(95)": 30.0, "p(99)": 30.0}),
    }
    for label, values in overrides.items():
        if values is None:
            parts.pop(label)
        else:
            parts[label] = dict(parts[label], **values)
    metrics = {}
    for label, values in parts.items():
        metrics.update(stage_metrics(label, **values))
    total = sum(v["attempts"] for v in parts.values() if v.get("attempts") is not None)
    succ = sum(v["success"] for v in parts.values() if v.get("success") is not None)
    metrics.update({"request_attempts": counter(total), "responses_success": counter(succ),
                    "responses_2xx": counter(succ), "responses_5xx": counter(total - succ),
                    "success_request_chain_duration": {"type": "trend", "values": {"p(95)": 999.0, "p(99)": 999.0}}})
    return metrics


class K6StageScriptTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        with open(K6_SCRIPT, encoding="utf-8") as f:
            self.src = f.read()

    def test_every_sample_of_an_attempt_carries_the_start_stage_tag(self):
        body = self.src[self.src.index("export default function"):self.src.index("export function handleSummary")]
        self.assertIn("const elapsed = t0 - exec.scenario.startTime;", body)
        self.assertLess(body.index("stageAt(STAGE_PLAN, elapsed)"), body.index("http.get(TARGET_URL, { tags })"))
        for sample in ("requestStartElapsed.add(elapsed, tags)", "vusAtRequestStart.add(exec.instance.vusActive, tags)",
                       "successResponses.add(1, tags)", "successChain.add(chainMs, tags)"):
            self.assertIn(sample, body)
        self.assertIn("...stageThresholds(STAGE_PLAN), // selector thresholds (always pass)", self.src)
        self.assertIn("import exec from 'k6/execution';", self.src)
        self.assertIn("stage_plan: STAGE_PLAN", self.src)

    def test_one_request_per_iteration_is_the_implemented_scope(self):
        # multi-request sequences (login/browse/download) are a separate, unimplemented scope item
        body = self.src[self.src.index("export default function"):self.src.index("export function handleSummary")]
        self.assertEqual(body.count("http.get("), 1)
        self.assertNotIn("http.post(", body)


@unittest.skipUnless(NODE, "node not installed; JavaScript is not executed")
class K6StageNodeTests(K6NodeTests):
    """Stage plan, thresholds and stage extraction (k6_summary.js executed with node, synthetic data)."""

    test_syntax_of_both_files = None
    test_derived_metrics_per_attempt = test_inconsistent_counters_are_invalid_not_zero = None
    test_no_attempts_is_invalid = test_early_end_is_invalid = test_missing_duration_is_invalid = None
    test_duration_parsing = None

    def plan(self, warmup_ms=0):
        return self.node({"plan": STAGES, "warmup_ms": warmup_ms})

    def stage_summary(self, metrics, duration_ms=212000, warmup_ms=0, tol=2000):
        config = dict(CONFIG, stages=STAGES, stage_plan=self.plan(warmup_ms), stage_evidence_tolerance_ms=tol)
        out = self.node({"data": {"metrics": metrics, "state": {"testRunDurationMs": duration_ms}}, "config": config,
                         "ended_utc": "2026-10-26T12:03:32.000Z"})
        return out, {s["planned"]["label"]: s for s in out["stage_results"]["stages"]}

    def test_plan_kinds_times_and_warmup(self):
        p = self.plan()
        self.assertEqual([(s["label"], s["kind"], s["start_ms"], s["end_ms"]) for s in p],
                         [("s01_ramp_to_50", "ramp", 0, 30000), ("s02_hold_50", "hold", 30000, 90000),
                          ("s03_ramp_to_200", "ramp", 90000, 120000), ("s04_hold_200", "hold", 120000, 180000),
                          ("s05_ramp_down", "ramp_down", 180000, 210000)])
        w = self.plan(10000)
        self.assertEqual([s["label"] for s in w][:3], ["s01_ramp_to_50", "s02_hold_warmup_50", "s02_hold_50"])
        self.assertEqual((w[1]["kind"], w[1]["end_ms"], w[2]["start_ms"]), ("hold_warmup", 40000, 40000))

    def test_boundary_attribution_by_request_start(self):
        labels = self.node({"plan": STAGES, "at": [-1, 0, 29999, 30000, 89999.5, 90000, 209999, 210000, 250000]})
        self.assertEqual(labels, ["s01_ramp_to_50", "s01_ramp_to_50", "s01_ramp_to_50", "s02_hold_50", "s02_hold_50",
                                  "s03_ramp_to_200", "s05_ramp_down", "after_planned_end", "after_planned_end"])

    def test_thresholds_define_every_required_submetric(self):
        th = self.node({"plan": STAGES, "thresholds": True})
        labels = [s["label"] for s in self.plan()] + ["after_planned_end"]
        required = {"request_attempts": "count>=0", "responses_success": "count>=0",
                    "responses_transport_error": "count>=0", "responses_5xx": "count>=0",
                    "success_request_chain_duration": "max>=0", "request_start_elapsed_ms": "value>=0",
                    "vus_at_request_start": "value>=0"}
        self.assertEqual(len(th), len(labels) * len(required))
        for label in labels:
            for metric, selector in required.items():
                self.assertEqual(th[f"{metric}{{stage:{label}}}"], [selector])

    def test_complete_holds_give_constant_vu_results_from_stage_submetrics(self):
        out, st = self.stage_summary(full_run_metrics())
        self.assertTrue(out["stage_results"]["valid"], out["stage_results"]["problems"])
        hold = st["s02_hold_50"]
        self.assertTrue(hold["observed"]["complete"])
        self.assertEqual(hold["derived"]["target_vus_observed"], "maintained_at_request_starts")
        self.assertTrue(hold["derived"]["constant_vu_result"])
        self.assertAlmostEqual(hold["derived"]["successful_rps"], 2970 / 60.0)
        self.assertAlmostEqual(hold["derived"]["primary_error_rate"], 30 / 3000)
        self.assertAlmostEqual(hold["derived"]["err5xx_transport_error_rate"], 30 / 3000)
        self.assertEqual(hold["derived"]["latency_success_request_chain_ms"]["p(99)"], 55.0)   # not the overall 999
        self.assertEqual((hold["planned"]["start_ms"], hold["observed"]["first_request_start_ms"]), (30000, 30000))
        ramp = st["s03_ramp_to_200"]
        self.assertFalse(ramp["derived"]["constant_vu_result"])
        self.assertIsNone(ramp["derived"]["successful_rps"])
        self.assertIn("not constant", ramp["null_reasons"]["successful_rps"])
        self.assertEqual(ramp["counts"]["attempts"], 3500)                 # ramp data reported, not mixed
        after = st["after_planned_end"]
        self.assertEqual((after["planned"]["kind"], after["counts"]["attempts"]), ("after_planned_end", 3))

    def test_absent_stage_submetric_is_zero_only_for_a_complete_stage(self):
        out, st = self.stage_summary(full_run_metrics(after_planned_end=None))
        after = st["after_planned_end"]
        self.assertTrue(after["observed"]["complete"])
        self.assertEqual(after["counts"]["attempts"], 0)
        self.assertIsNone(after["derived"]["primary_error_rate"])
        self.assertEqual(after["null_reasons"]["primary_error_rate"], "no attempts in this stage")
        self.assertIsNone(after["derived"]["latency_success_request_chain_ms"])

    def test_interrupted_run_gives_no_rate_from_the_planned_duration(self):
        metrics = full_run_metrics(s04_hold_200=dict(attempts=4000, success=3600, transport=100, r5xx=300,
                                                     last=150000), s05_ramp_down=None, after_planned_end=None)
        out, st = self.stage_summary(metrics, duration_ms=151000)
        self.assertFalse(out["valid"])                                        # whole-run result: ended early
        hold = st["s04_hold_200"]
        self.assertFalse(hold["observed"]["complete"])
        self.assertEqual(hold["counts"]["attempts"], 4000)                   # observed counts kept
        self.assertIsNone(hold["derived"]["successful_rps"])
        self.assertIn("hold not complete", hold["null_reasons"]["successful_rps"])
        self.assertIsNone(st["s05_ramp_down"]["counts"]["attempts"])        # no zero for an incomplete stage
        self.assertIn("not complete", st["s05_ramp_down"]["null_reasons"]["attempts"])
        self.assertFalse(st["s02_hold_50"]["observed"]["complete"])         # run ended early: nothing complete
        self.assertIsNone(st["s02_hold_50"]["derived"]["successful_rps"])

    def test_target_vus_not_maintained_is_not_a_constant_vu_result(self):
        out, st = self.stage_summary(full_run_metrics(s04_hold_200=dict(vmin=187)))
        hold = st["s04_hold_200"]
        self.assertEqual(hold["derived"]["target_vus_observed"], "not_maintained")
        self.assertFalse(hold["derived"]["constant_vu_result"])
        self.assertIsNone(hold["derived"]["successful_rps"])
        self.assertIn("target VU count not observed", hold["null_reasons"]["successful_rps"])

    def test_stage_sums_must_match_request_attempts(self):
        metrics = full_run_metrics()
        metrics["request_attempts"] = counter(metrics["request_attempts"]["values"]["count"] + 7)
        out, st = self.stage_summary(metrics)
        self.assertFalse(out["stage_results"]["valid"])
        self.assertIn("do not add up", out["stage_results"]["problems"][0])
        self.assertFalse(st["s02_hold_50"]["derived"]["constant_vu_result"])

    def test_stage_not_passed_by_observed_requests_is_incomplete(self):
        metrics = full_run_metrics(s05_ramp_down=None, after_planned_end=None,
                                   s04_hold_200=dict(last=170000))       # last start 10 s before the hold end
        out, st = self.stage_summary(metrics)
        self.assertFalse(st["s04_hold_200"]["observed"]["complete"])
        self.assertIn("no request start observed", st["s04_hold_200"]["observed"]["complete_reason"])
        self.assertTrue(st["s02_hold_50"]["observed"]["complete"])

if __name__ == "__main__":
    unittest.main()
