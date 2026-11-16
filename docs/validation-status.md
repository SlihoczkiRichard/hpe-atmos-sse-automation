# Validation status

**State: offline development and testing complete for modules 00–05; live runs of Experiments 1–4 performed (see below).**

Offline tests and dry-runs check the code's logic, file formats and safety rules against simulated
clocks, mocked SSH/HTTP/API and synthetic data. They do not show that the tools behave correctly
against the real ESXi hosts, connector VMs, Atmos Admin API or SSE data path. Figures produced from
dry-run data carry the watermark *SIMULATED – NOT A REAL MEASUREMENT* and are not experimental
results.

## Offline checks completed

- **Test suite:** `python -m unittest discover -s tests`, last run with Python 3.13 on Windows 11 (PowerShell and Git Bash parent shells):
  - 394 entries counted by unittest (including the skipped class below as 1 entry): 393 passed, 0 failed, 1 skipped;
  - one test class skipped by design: the native-POSIX telemetry tests (7 tests) do not apply on Windows; the same script tests ran under Git Bash and WSL.
- **Network guard:** active from before any module under test is imported. Socket connects, name resolution and paramiko SSH connects fail the test.
- **Covered by the tests:**
  - 01: hey report parsing, acceptance rule, invalid runs (no zero substitution); k6 summary derivation (executed with node); k6 stage plan, boundary attribution by request start, generated selector thresholds and stage extraction (complete / interrupted / not-maintained holds, absent submetrics, sum mismatch; executed with node on synthetic summary data); iperf3 parsing; telemetry script coverage states (really executed by Bash).
  - 02: `/proc/stat` field rules, sample-time windows and decision-time conditions, non-blocking power-on tracking, power-on attribution and scale-in gating, SSH success separated from CPU validity, `known_hosts` error handling, secret redaction.
  - 03: probe error classes, persistent probe never reconnecting (real `http.client` over a fake socket), outage and recovery rules, baseline rule, marker and clock-domain rules, no overwriting.
  - 04: URLhaus parsing and selection, Swagger contract of the used operations, writable-field payloads, paging checks, uncertain-write reconciliation, restore conflict, canary sequence, signed latency offsets, probes continuing during API calls (real thread, simulated components); canary snapshot saved and closed before the first write, snapshot failure preventing the write, restore from the saved snapshot after an exception or interruption, structured redacted worker errors (inline and threaded worker) kept apart from API outcomes and the restore result, incomplete finalisation.
  - 05: sadf CPU and memory and k6-raw adapters (incl. duplicates, overlaps, stage tags), resource windows per hey run (interval containment, warm-up, coverage bounded by 100 %, partial windows kept out of level medians), k6 stage figure (constant-VU holds only), figure computations, provenance rules, issue severities, no overwriting, untouched inputs.
- **Dry-runs:** every module's dry-run, and a full simulated processing run producing figures for all four experiments.
- **`lab.py`:** `tests/test_lab.py` (plan arithmetic, remote command construction, time-sync parsing, spec building, the E1 call sequence against a fake shell); `lab.py e1 --dry-run` and `lab.py e3 --dry-run` end to end; one E3 repetition against a local HTTP server with markers typed during the run; the remote telemetry start/export commands executed in bash with stand-in `sar`/`sadf`. `lab.py e1` has run against the testbed (see below).

## Live checks performed

- **Experiment 1 (`hey`, closed loop, through the SSE path):** `lab.py e1` end to end on the testbed: C1 `sar` telemetry over SSH, client `sar`, the stepped `hey` run, exports, time-sync records and processing with the `load_capacity` figure. Runs: E1-20261103-01 (`10..1000`, no saturation), E1-20261106-T1 (`1000..6000`, range finding), E1-20261106-01 (`400,800,1000,1200,2000,4000`, limit at c = 1200, 3650 1/s), E1-20261106-T2 (`1000..2000`, peak at c = 1400, 4034 1/s, consistent across three sweeps). The real `hey` report format, `sadf -d -- -u ALL` / `-r` exports and the pre-run target check (HTTP 200 required; a stopped backend gave 100 % HTTP 502) are confirmed by these runs. Capacity run E1-20261106-02 (`400,1000,1400,1600,2000,4000`, 3 × 60 s per level): highest median successful throughput 3888.5 1/s at c = 1400 (capacity limit under the predefined rule); only c = 4000 failed the error-rate criterion.
- **Experiment 2 (`lab.py e2`, `vcenter-api` backend):** `00-preflight --run` (vCenter login with the power-only user, VM lookup by name, power state) and five repetitions E2-20261112-01 … -05 plus the trial E2-20261112-T0, code `1d40ba5`. Confirmed live: the scaler trigger on real C1 `/proc/stat` samples, the vCenter `power?action=start` call and power-state polling, guest SSH reachability, and the Admin API `Available` status of C2. From `POWER_ON_SENT`, median (range, n = 5): VM powered on 4.9 s (4.8-5.2), guest SSH 27.3 s (26.1-28.0), C2 traffic in the backend's nginx log at most 98.2 s (78.1-103.0), portal Available 129.4 s (122.6-148.6). Load: `hey` c = 1400, 5 × 120 s (one 600 s step exceeds `hey`'s 1,000,000-result buffer). With a single client the SSE edge keeps existing connections on C1 and sends new ones to C2; per-connection balancing over both connectors was not observed.
- **Experiment 3 (`lab.py e3`):** five valid repetitions E3-20261109-CAL2, -r03, E3-20261114-r04 … -r06 (fault: vNIC of the traffic-carrying C2 disconnected), controls E3-20261109-T0 (no fault) and -r01 (idle C1 disconnected, 0 failures). The http probe's first success after the fault comes at a median of +301.5 s (294.7-303.8 s), failure span 299.1 s (292.2-301.4 s); the persistent connection breaks 4-5 s after the fault; no failures after recovery. Confirmed live: the static endpoint `/e3/probe.txt` with token check, chunked responses through the edge, and that the edge closes a keep-alive connection after 1000 requests (hence `FAILOVER_PERSISTENT_INTERVAL_MS=800`). The 11-09 runs recorded commit `5d18f0d`, an earlier version of `1d40ba5` with identical `03-failover/` and `lab.py`.
- **Experiment 4 (`04-threat-intel/`):** synchronisation E4-20261114-P0, -P1, -01 (`apply --commit none`), -P2 on SR-BENCHMARK-CLI with an URLhaus export (Auth-Key) and an exclusion file: 25 hosts written to a new tagged category, the second plan is empty (idempotent), and an untagged category with the default name was refused as `foreign_category`. Canary on a Windows client with the SSE agent: `validate-signature` E4-20261116-SIG3 (5/5, 403 + block-page text) and five valid runs E4-20261116-c05 … -c09. Confirmed live: category `GET`/`PUT` without the read-only `type` field, `POST /Commit` (204) putting the change into effect, the real block page, restore from the run's own snapshot and the restore Commit. First blocked probe after the Commit response: 0.48, 0.66 and 1.03 s (c06–c08, back-to-back), 680 s (c09, after a 2.6 h pause); c05 (manual Apply Changes) about 610 s after the Apply. Access returned 6.7–14.8 s after the restore. Invalid runs: c01–c02 (`*.github.io` is not inspected by the rule), c03 (600 s window shorter than the cold delay), c04 (interrupted).

## Live checks not yet performed

- **Experiment 1:**
  - real `k6` runs through the SSE path (`hey` has run, see above);
  - real report formats of the installed versions;
  - `hey -disable-redirects` availability;
  - k6 behaviour of `http_reqs` / `http_req_failed` with redirects;
  - real iperf3 JSON;
  - whether iperf3 traffic actually uses the SSE path.
- **Telemetry:** `sar` on the connector VMs, `sar -F` support, signal handling, and real `sadf -d -- -u ALL` and `sadf -d -- -r` exports (with `sadf -V`), to confirm:
  - the headers;
  - the meaning of `%memused` for that sysstat version;
  - the temporal interpretation used by the adapters (CPU = average over `[t - interval, t]`, memory = reading at `t`).
- **k6 stage results:** one real run of `k6_workload.js` (record `k6 version`), to confirm:
  - that `exec.scenario.startTime` and `exec.instance.vusActive` are available;
  - that the tagged stage submetrics appear in `handleSummary` through the selector thresholds;
  - that `testRunDurationMs` and the stage timeline agree well enough for the completeness tolerance.
- **Experiment 2:**
  - real `vim-cmd` timing and power-state updates with the `esxi-ssh` backend (the live runs used `vcenter-api`);
  - the vCenter 6.x `/rest` dialect (tested offline only);
  - `/proc/stat` behaviour of the connector kernel (iowait/idle accounting);
  - the meaning of steal under ESXi;
  - the Admin API's own status timestamps (the live runs use the time the scaler first saw `Available`).
- **Experiment 3:**
  - the achievable probe interval under load (the live runs had no parallel load);
  - the shared clock domain of markers and probes on Windows.
- **Experiment 4:**
  - the scope of `POST /Commit` (whether it applies other administrators' pending changes; every run started with an empty pending list);
  - the cause of the two blocking-delay regimes (about 1 s vs. 610–680 s);
  - API acceptance of an empty test category;
  - the 404 semantics of an empty category listing;
  - the keyless `--fetch` download (HTTP 410 now; the runs used an Auth-Key export with `--feed-file`);
  - whether `category_snapshot.json` survives an abrupt power-off on the client's file system (fsync covers the file data only).
- **Processing:** with real data, especially a real k6 raw JSON file and sadf exports.

## Operator prerequisites

- A complete `.env` (no template placeholders) for the live modes, started from the repository root.
- SSH host keys of C1, C2 and the ESXi host in `known_hosts` (or `SSH_KNOWN_HOSTS`).
- Experiment 1:
  - `hey`, `k6` and `iperf3` installed on the client;
  - iperf3 servers started by hand;
  - `sysstat` on the VMs;
  - synchronised VM clocks if telemetry coverage is to be judged.
- Experiment 2: the secondary connector VM pre-configured on its ESXi host (it is powered on, not cloned).
- Experiment 3:
  - a static HTTP endpoint with a unique token, an expected status, no redirect and `Content-Length` or chunked encoding;
  - known backend keep-alive timeout and request limit;
  - a TLS chain trusted by the client;
  - evidence that the probes use the SSE path;
  - markers written on the probe machine.
- Experiment 4:
  - an own canary host and a separate, permanently blocked reference host;
  - a dedicated test category assigned **by hand** to a blocking SWG rule, without the canary host in it;
  - the SWG CA in `HTTP_CA_BUNDLE` if TLS is inspected;
  - an explicit `--commit none|after-update` choice.
- Experiment 2 application view: an operator time-sync statement (`time_sync` in the 05 spec) for combining data of different machines.

## Known limitations

- **Experiment 1:**
  - hey does not verify TLS, and its latency percentiles cover all HTTP responses, not only successful ones;
  - stage results are attributed by request start; VU counts are observed at request starts only;
  - each k6 iteration sends one `GET`; multi-request sequences (login / browse / download) are a separate, unimplemented scope item;
  - the resource figure shows load and resource use in the same windows; it does not establish a connector bottleneck;
  - an accepted capacity level is an acceptance result for the tested levels, not a physical saturation point.
- **Output protection, best-effort parts:**
  - hey, iperf3 and the telemetry script refuse existing results of a `RUN_ID`;
  - the k6 summary uses a millisecond-timestamped name because k6 cannot create files exclusively;
  - the k6 `--out json` file is overwritten if its name is reused; only a launcher wrapper could prevent that, and none is included;
  - the telemetry check cannot cover a second collector started at the same moment;
  - interruption handling covers Ctrl+C and, where delivered, SIGTERM; a hard kill leaves no manifest.
- **Scaler:**
  - no observe-only mode;
  - the scale-in shutdown is still followed by blocking polling (scale-in is disabled in the main experiment);
  - `POWER_STATE_POLL_SEC` is a target interval, not a guaranteed resolution;
  - its outputs carry no `RUN_ID` or provenance field;
  - the cited sources of the `/proc/stat` field rules still have to be checked against the kernel documentation.
- **Failover:**
  - `failure_span_ms` and `bracket_interval_ms` are observations derived from probe start and end times, not proven bounds and not an internal tunnel convergence time;
  - the marker is an operator signal;
  - the persistent-probe analysis does not list the marker it used (05 re-selects it with the 03 rule).
- **Threat intel:**
  - reducing URLs to hosts blocks more than the listed URLs;
  - the exclusion list is not a general over-blocking protection;
  - the managed-by tag is a naming convention, not an API permission;
  - equal counts while paging do not prove that the listing did not change;
  - the blocking latency is the delay perceived by the probes of one client, measured from the category update, not from the appearance of an indicator in the feed;
  - some hosts (e.g. `*.github.io`) are not inspected by the rule and cannot serve as a canary; check the certificate issuer inside the category first;
  - the canary dry-run executes API steps inline;
  - the canary snapshot protects against interruptions, exceptions and kills after it was saved, not against every power-loss, hard-kill or storage-failure case.
- **Processing:**
  - only the `sadf -d` CPU (`-u ALL` / `-u`) and memory (`-r`) exports are supported (not the sar text output);
  - `cpu_busy_excl_iowait_pct` uses the scaler's formula but another tool and interval: comparable, not identical to the scaler's CPU value;
  - the k6 raw adapter is implemented from the k6 documentation and still needs a real sample;
  - cross-machine views depend on the operator's time-sync statement, which the processor does not verify.

## Unresolved API and environment questions

Answered by the Experiment 4 runs (see *Live checks performed*): a WebCategory `PUT` without `type` is
accepted; `POST /Commit` puts a category change into effect; the category is assigned to a blocking
SWG rule by hand in the portal (Policy → Rules); the block page is an HTTP 403 page of about 172 KB,
and only traffic matching the blocking rule is TLS-inspected. Still open:

1. Does `POST /Commit` also apply other administrators' pending changes?
2. What causes the two blocking-delay regimes (about 1 s vs. 610–680 s)?
3. Is an empty custom category accepted?
4. Exact ESXi version of the hosts (sources disagree; `00-preflight --run` records `vmware -v`).
5. Does `sar -F` work on the connector VMs (the `sadf -d -- -u ALL` / `-r` exports were confirmed in E1)?
