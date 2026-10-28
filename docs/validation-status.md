# Validation status

**State: offline development and testing complete for modules 00–05; no live validation yet.**

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

## Live checks not yet performed

- **Preflight:** `00-preflight --run` against the testbed.
- **Experiment 1:**
  - real `hey` and `k6` runs through the SSE path;
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
  - real `vim-cmd` timing and power-state updates;
  - SSH host keys;
  - `/proc/stat` behaviour of the connector kernel (iowait/idle accounting);
  - the meaning of steal under ESXi;
  - Admin API connector-status timestamps.
- **Experiment 3:**
  - the static endpoint and its keep-alive behaviour;
  - the achievable probe interval under load and during faults;
  - the shared clock domain of markers and probes on Windows.
- **Experiment 4:**
  - a write without the read-only `type` field;
  - the necessity and scope of `POST /Commit`;
  - API acceptance of an empty test category;
  - the real block page and the `validate-signature` run against the reference host;
  - the 404 semantics of an empty category listing;
  - the URLhaus download;
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
  - a static HTTP endpoint with a unique token, an expected status, no redirect and `Content-Length`;
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
  - the blocking latency is the delay perceived by the probes;
  - the canary dry-run executes API steps inline;
  - the canary snapshot protects against interruptions, exceptions and kills after it was saved, not against every power-loss, hard-kill or storage-failure case.
- **Processing:**
  - only the `sadf -d` CPU (`-u ALL` / `-u`) and memory (`-r`) exports are supported (not the sar text output);
  - `cpu_busy_excl_iowait_pct` uses the scaler's formula but another tool and interval: comparable, not identical to the scaler's CPU value;
  - the k6 raw adapter is implemented from the k6 documentation and still needs a real sample;
  - cross-machine views depend on the operator's time-sync statement, which the processor does not verify.

## Unresolved API and environment questions

1. Does the Admin API accept a WebCategory write without `type` (the Swagger marks it both required and readOnly)?
2. Is `POST /Commit` needed for a category change to take effect, and does it apply other pending changes?
3. Is an empty custom category accepted?
4. How is the category assigned to a blocking SWG rule (no rule operation in the Swagger)?
5. What does the real SWG block page look like, and is TLS inspected?
6. Exact ESXi version of the hosts (sources disagree; `00-preflight --run` records `vmware -v`).
7. Do `sar -F` and `sadf -d` on the connector VMs produce the expected formats?
