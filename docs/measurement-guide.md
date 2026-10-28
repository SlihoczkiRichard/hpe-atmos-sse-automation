# Measurement guide

How to run the tools on the testbed. The commands below are the ones the code actually supports
(see `--help` of each entry point). Nothing in this guide has been executed against the real
testbed yet; start with the [pilot procedure](#pilot-procedure-low-load-single-connector) and read
[validation-status.md](validation-status.md) first.

## Machines and roles

| Machine | Runs | Needs |
|---|---|---|
| **Control host** | `00-preflight`, `02-scaler-poc`, `04-threat-intel` sync mode, `05-results` | SSH to C1, C2 and the ESXi host; HTTPS to the Admin API; `known_hosts` entries |
| **Client / load generator** (traffic goes through the SSE path) | `hey`, `k6`, `iperf3` client, `03-failover` probes and markers, `04` canary mode | `hey`, `k6`, `iperf3`; for the canary: web traffic through the SWG and the SWG CA trusted if TLS is inspected |
| **Connector VMs** C1 and C2 | `01-load-test/collect_connector_telemetry.sh`, `sadf` export | `sysstat` (`sar`, `sadf`) |
| **iperf3 servers** | `iperf3 -s`, started by the operator | listening on the configured host and port; the tools never start servers or open ports |

The control host and the client may be the same machine. **Failover markers must be written on
the machine that runs the failover probes** (same clock domain). Data of different machines is only
combined in `05-results` on UTC, with an operator time-sync statement.

## Configuration and RUN_ID

1. `cp .env.example .env` and fill in every value that the experiment uses. `--help` and
   `--dry-run` never read `.env`; a live mode reports an unusable value (for example a non-numeric
   `CONNECTOR_2_VMID`) when it parses that value, and does not start.
2. Secrets (`CONNECTOR_SSH_PASSWORD`, `CONNECTOR_2_SSH_PASSWORD`, `ESXI_PASSWORD`, `ATMOS_API_KEY`)
   are read from the environment only.
3. Start the Python tools from the repository root; they load `.env` from there.
4. Choose a `RUN_ID` per measurement run (letters, digits, `.`, `_`, `-`; at most 80 characters),
   for example `E1-20261101-01`. Pass the **same** `RUN_ID` to every tool of that run (`--run-id` or
   `RUN_ID=` in the environment; for k6 `-e RUN_ID=`).
5. **Use a new `RUN_ID` for every new run of `run_hey_stepped.py`, `run_iperf3_comparison.py`, k6
   and the telemetry script.** hey, iperf3 and the telemetry script refuse to start (exit code 2)
   if results of the same `RUN_ID` exist; they never overwrite. The k6 summary carries a millisecond
   timestamp in its name (best effort, see below). Modules 03, 04 and 05 never overwrite; they add
   `.attemptN` or `.revN`.
6. Default output directories: `<module>/results/` (excluded by `.gitignore`); `05-results` writes
   to `05-results/processed/`.

## Experiment 1 – capacity and load tolerance

### hey (client)

```bash
python 01-load-test/run_hey_stepped.py --run-id E1-20261101-01 \
    --url "$TARGET_APP_URL" --steps 10,25,50,100 --sweeps 3 --duration 30s
```

- **Success:** only the `SUCCESS_STATUSES` codes count as success (default `200`).
- **Acceptance:** a concurrency level is accepted only if all three sweeps are valid and each has a primary error rate strictly below `ACCEPT_MAX_ERROR_RATE` (default `0.01`).
- **TLS:** hey does not verify certificates.
- **Redirects:** use `--no-follow-redirects` to count a 3xx response as non-success.
- **Outputs:** `01-load-test/results/<RUN_ID>/{runs.csv,levels.csv,manifest.json,raw/}`. Existing
  results of the same `RUN_ID` → refused (exit code 2). Interrupted → manifest status `interrupted`
  (exit code 3).

### k6 (client)

k6 does not read `.env`; pass the variables with `-e`. The summary directory must exist.

```bash
mkdir -p 01-load-test/results/k6
k6 run -e RUN_ID=E1-20261101-02 -e TARGET_APP_URL="$TARGET_APP_URL" \
       -e STAGE_VUS="10,50,100" -e RAMP_DURATION=30s -e HOLD_DURATION=1m \
       -e K6_RESULTS_DIR=01-load-test/results/k6 \
       --out json=01-load-test/results/k6/k6_E1-20261101-02_raw.json \
       01-load-test/k6_workload.js
```

- **Summary:** `k6_<RUN_ID>_summary.<UTC timestamp>.json` holds the whole-test result (`derived`) and,
  separately, per-stage results (`stage_results`). Overwrite protection is best effort: k6 cannot create files exclusively, so the name
  carries the end time in milliseconds. The `--out json` file is written by k6 itself and **is
  overwritten if its name is reused**; only a launcher that checks the path before starting k6
  could prevent that, and none is included. Always use a new `RUN_ID` and file name.
- **Raw JSON:** the `--out json` file is needed for time-resolved application data in experiment 2. `05-results` reads it with the k6 raw adapter.
- **Variables:**
  - `SUCCESS_STATUSES`, `LOAD_FOLLOW_REDIRECTS`, `K6_INSECURE_SKIP_TLS` (default `false`, TLS verified);
  - `THINK_TIME_SEC`, `TREND_STATS`, `ACCEPT_MAX_ERROR_RATE`;
  - `K6_TARGET_PERCENTILE_1/2`, `K6_LIMIT_MS_1/2` (SLA-style thresholds);
  - `HOLD_WARMUP` (default `0s`): the first part of every hold is reported as its own `hold_warmup`
    stage and excluded from the hold result; `STAGE_EVIDENCE_TOLERANCE_MS` (default `2000`).
- **Stage results (`stage_results`):**
  - every request attempt is tagged with the planned stage in which it **started** (elapsed time since
    `exec.scenario.startTime`); a request crossing a boundary belongs to its start stage;
  - stage kinds: `ramp`, `hold`, `hold_warmup`, `ramp_down`, and `after_planned_end` (graceful
    ramp-down / stop; reported, never dropped);
  - planned times (`planned`) and observed evidence (`observed`: first/last request start, VUs active
    at request starts, completeness) are separate. A stage is complete only if the run did not end
    early and a request start was observed at or after the stage end minus the tolerance;
  - `successful_rps` = successful attempts started in the hold / hold duration, only for a complete
    hold whose observed VU count at every request start equals the target (`constant_vu_result`);
    ramps get no constant-VU rate. Undefined values are `null` with a reason in `null_reasons`;
  - the thresholds named `...{stage:...}` always pass. They only make k6 report the stage submetrics
    in `handleSummary` and are **not** SLA or acceptance criteria;
  - not yet seen with a real k6 run: record `k6 version` and check that `stage_results` contains
    the submetrics (see `docs/validation-status.md`, live checks).
- **Scope:** each iteration sends **one** `GET` to `TARGET_APP_URL` followed by `THINK_TIME_SEC`.
  Multi-request sequences (for example login / browse / download) are **not implemented**; this is a
  separate scope item, and the stage results do not replace it.

### iperf3 (client; the servers must already be listening)

```bash
python 01-load-test/run_iperf3_comparison.py --run-id E1-20261101-03 \
    --path direct=<backend-ip> --path sse=<sse-app-host> --repetitions 3
```

- **Path labels:** the labels are configuration only, so `path_verification` is `not_verified`. Add `--path-evidence sse="<what you checked>"` only after you have actually verified the path (then `operator_asserted`).
- **Metrics:** retransmits are reported as sender TCP retransmits, not packet loss.
- **Collisions / interruption:** as for hey (refused with exit code 2; interrupted → status
  `interrupted`, exit code 3).

### Connector-VM telemetry (on C1 and C2)

Copy `01-load-test/collect_connector_telemetry.sh` to each VM and start it before the load.
`RUN_START_EPOCH` is the start of the whole run (same value on every host). It is compared with
the VM's own clock, so the VM clocks must be synchronised for the coverage result to be meaningful.

```bash
RUN_ID=E1-20261101-01 ROLE=c1 RUN_START_EPOCH=<epoch> COVERAGE_TOLERANCE_SEC=5 \
    bash collect_connector_telemetry.sh 600 1 ./telemetry
```

- **Arguments:** `duration_sec`, `interval_sec`, `output_dir`.
- **Coverage in the metadata:** `full_from_run_start`, `partial_late_start`, `partial_early_end`, `partial_interrupted`, `invalid_sar_failed` or `unknown_run_start`.
- **Exit code:** 1 if `sar` failed or the script was interrupted, 2 for input errors or when
  `telemetry_<RUN_ID>_<ROLE>_<host>*` files already exist (nothing is overwritten; best effort
  against a second collector started at the same moment, because `sar` creates its `.sa` file itself).

**Supported CPU and memory exports for `05-results` (run on the VM after collection):**

```bash
sadf -d telemetry_<RUN_ID>_<ROLE>_<host>.sa -- -u ALL > telemetry_<RUN_ID>_<ROLE>_<host>_cpu_sadf.csv
sadf -d telemetry_<RUN_ID>_<ROLE>_<host>.sa -- -r     > telemetry_<RUN_ID>_<ROLE>_<host>_mem_sadf.csv
sadf -V    # record the sysstat version
```

Only these `sadf -d` exports (UTC timestamps; CPU: `-u ALL` or `-u` columns; memory: `-r` with
`kbmemfree`, `kbmemused`, `%memused`, optionally `kbavail`) are supported.

CPU values keep every component (`usr_pct`, `sys_pct`, `iowait_pct`, `steal_pct`, `soft_pct`, ...)
and two derived values with different formulas: `cpu_not_idle_pct = 100 - %idle` and
`cpu_busy_excl_iowait_pct = 100 - %idle - %iowait`. Only the second uses the scaler's formula (iowait
counted as idle); it is comparable with the scaler's CPU value, not identical (other tool, other
interval). `mem_used_pct` is sysstat's own `%memused`, whose definition depends on the sysstat
version. Interpretation used until a real export confirms it: a CPU record is the average over
`[t - interval, t]`, a memory record is a reading at `t`. The
`*_sar.txt` text output is not parsed. Copy all telemetry files (including `*_meta.json`) back,
for example into `01-load-test/results/<RUN_ID>/telemetry/`.

## Experiment 2 – CPU-threshold activation (control host)

Always test the configuration with the simulated mode first:

```bash
python 02-scaler-poc/scaler_daemon.py --dry-run --max-cycles 40
```

Live run, with scale-in disabled (the default):

```bash
python 02-scaler-poc/scaler_daemon.py --scale-out-pct 80 --window-sec 15 --poll-sec 5 \
    --power-on-timeout-sec 60 --cooldown-sec 60
```

- **Side effect:** the live mode **powers on the C2 VM** on the ESXi host when C1's CPU stays at or above the threshold for the trigger window. There is no observe-only mode.
- **Further checks:** `--target-url`, `--c2-connector-id` (with `ATMOS_API_KEY`) and `--c2-connection-check ss-established` add readiness checks. Each check is reported with its own status.
- **Scale-in:** `--enable-scale-in` enables ACPI shutdown. Only a C2 whose power-on the scaler confirmed is shut down, unless `--allow-scale-in-manual-c2` is given. `--allow-force-power-off` enables a hard power-off.
- **Lab flags:** `--lab-insecure-ssh` and `--lab-insecure-tls` weaken verification and are logged.
- **Outputs:** `02-scaler-poc/results/scaler_<timestamp>_{timeseries,events,errors}.csv`. They contain no `RUN_ID`; note the file prefix and assign the `RUN_ID` in the 05 spec.

## Experiment 3 – availability and recovery (client)

Start one process per probe type in separate terminals, with the same `RUN_ID`, at least the
baseline time (30 s) before the fault:

```bash
python 03-failover/failover_probe.py run --probe tcp  --run-id E3-20261101-01 --tcp-host <host> --tcp-port 443 --duration-sec 300
python 03-failover/failover_probe.py run --probe http --run-id E3-20261101-01 --http-url https://<app>/<static-path> --expect-body <token> --duration-sec 300
python 03-failover/failover_probe.py run --probe persistent --run-id E3-20261101-01 --http-url https://<app>/<static-path> --expect-body <token> --duration-sec 300
```

Inject the fault by hand (for example stop the C1 connector) and record it **on the same machine**:

```bash
python 03-failover/failover_probe.py mark --run-id E3-20261101-01 --kind fault_injected --note "C1 stopped by hand"
```

After the runs:

```bash
python 03-failover/failover_probe.py analyze --run-id E3-20261101-01 --probe tcp
python 03-failover/failover_probe.py analyze --run-id E3-20261101-01 --probe http
python 03-failover/failover_probe.py analyze --run-id E3-20261101-01 --probe persistent
```

- **Defaults:** 50 ms target interval (not a guaranteed resolution), TCP timeout 250 ms, HTTP timeout 1000 ms, N = 10 successes for stable recovery, 30 s baseline.
- **HTTP probe:** it needs a content check (`--expect-body` and/or `--expect-regex`).
- **Persistent probe:** the endpoint must send `Content-Length`.
- **Marker:** it is an operator signal, not proof of the failure time.

## Experiment 4 – threat intelligence and perceived blocking delay

### Indicator synchronisation (control host)

```bash
python 04-threat-intel/sync_threat_intel.py plan  --run-id E4-20261101-01 --feed-file <saved-csv>   # or --fetch
python 04-threat-intel/sync_threat_intel.py plan  --run-id E4-20261101-01 --fetch --read-api       # read-only comparison
python 04-threat-intel/sync_threat_intel.py apply --run-id E4-20261101-01 --fetch --commit after-update
python 04-threat-intel/sync_threat_intel.py restore --run-id E4-20261101-01 \
    --snapshot 04-threat-intel/results/E4-20261101-01/sync_apply/category_snapshot.json --commit after-update
```

- **`--commit`:** mandatory for `apply` and `restore`. Whether the Commit is needed, and whether it also applies other pending changes of the tenant, is not validated.
- **Indicators:** at most 25 hosts by default, chosen by a deterministic rule. IP indicators are only saved.
- **Rule assignment:** assigning the category to a blocking SWG rule is a manual step.

### Canary experiment (client whose web traffic goes through the SWG)

Prerequisites:
- an own canary host serving a unique token;
- an own reference host that is permanently blocked;
- a dedicated test category assigned **by hand** to a blocking rule, **without** the canary host in it.

```bash
python 04-threat-intel/canary_block_test.py validate-signature --run-id E4-20261101-02 \
    --reference-url https://<reference-host>/ --block-body-regex "<text of the block page>"
python 04-threat-intel/canary_block_test.py run --run-id E4-20261101-02 --repetition 1 \
    --canary-url https://<canary-host>/canary.txt --canary-token <token> \
    --category-id <id> --category-name <name> --block-body-regex "<text of the block page>" \
    --signature-file 04-threat-intel/results/E4-20261101-02/signature/signature_validation.json \
    --commit after-update
```

- **Sequence:** baseline (30 s) → add the canary to the test category → optional Commit → observe until 10 consecutive blocked probes (or 600 s) → restore → wait for 10 consecutive reachable probes.
- **Safety:** a 403, timeout, TLS or DNS error alone is never counted as blocking.

Restore the test category from a canary run's own snapshot (for example after an interrupted run):

```bash
python 04-threat-intel/canary_block_test.py restore --run-id E4-20261101-02 \
    --snapshot 04-threat-intel/results/E4-20261101-02/canary/category_snapshot.json \
    --category-id <id> --category-name <name> --commit after-update
```

`category_snapshot.json` is written, fsync'ed and closed **before** the first category write. It
contains the pre-check state and the exact payload about to be sent. If it cannot be saved, the run
writes nothing (`not_started_snapshot_failed`). This protects an interruption, exception or kill after
the snapshot was saved. It does not guarantee recovery after a power loss or OS crash (whether the
file's directory entry survives depends on the file system), a storage failure, or a write that was
in flight when the process died. In that last case the restore below stops on its checks.

The run's `summary.json` and `manifest.json` keep four layers apart:
- `execution_errors`: exceptions in an API job, redacted (type and message only);
- `api_outcomes`: raw HTTP write outcomes and the GET-only reconciliation;
- `apply_state`;
- `restore_state`.

If the API worker is still running at exit, or a finalisation step fails, `finalisation.status` is
`incomplete` and the run is not valid.

The category id and name must match the snapshot. The command writes only if the category still
equals what the run wrote:
- if the category already equals the snapshot: `restore_not_needed`;
- if anything else changed: `restore_conflict`, nothing is written, and manual recovery data is in `result.json`;
- a timeout or other uncertain outcome is never retried: `restore_uncertain`, exit code 4.

The command never deletes anything. It restores the category only; check the access to the canary
separately.

## Result processing (control host)

```bash
python 05-results/process_results.py scan --root 01-load-test/results --root 02-scaler-poc/results \
    --root 03-failover/results --root 04-threat-intel/results --out spec_draft.json
# review and edit the spec, then:
python 05-results/process_results.py process --spec spec_reviewed.json
```

Review the spec before processing:

- set `processing_id` and `"reviewed_by_operator": true`;
- set `provenance` for every dataset: `simulated`, `real` or `unknown`. Tool metadata that says
  simulated or measurement must agree with it. Telemetry, sadf, k6 raw, sync and scaler outputs
  carry no provenance and need your classification. One processing run must not mix provenances;
- set `run_id` for every scaler dataset;
- add the k6 raw file by hand: `{"id": "...", "kind": "k6_raw", "path": "...", "provenance": "..."}`;
- for connector resources per hey level (experiment 1), add
  `"groups": {"m1_resources": [{"hey": "<hey id>", "sar_cpu": "<id>", "sar_mem": "<id>", "warmup_sec": 0,
  "min_coverage": 0.9}]}` and the `time_sync` statement (hey and sar run on different machines).
  `warmup_sec` must be set explicitly (`0` = whole hey run interval). Each hey run's window is
  `[started_utc + warmup_sec, ended_utc]`. A CPU record counts only if its whole interval lies inside
  the window, a memory reading if its time does; duplicates and overlapping records are excluded, so
  coverage cannot exceed 100 %. CPU and memory coverage are reported separately. The level medians
  use only hey-valid runs with a complete window (coverage ≥ `min_coverage`); partial and missing
  windows stay in `m1_resources_by_run_<n>.csv` and are counted per level. The figure shows load and
  resource use side by side; it does not establish a bottleneck;
- for the application-performance view of experiment 2, add
  `"groups": {"m2": [{"scaler": "<id>", "app": ["<hey id>", "<k6_raw id>"]}]}` and a
  `"time_sync": {"statement": ..., "source": ..., "known_uncertainty": ...}` statement. This is
  your claim about clock synchronisation; the processor does not verify it, and there is no default.

The output directory contains PNG and PDF figures, the CSV behind each figure and
`processing_manifest.json`, which lists the inputs (with sha256), issues, produced and skipped
figures with reasons, and the open data requirements.

## Pilot procedure (low load, single connector)

Goal: check connectivity, tool installation, output files, clocks and processing at minimal risk.
The pilot makes **no power action and no configuration change**; only C1 is active (C2 powered off).

1. Fill in `.env` completely. Run `python 00-preflight/preflight_check.py` (prints the plan only).
2. Run `python 00-preflight/preflight_check.py --run` (read-only SSH and Admin API GETs). Fix every
   `failed` check; note every `not_checked` one.
3. On C1: start the telemetry script for 10 minutes with a new `RUN_ID` (for example `PILOT-20261101-01`).
4. Client: `run_hey_stepped.py --run-id PILOT-20261101-01 --steps 1,5 --sweeps 1 --duration 30s`.
   (One sweep is enough for the pilot; the experiment itself uses three.)
5. Client: a short k6 run with a new `RUN_ID` (`STAGE_VUS=2`, `RAMP_DURATION=10s`, `HOLD_DURATION=30s`)
   including `--out json`.
6. Client: `failover_probe.py run` for tcp and http, 3 minutes, **without** injecting a fault; write a
   `mark --kind note`. Then run `analyze`. `not_valid` (no fault marker) is expected; check the
   actual interval statistics and probe durations in the analysis.
7. Control host: `sync_threat_intel.py plan` (with a saved feed file or `--fetch`). No `apply` and no
   canary `run` in the pilot, because both change cloud configuration.
8. The scaler is **not** started live in the pilot (there is no observe-only mode); use `--dry-run`.
9. On C1: `sadf -d … -- -u ALL` export and `sadf -V`. Copy the telemetry files back.
10. Control host: `scan`, review the spec (classify the pilot data as `real`), `process`.
    Check `processing_manifest.json` for issues and skipped figures.

Record after the pilot:
- tool versions (`hey`, `k6 version`, `iperf3 --version`, `sadf -V`);
- whether the clocks are synchronised and how;
- the actual probe intervals;
- any preflight warnings.

## Stopping and recovery

| Tool | How to stop | What remains / what to do |
|---|---|---|
| `run_hey_stepped.py`, `run_iperf3_comparison.py` | Ctrl+C (SIGTERM where the OS delivers it to Python) | Rows and raw files written so far remain; the in-flight run is recorded as invalid; `levels.csv` / summary and the manifest are written with status `interrupted` (exit code 3); never an acceptable capacity result. A hard kill (SIGKILL, power loss) leaves no manifest. Repeat with a **new** `RUN_ID`. |
| k6 | Ctrl+C | k6 is expected to call `handleSummary` on a graceful stop (not verified here); if the summary is written, `k6_summary.js` marks a run that ended early as invalid. Use a new `RUN_ID` for the next run. |
| telemetry script | Ctrl+C / SIGTERM | Metadata is still written with `partial_interrupted`; exit code 1. |
| `scaler_daemon.py` | Ctrl+C | The open activation is closed with reason "daemon stopped". **C2 keeps its current power state**; power it off by hand (vSphere / ESXi) if needed. |
| `failover_probe.py run` | Ctrl+C | Records and manifest are written (`ended_by: keyboard_interrupt`). Restore the injected fault by hand. |
| `sync_threat_intel.py apply` | avoid interrupting | If interrupted or uncertain (exit code 4), check the category in the Admin console. For an update, a `category_snapshot.json` exists from before the write and `restore` can be used; `restore` refuses if the category changed meanwhile (`restore_conflict`). |
| `canary_block_test.py run` | Ctrl+C (SIGTERM where the OS delivers it to Python) | `INTERRUPTED` is logged and the restore may not have run; the snapshot exists if a write was attempted. Use `canary_block_test.py restore` with the run's `category_snapshot.json` (see experiment 4); on `restore_conflict` or `restore_uncertain` fix the category by hand using the recovery data in `result.json`. |
| `process_results.py` | Ctrl+C | Partial output directory; run again (a new `.attemptN` directory is used). |
