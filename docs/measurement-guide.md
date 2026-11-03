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
2. Secrets (`CONNECTOR_SSH_PASSWORD`, `CONNECTOR_2_SSH_PASSWORD`, `ESXI_PASSWORD`, `VCENTER_PASSWORD`, `ATMOS_API_KEY`)
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

## Menu-driven runs (optional): `lab.py`

`lab.py` in the repository root is a convenience layer over the commands in this guide. It calls
the same scripts with the same arguments, in the same order, and produces the same files; the
manual procedure in the rest of this guide stays valid and is exactly what `lab.py` automates. Use
whichever you prefer; results of both are processed the same way.

```bash
python3 lab.py            # menu
python3 lab.py check      # tools, .env, SSH key login to C1 (read only)
python3 lab.py e1         # E1 end to end, figures included
python3 lab.py e1 --dry-run   # offline practice: synthetic hey output, figures watermarked SIMULATED
```

Requirements in addition to the manual procedure:

- Run it on the load-generator host. It restarts itself inside tmux (session `lab`) if it is not
  already in one, so a dropped SSH/VPN session does not stop a run (reattach: `tmux attach -t lab`),
  and it uses `.venv/bin/python` when that exists.
- Key-based SSH from that host to C1 (`ssh-copy-id <CONNECTOR_SSH_USER>@<CONNECTOR_1_IP>` once),
  with C1's host key already in `known_hosts` (or `SSH_KNOWN_HOSTS`). `lab.py` uses the system
  `ssh`/`scp` with `BatchMode=yes` and `StrictHostKeyChecking=yes`; it never asks for or stores a
  password.
- `sysstat` (`sar`, `sadf`) on the client and on C1; `setsid` on C1 (util-linux).
- Optional keys in `.env`: `LAB_REMOTE_DIR`, `LAB_LEAD_SEC`, `LAB_TELEMETRY_SEC`, `LAB_COPY_DEST`
  and, for E2, `E2_*` (see `.env.example`).
- Parameters: menu item **Settings** (`python3 lab.py settings`) shows and changes the non-secret
  `.env` keys of the experiments, with the same checks the tools apply (steps, durations, numbers).
  It writes `.env` with mode 0600 and keeps the previous version as `.env.bak`. Passwords, the API key
  and tokens are never shown or changed there; edit those in `.env` by hand. Every run records the
  values it used in `lab_run.json`.

What `lab.py e1` does (the manual equivalent is in the E1 and telemetry sections below):

1. Checks the tools, the SSH login and that the `RUN_ID` is unused (default suggestion:
   `E1-<UTC date>-NN`), shows the plan and the code commit (uncommitted changes are listed), and asks
   for confirmation.
2. Copies `collect_connector_telemetry.sh` to `~/<LAB_REMOTE_DIR>` on C1, verifies its sha256
   against the repository copy and starts it detached (`setsid nohup`) with `RUN_START_EPOCH` taken
   on C1. Length: lead time + 1.1 x the planned load time + 180 s, rounded up to 5 min (1800 s for
   the E1 plan), unless `LAB_TELEMETRY_SEC` is set.
3. Starts `sar -u 1 <same length> -o results/<RUN_ID>/client_sar/client.sa` on the client.
4. Waits `LAB_LEAD_SEC` (default 60 s idle baseline), raises the open-file limit to 8192 (warns if
   the hard limit is lower) and runs `run_hey_stepped.py` with explicit `--steps --sweeps --duration
   --cooldown --qps` from `.env`.
5. Waits for the telemetry to end, runs the `sadf` exports on C1 (`-u ALL`, `-r`, `sadf -V`), copies
   all `telemetry_<RUN_ID>_*` files to `results/<RUN_ID>/telemetry/` and exports the client CPU to
   `client_sar/client_cpu.csv`.
6. Reads `timedatectl` on both hosts. If both are NTP-synchronised it writes the `time_sync`
   statement (servers and offsets as the source); otherwise there is none and the cross-host
   figures are skipped.
7. Writes `results/<RUN_ID>/lab_run.json`: git commit and uncommitted changes, parameters, exact
   command lines, telemetry script hash, coverage, time-sync readings, timings.
8. Processing: `scan` -> reviewed spec (provenance from the tool metadata, the `m1_resources` group,
   `time_sync`), which is printed for the operator review and needs a yes -> `process` -> one
   `tar.gz` bundle with its sha256 and the `scp` command to copy it to your computer. Specs are kept
   in `05-results/specs/` (not committed).

Ctrl+C during the load stops hey the usual way (partial results kept, run marked interrupted);
`lab.py` then asks whether to stop the telemetry. Nothing is overwritten: a used `RUN_ID` is
refused, and processing the same spec again writes a new `.attemptN` folder.

Other menu items: **E2** (live scaler + load + C1 telemetry; needs `E2_CONCURRENCY_STEPS`, a
methodology decision, and shows a scaler dry run first), **E3** (one repetition: starts the three
probes, prints their status every 5 s, writes the markers when you type `f` / `c` / `n TEXT`, each
immediately BEFORE the Save in the Host Client, then runs `analyze`), **E4** (`plan`,
`validate-signature`, `canary`, `restore`; anything that writes asks first), **Process results**
(any `RUN_ID`s, or `lab.py figures --spec <reviewed spec>` to regenerate figures), and the read-only
**preflight**.

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

### E1 capacity run (client)

The capacity run covers the whole range in one run, so that one table and one curve describe it,
and it has to go **beyond** the connector's limit, otherwise no capacity conclusion can be drawn.
The first run (E1-20261103-01, `10..1000`, 30 s) did not saturate: at c = 1000 the throughput was
still rising (2853 -> 3202 1/s from c = 800) and C1 CPU was 83 %. A range-finding run
(E1-20261106-T1, `1000..6000`, one 30 s sweep) then located the limit: throughput peaked at
c = 1000 (3540 1/s), collapsed above it (3042, 1777, 862 1/s at 1500, 2000, 3000) and the error rate
passed 1 % from c = 4000 (2.6 %, 9.4 %, 19.4 %). A first six-level run (E1-20261106-01,
`400,800,1000,1200,2000,4000`) put the limit at c = 1200 (3650 1/s), but the gap up to 2000 was too
wide to place the peak. A second range-finding run (E1-20261106-T2, `1000,1200,1400,1500,1600,1800,2000`,
three 60 s sweeps) placed it at c = 1400 (4034 1/s, all three sweeps 3823-4116 1/s); from c = 1500 the
throughput falls in every sweep (3289, 2638, 2148, 1727 1/s up to c = 2000) with errors below 0.13 %,
while c = 1200 and c = 2000 repeated the first run within 2 % and 8 %. Low levels add no information,
so the capacity run uses six levels around these points (ramp-up, peak, collapse, failing range;
about 20 minutes):

```bash
ulimit -n 8192 && ulimit -n      # hey opens about c connections; the default 1024 fails at c = 1000
python 01-load-test/run_hey_stepped.py --run-id E1-<date>-01 \
    --steps 400,1000,1400,1600,2000,4000 \
    --sweeps 3 --duration 60s --cooldown 5 --qps 0
```

These are the `.env.example` values (`LOAD_CONCURRENCY_STEPS`, `LOAD_SWEEPS`, ...; `lab.py e1` uses
them from `.env` and sizes the telemetry, 1800 s, itself); the explicit flags make the command
self-describing. The manifest records the levels actually used.

- **Capacity limit (defined before the run, computed by `05-results`):** the highest accepted level
  after which throughput stops scaling: the next level is not accepted (a run with a primary error
  rate of at least `ACCEPT_MAX_ERROR_RATE`, or an invalid run), or the next level's median
  throughput grows by less than 0.25 x the relative increase of `c` (closed-loop load: an
  unsaturated path grows proportionally; E1-20261103-01 stayed at 0.46-2.0 up to c = 1000). If
  neither occurs, the result is "no saturation up to the highest tested level", not a capacity
  value. The publication figure `load_capacity` (colour) shows the median throughput per level as bars
  (green up to the limit, orange hatched for accepted overload levels, red cross-hatched for levels
  that fail acceptance, with each run as a dot) above p95/p99 latency (log scale) and C1 CPU on the
  same categorical concurrency axis, with the limit marked; `load_capacity.csv` next to it holds the values per level
  and the manifest the limit statement.
- **Which component limits:** if throughput stops scaling while C1 CPU stays well below 90 % and
  the client CPU has headroom, the limit is outside the connector (SSE edge, WAN, backend); this is
  a valid result too, stated as such. Connector CPU is
  reported as the run-window mean; 1 s percentiles are noisy on the connector VM and are not used as
  the limit.
- **Order and telemetry:** start the connector telemetry first (`collect_connector_telemetry.sh 1800
  1 ...`; about 20 minutes of load plus idle time before and after), then hey about one minute
  later. Run hey in `tmux` (or `screen`) so that a dropped SSH session does not interrupt it.
- **Client headroom (required):** record the client CPU for the same window, for example
  `sar -u 1 1800 -o ~/client_sar_<RUN_ID>.sa > /dev/null`, and keep its export out of the files that
  `05-results` scans as connector telemetry (do not name it `*_cpu_sadf.csv`). Without it, a
  client-side limit cannot be told apart from a connector limit at high concurrency.
- **File-descriptor errors:** `too many open files` in the raw hey output is a client limit, not an
  SSE result; such a run is not a valid measurement of the connector.

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

- **Side effect:** the live mode **powers on the C2 VM** when C1's CPU stays at or above the threshold for the trigger window. There is no observe-only mode.
- **Power-on backend (`C2_POWER_BACKEND`):**

  | Value | How C2 is powered on | Power state from | Needs |
  |---|---|---|---|
  | `esxi-ssh` (default) | `vim-cmd vmsvc/power.on` over SSH | ESXi | SSH enabled on the host, `ESXI_*`, `CONNECTOR_2_VMID` |
  | `vcenter-api` | vCenter REST `power?action=start` (7.0+) or `power/start` (6.x) | vCenter | `VCENTER_*`, a least-privilege user |
  | `manual` | the operator presses Power On when the console beeps and shows `MANUAL ACTION` | TCP connect to `CONNECTOR_2_IP:MANUAL_STATE_PORT` (proxy) | `CONNECTOR_2_IP`; no scale-in |

  On a shared host use `vcenter-api`. One-time setup by a vCenter administrator:
  1. Administration > Access Control > Roles: new role (e.g. `SSE-Thesis-PowerOnly`) with only
     *Virtual machine > Interaction > Power on* and *Power off*.
  2. Single Sign On > Users and Groups: user `sse-scaler@vsphere.local`.
  3. On the **SR-CONN02 VM only**: Permissions > Add, that user, that role, *Propagate to children* off.
  4. Download the vCenter root CA (`https://<vcenter>/certs/download.zip`) to the control host and set
     `VCENTER_CA_BUNDLE`. TLS verification cannot be switched off for vCenter.
  5. `python 00-preflight/preflight_check.py --run` logs in, finds the VM by `VCENTER_VM_NAME` (exactly
     one match is required) and reads its power state. It never powers it on, so the *Power on*
     privilege is first exercised by the live run (an HTTP 403 there is logged as `POWER_ON_FAILED`).

  With `manual` every offset after `POWER_ON_SENT` includes the operator's reaction time, and
  `VM_POWERED_ON` means "guest TCP port answers", which is later than the hypervisor power-on.
  Report these runs separately from automated ones.
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
- **Persistent probe:** the response must carry `Content-Length` or use chunked transfer encoding (the
  SSE edge re-encodes the backend's `Content-Length` response as chunked); either way the body must fit
  `FAILOVER_HTTP_MAX_BODY_BYTES` and the connection must stay open (no `Connection: close`).
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

Figure style: by default the figures are written for the thesis: no title, footer, date, time of
day or run id; only the essential figures of each experiment, with descriptive file names
(`load_capacity` when a hey run is paired with C1 CPU, otherwise `load_throughput` and
`load_latency`; `load_cpu_timeline`, `scaling_*`,
`failover_*`, `threat_*`). Captions belong in LaTeX. `--diagnostic` writes the full internal
figure set (titles, run ids, UTC axes, provenance footers) for checking. The manifest and the CSVs
keep the real run ids in both styles.

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
