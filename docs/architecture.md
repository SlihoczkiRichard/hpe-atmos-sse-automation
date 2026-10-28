# Architecture

This document describes what each file does, which files are entry points, what they read and
write, which side effects they can have on the testbed, and how the components interact.
Validation status: see [validation-status.md](validation-status.md).

## Overview

```text
                 operator (.env, CLI, manual fault injection, reviewed spec)
                                     │
   ┌──────────────┬──────────────────┼───────────────────┬────────────────────┐
   ▼              ▼                  ▼                   ▼                    ▼
00-preflight   01-load-test       02-scaler-poc       03-failover         04-threat-intel
(read-only)    hey / k6 / iperf3  SSH: C1, C2, ESXi   TCP/HTTP/persistent sync: URLhaus -> category
               + sar on the VMs   Admin API (GET)     probes + markers    canary: category change
                                                                          + blocking probes
   │              │                  │                   │                    │
   └──────────────┴────── files under <module>/results/... ┴────────────────────┘
                                     │
                                     ▼
                     05-results: scan -> reviewed spec -> process
                     (read-only on inputs; figures, CSV, manifest)
```

The measurement modules do not call each other. They share a `RUN_ID` given by the operator, the
`.env` configuration and some library code that is loaded read-only by file path (directory
names start with digits, so modules are loaded with `importlib`, not imported as packages):

- `00-preflight` reuses the scaler's parsers and SSH executor.
- `05-results` reuses `03-failover/failover_analysis.py` for the clock-domain and marker rules.

Common conventions:

- Secrets (passwords, API key) are read from the environment only, never from CLI arguments.
  They are redacted from logs and never written to output files.
- `.env` is loaded only in `main()` of a live mode started from the command line; `--help` and
  `--dry-run` use an empty, synthetic configuration and never read `.env` or the process
  environment. Numeric settings are converted only when the selected mode parses them. Importing
  a module has no side effects (no `.env`, no SSH client, no host-key file, no network).
- SSH host keys are verified (paramiko `RejectPolicy`); TLS certificates are verified. Insecure
  modes exist only as explicit `--lab-insecure-*` flags of the scaler and are logged.
- Output files are never overwritten silently: 01 tools refuse to start when results of the same
  `RUN_ID` exist (files are created with mode `x`; the k6 summary name carries a millisecond
  timestamp, best effort), 03–05 add an `.attemptN` file or directory suffix (03 analysis: `.revN`).
- Dry-run / simulated modes are labelled `SIMULATED - NOT A REAL MEASUREMENT` (or "dry-run ... NOT a
  measurement") in their manifests.

## 00-preflight

| File | Role |
|---|---|
| `preflight_check.py` | **Entry point.** Without `--run` it only prints the plan of checks. With `--run` it performs read-only checks. |

- Inputs: `.env` (ESXi, connector, API and target settings).
- Network and SSH (only with `--run`):
  - SSH commands from a fixed allow-list: `vmware -v`, `vim-cmd vmsvc/getallvms`, `vim-cmd vmsvc/power.getstate`, `head -n1 /proc/stat`, `command -v sar`, `command -v ss`;
  - Admin API GETs: `/Health`, `/Connectors`, `/Connectors/{id}/status`;
  - one HTTPS GET to the target application.
- Side effects: none on the testbed. It never powers VMs on or off, never writes `known_hosts`, and never changes cloud configuration.
- Output: `00-preflight/results/preflight_<timestamp>.json` with derived facts only. The exit code is 1 if any check failed.

## 01-load-test (experiment 1)

| File | Role |
|---|---|
| `run_hey_stepped.py` | **Entry point.** Runs `hey` as a subprocess for ascending concurrency levels in repeated sweeps. It parses the reports and applies the acceptance rule. |
| `k6_workload.js` | **k6 script** (run by `k6 run`). It uses staged VUs and success by `SUCCESS_STATUSES`, tags every attempt with the stage in which it started, and writes a JSON summary (whole test plus per-stage results). One `GET` per iteration. |
| `k6_summary.js` | Imported by `k6_workload.js`. Pure functions deriving the summary from k6's own counters, plus the stage plan, stage attribution, stage-submetric selector thresholds and per-stage results, so they can be tested with node. |
| `run_iperf3_comparison.py` | **Entry point.** Runs the `iperf3` client against two configured paths in alternating order. The path label is configuration only; verification is `not_verified` or `operator_asserted`. |
| `collect_connector_telemetry.sh` | **Run on a connector VM.** Collects `sar` CPU, memory, swap, disk, network (and filesystem if supported) plus `df` snapshots. It records coverage metadata. |

- Network side effects: HTTP load on the target URL (hey, k6) and TCP load to the iperf3 servers.
  The tools open no ports and change no SSE configuration.
- Outputs:
  - `results/<RUN_ID>/runs.csv`, `levels.csv`, `manifest.json`, `raw/` (hey);
  - `iperf3_runs.csv`, `iperf3_summary.csv`, `iperf3_manifest.json`, `raw/` (iperf3);
  - `${K6_RESULTS_DIR}/k6_<RUN_ID>_summary.<UTC timestamp>.json` (k6; the directory must exist) and, optionally, the k6 raw JSON from `--out json=<file>`;
  - hey and iperf3: an interruption still writes the manifest with status `interrupted` (never an acceptable result);
  - on the VM: `telemetry_<RUN_ID>_<ROLE>_<host>_{sar.txt,.sa,sar.err,df_start.txt,df_end.txt,meta.json}`.

## 02-scaler-poc (experiment 2)

| File | Role |
|---|---|
| `scaler_daemon.py` | **Entry point** and library. It contains the configuration, `/proc/stat` CPU parsing, the SSH executor and ESXi adapter, the CPU samplers, the connector-status and application probes, the pure `ScalerController`, the activation tracking, the recorders and the daemon loop. |

- Inputs: `.env` and CLI options (thresholds, windows, timeouts, connector and ESXi settings).
- SSH connections:
  - C1 guest: CPU samples via `/proc/stat`;
  - C2 guest: CPU samples, guest reachability and the optional `ss` connection check;
  - ESXi host: `vim-cmd vmsvc/power.getstate | power.on | power.shutdown | power.off`.
- Other network: Admin API GET `/Connectors/{id}/status` and an HTTP GET to the target, both optional.
- Side effects on the testbed:
  - **power-on of the C2 VM** when the CPU threshold is held;
  - ACPI shutdown only if scale-in is explicitly enabled (it is disabled by default);
  - forced power-off only with `--allow-force-power-off`;
  - never stops a C2 whose power-on it did not confirm, unless `--allow-scale-in-manual-c2` is given.
- Output: `<output-dir>/scaler[_dryrun]_<timestamp>_{timeseries,events,errors}.csv`. The files carry no `RUN_ID` and no provenance field; the `RUN_ID` is assigned in the 05 spec.
- The dry-run uses a simulated clock, ESXi and CPU profiles and contacts nothing.

## 03-failover (experiment 3)

| File | Role |
|---|---|
| `failover_probe.py` | **Entry point.** Subcommands:<br>- `run`: one probe type per process: `tcp` (new connection per probe), `http` (new connection, expected status and content), `persistent` (one keep-alive connection, never reconnects);<br>- `mark`: operator marker: `fault_injected`, `fault_cleared` or `note`;<br>- `analyze`: evaluates one probe type. |
| `failover_analysis.py` | Imported library (pure). Finds outages, applies the baseline and stable-recovery rules, and handles markers and clock domains. Also used by 05. |

- The fault is injected **by hand**. The tool never stops VMs, changes vNICs or touches SSE configuration.
- Network side effects: TCP connects and HTTP(S) GETs to the configured target.
- Outputs in `results/<RUN_ID>/`:
  - `probes_<type>[.attemptN].csv`, `manifest_<type>[.attemptN].json`;
  - `markers.csv` (with clock-domain fields);
  - `analysis_<type>[.attemptN][.revN].json`, `outages_<type>[...].csv`.

## 04-threat-intel (experiment 4)

| File | Role |
|---|---|
| `sync_threat_intel.py` | **Entry point, sync mode:**<br>- `plan`: feed to indicator list; optional read-only API comparison;<br>- `apply`: create or update the managed category, verify, optional Commit;<br>- `restore`: put the category back to the apply snapshot, with a conflict check. |
| `canary_block_test.py` | **Entry point, canary mode:**<br>- `validate-signature`: probes the blocked reference host;<br>- `run`: baseline → add canary → optional Commit → observe blocking → restore → check access;<br>- `restore`: puts the test category back to a run's own `category_snapshot.json`, only if the category still equals what the run wrote.<br>The snapshot is saved and closed before the first category write. One API worker thread; the probes run on the main thread. Worker exceptions are reported apart from the API outcomes. |
| `threat_feed.py` | Imported (pure). URLhaus CSV parsing, host normalisation and the deterministic selection rule. |
| `atmos_categories.py` | Imported. Admin API client for `WebCategories` and `Commit`, restricted to Swagger operations. It builds payloads from an explicit writable-field list, never sends `id` or `type`, never calls DELETE, and treats a write after a timeout as uncertain. |
| `block_analysis.py` | Imported (pure). Canary probe classification, signature validation and the blocking timeline with signed offsets. |
| `run_files.py` | Imported. Exclusive run directories and files. |
| `atmos-swagger.json` | Admin API contract used for implementation and contract tests. |

- Network:
  - the URLhaus download, only with `--fetch`;
  - Admin API GET/POST/PUT on `WebCategories` and POST `/Commit` (`apply`, `restore` and canary `run` only);
  - GETs to the own canary and reference hosts.
- Side effects:
  - changes to **one** managed category (sync) or to **one** pre-existing test category (canary);
  - an optional Commit, whose necessity and scope are not validated.
- Outputs in `results/<RUN_ID>/`:
  - `sync_<command>[.attemptN]/`: manifest, indicators, category snapshot, api_log.jsonl, result;
  - `signature[.attemptN]/`;
  - `canary[.attemptN]/`: probes, events, api_log.jsonl, snapshot, summary, manifest;
  - `canary_restore[.attemptN]/`: result, api_log.jsonl, manifest.

## 05-results (processing)

| File | Role |
|---|---|
| `process_results.py` | **Entry point:**<br>- `scan` writes a spec draft;<br>- `process` reads only the files named in a reviewed spec. |
| `loaders.py` | Imported. Read-only loaders per output type. It records the sha256 of each input, the provenance (`simulated` / `real` / `unknown`) and the issues (`fatal` / `figure` / `partial`). |
| `sar_adapter.py` | Imported. Supports exactly two formats, both with UTC timestamps: the `sadf -d … -- -u ALL` (or `-u`) CPU export and the `sadf -d … -- -r` memory export. Duplicates and overlapping records are reported. |
| `k6_raw_adapter.py` | Imported. Parses the k6 `--out json` NDJSON into fixed UTC bins, plus per-stage counts and percentiles when the points carry the `stage` tag. |
| `derive.py` | Imported (pure). The computations behind the figures. |
| `plots.py` | Imported. Matplotlib figures (PNG and PDF) plus the CSV behind each figure, with the provenance watermark. |

- Inputs: only the files listed in the spec. Nothing is modified.
- Output: `05-results/processed/<processing_id>[.attemptN]/` with figures, CSV files and `processing_manifest.json`.
- No network, SSH or API access.

## tests/

The offline test suite (`unittest`).

| File | Role |
|---|---|
| `_helpers.py` | Installs a process-wide network guard before any module under test is imported. |
| `_bash_runtime.py` | Selects native POSIX bash, Git Bash or WSL for the telemetry-script tests. |
| `_results_fixtures.py` | Builds a simulated input set from the modules' own dry-run code paths. |

## Configuration

`.env.example` documents every variable, grouped by experiment. CLI options override `.env`
defaults; secrets are environment-only. `RUN_ID` (letters, digits, `.`, `_`, `-`) is passed
explicitly to every tool of one measurement run. The k6 script does not read `.env`; its variables
are passed with `k6 run -e NAME=value`.
