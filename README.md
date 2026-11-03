# HPE Aruba SSE Connector Evaluation Framework

Measurement and automation tooling for a BSc thesis at the Budapest University of Technology and
Economics (BME VIK) on HPE Aruba Networking SSE (Axis Atmos) connectors. The testbed is an HPE
Aruba SSE Cloud Edge setup with two VMware ESXi hosts, one connector VM per host.

> **Validation status (short):** all components are covered by offline tests (simulated clocks,
> mocked SSH/HTTP/API and synthetic data). Experiment 1 (`hey` load through the SSE path with C1 and
> client `sar` telemetry, via `lab.py e1`) has run on the testbed: one connector peaks at about
> 1400 concurrent clients (about 4000 successful responses/s) and collapses above it. ESXi/vCenter
> power control, failover and the Admin API have not been run live yet. Figures produced from
> dry-run data are watermarked **SIMULATED – NOT A REAL MEASUREMENT** and are not experimental
> results. Details: [docs/validation-status.md](docs/validation-status.md).

## The four experiments

| # | Question | Module |
|---|---|---|
| 1 | Capacity and load tolerance of access through a connector | `01-load-test/` |
| 2 | CPU-threshold activation of a pre-configured secondary connector VM (power-on over ESXi SSH, the vCenter API or by hand; no cloning) | `02-scaler-poc/` |
| 3 | Availability and recovery during a manually injected connector failure | `03-failover/` |
| 4 | URLhaus indicator synchronisation and the *perceived* SWG blocking delay, measured with an own, harmless canary host | `04-threat-intel/` |

`00-preflight/` checks testbed assumptions read-only; `05-results/` processes the outputs of all
four experiments into figures, CSV files and a processing manifest.

## Repository structure

```text
hpe-atmos-sse-automation/
├── 00-preflight/        read-only testbed pre-flight check
├── 01-load-test/        hey/k6 load tests, iperf3 path comparison, connector-VM telemetry (sar)
├── 02-scaler-poc/       CPU-threshold activation daemon for the secondary connector VM
├── 03-failover/         TCP/HTTP/persistent availability probes, operator markers, analysis
├── 04-threat-intel/     URLhaus sync into a custom web category; canary blocking experiment
├── 05-results/          common result processing and figures (scan -> reviewed spec -> process)
├── lab.py               optional menu / one-command runner over the scripts above
├── docs/                architecture, measurement guide, validation status
├── tests/               offline test suite (unittest; no network)
├── .env.example         configuration template (copy to .env; never commit .env)
├── requirements*.txt    Python dependencies (measurement / development / result processing)
└── LICENSE              MIT
```

## Prerequisites

- Python 3 (the offline test suite was run with Python 3.13 on Windows 11).
- Python packages: `requirements.txt` (measurement tools), `requirements-results.txt` (figures),
  `requirements-dev.txt` (optional pytest; the suite itself uses `unittest`).
- External tools, depending on the experiment: [`hey`](https://github.com/rakyll/hey),
  [`k6`](https://k6.io/), `iperf3`, and `sysstat` (`sar`, `sadf`) on the connector VMs.
- For live runs: an Atmos Admin API token, SSH access to the connector VMs and the ESXi host,
  host keys in `known_hosts`, and the operator prerequisites listed in
  [docs/validation-status.md](docs/validation-status.md).

## Installation

```bash
git clone https://github.com/<your-username>/hpe-atmos-sse-automation.git
cd hpe-atmos-sse-automation
python -m pip install -r requirements.txt -r requirements-results.txt
cp .env.example .env    # then edit .env; secrets are read from the environment only
```

## Quick start (offline, no testbed needed)

Run the offline test suite (no network, SSH or API access; Bash- and node-based tests are
skipped with a reason if no suitable runtime is present):

```bash
python -m unittest discover -s tests
```

Try the simulated modes (every output is labelled as simulated):

```bash
python 01-load-test/run_hey_stepped.py --dry-run --run-id DEMO-1
python 02-scaler-poc/scaler_daemon.py --dry-run
python 03-failover/failover_probe.py run --probe tcp --run-id DEMO-1 --dry-run --duration-sec 60
python 03-failover/failover_probe.py analyze --probe tcp --run-id DEMO-1
```

Note: `--help` and `--dry-run` never read `.env` (they use an empty, synthetic configuration);
the live modes load `.env` from the working directory and report its errors only when they need
the affected value.

For live measurements follow [docs/measurement-guide.md](docs/measurement-guide.md), starting with
the low-load, single-connector pilot.

## Optional menu: `lab.py`

The same procedures are also available from a menu on the load-generator host. It calls the scripts
above with the same arguments and records every command, the code commit and the parameters in
`lab_run.json` next to the results:

```bash
python3 lab.py               # menu: check, preflight, E1-E4, process results / regenerate figures, settings
python3 lab.py e1            # E1 end to end: C1 telemetry over SSH, client sar, hey, exports, figures
python3 lab.py e1 --dry-run  # offline practice (synthetic data, figures watermarked SIMULATED)
```

It needs key-based SSH to the connector VM (no passwords) and runs itself inside tmux. Details:
[docs/measurement-guide.md](docs/measurement-guide.md#menu-driven-runs-optional-labpy).

## Documentation

- [docs/architecture.md](docs/architecture.md) – file responsibilities, entry points, inputs,
  outputs and side effects, and how the components interact.
- [docs/measurement-guide.md](docs/measurement-guide.md) – which machine runs which command,
  configuration and `RUN_ID` handling, telemetry export, result processing, pilot procedure,
  stopping and recovery.
- [docs/validation-status.md](docs/validation-status.md) – offline checks completed, live checks
  not yet performed, operator prerequisites, known limitations and open questions.

## Academic citation

```bibtex
@bachelorsthesis{slihoczki2026atmos,
  author       = {Richard Slihoczki},
  title        = {Performance Evaluation, Dynamic Autoscaling, and Policy Automation of HPE Aruba SSE Connectors},
  school       = {Budapest University of Technology and Economics (BME)},
  year         = {2026}
}
```

## License

MIT – see [LICENSE](LICENSE).

## Author

Richard Slihoczki – BSc student, Faculty of Electrical Engineering and Informatics (VIK),
Budapest University of Technology and Economics (BME).
