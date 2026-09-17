# HPE Aruba SSE (Atmos) Connector Automation & Evaluation Framework

Practical measurement, automated provisioning, high-availability verification, and threat intelligence integration framework for HPE Aruba Networking SSE (Axis Atmos) Connectors. Developed as part of an MSc Thesis at Budapest University of Technology and Economics (BME).

## Project Overview

This repository provides an automated, reproducible research and measurement framework structured around four core pillars:

1. **01-load-test**: Baseline capacity, throughput (RPS), and latency distribution (p95/p99) characterization using `hey` and `k6` under stepped concurrent workloads.
2. **02-scaler-poc**: Resource telemetry daemon (monitoring CPU/memory loads) triggering event-driven horizontal autoscaling via Proxmox VE API.
3. **03-failover**: High-resolution network failover probes measuring tunnel convergence, packet retransmissions, and service restoration timing during simulated node/zone outages.
4. **04-threat-intel**: Automated security intelligence ingestion consuming public malicious indicators (abuse.ch URLhaus) and synchronizing threat policies via the Atmos Admin REST API.

---

## Repository Structure

```text
hpe-atmos-sse-automation/
├── 01-load-test/              # Load and performance benchmarking scripts
├── 02-scaler-poc/             # Telemetry-based autoscaling daemon
├── 03-failover/               # High-frequency network convergence probes
├── 04-threat-intel/           # Threat feed ingestion & Atmos API sync
├── .env.example               # Configuration template for sensitive variables
├── .gitignore                 # Excludes secrets, metrics, and network captures
├── LICENSE                    # MIT License
├── README.md                  # Project documentation
└── requirements.txt           # Python package dependencies
```

---

## Getting Started

### 1. Prerequisites
* Python 3.10 or newer
* Network access to HPE Aruba SSE Management Tenant (`admin-api.axissecurity.com`)
* Administrative API Token configured in Atmos (`Settings > Admin API`)
* Target host/VM for Connector deployment (Ubuntu 22.04 LTS recommended)

### 2. Installation
Clone the repository:
```bash
git clone [https://github.com/](https://github.com/)<your-username>/hpe-atmos-sse-automation.git
cd hpe-atmos-sse-automation
```

Install Python dependencies:
```bash
pip install -r requirements.txt
```

### 3. Environment Configuration
Duplicate the configuration template and provide your deployment parameters:
```bash
cp .env.example .env
```

Edit `.env` with your active endpoints and tokens:
```dotenv
TARGET_APP_URL=[https://richard-internal-web.local](https://richard-internal-web.local)
INTERNAL_HOST=192.168.1.50
TCP_TARGET_PORT=443

CPU_SCALE_OUT_THRESHOLD=80.0
CPU_SCALE_IN_THRESHOLD=30.0
TRIGGER_WINDOW_SEC=15
POLL_INTERVAL_SEC=5

PROXMOX_URL=[https://pve.bme.hu:8006](https://pve.bme.hu:8006)
PROXMOX_NODE=pve-node-02
CONNECTOR_2_VMID=102
PROXMOX_TOKEN_ID=user@pam!token
PROXMOX_TOKEN_SECRET=your_pve_token_secret

ATMOS_BASE_URL=[https://admin-api.axissecurity.com/api/v1.0](https://admin-api.axissecurity.com/api/v1.0)
ATMOS_API_KEY=your_atmos_jwt_token
```

---

## Module Usage

### Threat Intelligence Feed Sync (Pillar 4)
Polls the latest verified malware distribution URLs from abuse.ch and synchronizes them with the Atmos custom category policy:
```bash
python 04-threat-intel/sync_threat_intel.py
```

### Autoscaler Daemon (Pillar 2)
Runs continuous telemetry checks and manages hypervisor node states based on configured load thresholds:
```bash
python 02-scaler-poc/scaler_daemon.py
```

---

## Academic Citation

If you use or reference this framework in related academic research or projects, please cite:

```bibtex
@mastersthesis{slihoczki2026atmos,
  author       = {Richard Slihoczki},
  title        = {Performance Evaluation, Dynamic Autoscaling, and Policy Automation of HPE Aruba SSE Connectors},
  school       = {Budapest University of Technology and Economics (BME)},
  year         = {2026}
}
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author
* **Richard Slihoczki** - MSc Candidate, Faculty of Electrical Engineering and Informatics (VIK), Budapest University of Technology and Economics (BME)