# HPE Aruba SSE (Atmos) Connector Automation & Evaluation Framework

Practical measurement, automated provisioning, high-availability verification, and threat intelligence integration framework for HPE Aruba Networking SSE (Axis Atmos) Connectors. Developed as part of a BSc Thesis at Budapest University of Technology and Economics (BME).

## Project Overview

This repository provides an automated, reproducible research and measurement framework structured around four core pillars:

1. **01-load-test**: Baseline capacity, throughput (RPS), and latency distribution (p95/p99) characterization using `hey` and `k6` under stepped concurrent workloads.
2. **02-scaler-poc**: Resource telemetry daemon (monitoring guest CPU utilization) triggering event-driven horizontal autoscaling via VMware ESXi 6.7.0 CLI (`vim-cmd`).
3. **03-failover**: High-resolution network failover probes measuring tunnel convergence, packet retransmissions, and service restoration timing during simulated node/zone outages.
4. **04-threat-intel**: Automated security intelligence ingestion consuming public malicious indicators (abuse.ch URLhaus) and synchronizing threat policies via the Atmos Admin REST API.

---

## Repository Structure

```text
hpe-atmos-sse-automation/
├── 01-load-test/               # Load and performance benchmarking scripts
├── 02-scaler-poc/              # Telemetry-based autoscaling daemon
├── 03-failover/                # High-frequency network convergence probes
├── 04-threat-intel/            # Threat feed ingestion & Atmos API sync
├── .env.example                # Configuration template for sensitive variables
├── .gitignore                  # Excludes secrets, metrics, and network captures
├── LICENSE                     # MIT License
├── README.md                   # Project documentation
└── requirements.txt            # Python package dependencies
```

---

## Getting Started

### 1. Prerequisites
- Python 3.10 or newer
- Network access to HPE Aruba SSE Management Tenant (`admin-api.axissecurity.com`)
- Administrative API Token configured in Atmos (`Settings > Admin API`)
- Target host/VM for Connector deployment (Ubuntu 24.04 LTS recommended)

### 2. Installation
Clone the repository:
```bash
git clone https://github.com/<your-username>/hpe-atmos-sse-automation.git
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
# ==============================================================================
# Target Workload & Endpoints
# ==============================================================================
TARGET_APP_URL= https://sr-target-web-szinvanet.axisapps.io/
BACKEND_HOST=10.0.1.123
TCP_TARGET_PORT=443

# ==============================================================================
# Pillar 2: Autoscaling Telemetry & VMware ESXi Lifecycle Control
# ==============================================================================
# Primary Connector Guest SSH (ibm09esxi) - CPU Telemetry
CONNECTOR_1_IP=10.0.1.121
CONNECTOR_SSH_USER=your_ssh_user
CONNECTOR_SSH_PASSWORD=your_guest_ssh_password

# Secondary Connector Hypervisor (ibm06esxi) - VM Lifecycle & Telemetry
ESXI_HOST=ibm06esxi.szinva.net
ESXI_USER=root
ESXI_PASSWORD=your_esxi_root_password
CONNECTOR_2_VMID=12
CONNECTOR_2_IP=10.0.1.122

# Thresholds & Windows
CPU_SCALE_OUT_THRESHOLD=80.0
CPU_SCALE_IN_THRESHOLD=30.0
TRIGGER_WINDOW_SEC=15.0
POLL_INTERVAL_SEC=5.0
SCALE_IN_COOLDOWN_SEC=60.0

# ==============================================================================
# Pillar 4: HPE Aruba SSE Cloud Management REST API
# ==============================================================================
ATMOS_BASE_URL=https://admin-api.axissecurity.com/api/v1.0
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
@bachelorsthesis{slihoczki2026atmos,
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
- **Richard Slihoczki** - BSc Student, Faculty of Electrical Engineering and Informatics (VIK), Budapest University of Technology and Economics (BME)