# Steelix Fusion (v2.1)

Steelix Fusion is a modular, distributed endpoint monitoring and anomaly detection system engineered for bare-metal Linux environments. Utilizing a centralized Hub-and-Spoke architecture managed via `systemd`, Steelix leverages localized telemetry collection agents ("Gym Leaders"), an integrated HTTP honeypot ("Red Gyarados"), and an Isolation Forest machine learning engine to establish a system behavior baseline and flag runtime anomalies in real time.

---

## Architecture Overview

Steelix Fusion is structured into four main operational pillars:

1. **The Hub Core (`steelix-brain`):** A multi-threaded TCP daemon that handles central data ingestion, processes inbound agent heartbeats, manages threat level scaling (`GREEN`, `YELLOW`, `RED`), and exposes an administrative loop for the command-line interface.
2. **Regional Telemetry Agents (`steelix-region-*`):** Eight independent, lightweight background loops that gather distinct underlying kernel and operational metrics to pass to the core ingestion loop.
3. **The AI Cortex Engine:** A serialization module that uses `scikit-learn`'s Anomaly Isolation Forest to dynamically baseline telemetry trends and classify infrastructure anomalies.
4. **Network Honeypot Subsystem (`steelix-gyarados`):** A Flask-based trap running on port `8888` that logs unauthorized network scanning/probing and immediately shifts the global cluster state to an emergency alert phase.



[Image of Hub and Spoke Network Topology]


### Regional Telemetry Matrix

| Inbound Agent Daemon | Monitored Operating System Metric | Domain Name Logic |
| :--- | :--- | :--- |
| `steelix-region-boulder` | Loaded Kernel Module Count (`lsmod`) | *Iron Defense* |
| `steelix-region-cascade` | Active Network Sockets (`ss -tunH`) | *Bubble Beam* |
| `steelix-region-thunder` | CPU Thermal Zone Temperature (`/sys/class/thermal`) | *Thunderbolt* |
| `steelix-region-rainbow` | Root Filesystem Disk Utilization (`df`) | *Mega Drain* |
| `steelix-region-soul`    | Zombie Process Allocations (`ps axo stat`) | *Toxic* |
| `steelix-region-marsh`   | Memory Consumption Percentages (`free`) | *Future Sight* |
| `steelix-region-volcano` | 15-Minute Host Load Averages (`os.getloadavg`) | *Fire Blast* |
| `steelix-region-earth`   | Active Logged-in System User Sessions (`who`) | *Earthquake* |

---

## Directory Structure

Following a successful deployment, the system installs clean logical barriers inside the target directory skeleton:

```text
/opt/Steelix_Fusion/
├── agent/      # Core edge metrics instrumentation loop
├── brain/      # Multithreaded TCP orchestration and db ingest logic
├── cortex/     # Machine learning training models and pkl binaries
├── gyarados/   # Flask early-warning token trap (Port 8888)
├── pokegear/   # Thread-safe persistent system logging backend
└── reporter/   # 24h cron-style log aggregation engine
