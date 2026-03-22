# AI-Augmented Security Operations Center (AI-SOC)

An AI-powered SOC platform that detects network threats with ML, explains alerts with LLMs, correlates attacks into incidents, learns from analyst feedback, and generates its own detection rules.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-required-blue.svg)](https://www.docker.com/)

---

## What It Does

A security analyst receives thousands of alerts per day. Most are noise. This system compresses that noise into actionable intelligence:

1. **Detects threats** using ML models trained on CICIDS2017 (99.28% accuracy, <5ms inference)
2. **Explains alerts** in plain English using a local LLM (Ollama) with MITRE ATT&CK mapping
3. **Correlates related alerts** into incidents by IP affinity, time window, and kill chain stage
4. **Learns from analyst decisions** — false positive markings and severity corrections improve future detection
5. **Predicts next-stage attacks** using kill chain transition probabilities
6. **Generates detection rules** — the LLM writes Sigma rules for novel attack patterns and queues them for analyst approval

The LLM runs locally via Ollama. No security data leaves the network.

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │           DETECTION LAYER               │
                    │  Wazuh SIEM  |  Suricata IDS  |  Zeek   │
                    └──────────────┬──────────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────────┐
                    │       INTEGRATION LAYER                  │
                    │  Wazuh Integration (:8002)               │
                    │  Webhook receiver + alert router         │
                    └──────┬───────────────┬──────────────────┘
                           │               │
              ┌────────────▼─────┐  ┌──────▼───────────┐
              │  AI ANALYSIS     │  │  KNOWLEDGE BASE   │
              │  Alert Triage    │  │  RAG Service      │
              │  (:8100)         │  │  (:8300)          │
              │  LLM + ML + RAG  │◄─│  MITRE ATT&CK    │
              │  Async workers   │  │  CVE database     │
              │  Context memory  │  │  Security runbooks│
              └────────┬─────────┘  └──────────────────┘
                       │
              ┌────────▼─────────┐  ┌──────────────────┐
              │  ML INFERENCE    │  │  CORRELATION      │
              │  (:8500)         │  │  ENGINE (:8600)   │
              │  RF/XGB/DT       │  │  Incident grouping│
              │  77 features     │  │  Kill chain track │
              │  Hot-reload      │  │  Attack prediction│
              └──────────────────┘  └──────────────────┘
                       │
              ┌────────▼─────────┐  ┌──────────────────┐
              │  FEEDBACK LOOP   │  │  RULE GENERATOR   │
              │  (:8400)         │  │  (:8700)          │
              │  PostgreSQL      │  │  LLM-generated    │
              │  Alert history   │  │  Sigma rules      │
              │  Analyst feedback│  │  Back-testing     │
              │  Retraining data │  │  Approval queue   │
              └──────────────────┘  └──────────────────┘
```

---

## Quick Start

```bash
git clone https://github.com/zhadyz/AI_SOC.git
cd AI_SOC

# Option 1: Single-command deploy (Linux/macOS)
./deploy-ai-soc.sh

# Option 2: Manual deploy
docker compose -f docker-compose/phase1-siem-core.yml up -d    # SIEM
docker compose -f docker-compose/ai-services.yml up -d          # AI services
docker compose -f docker-compose/monitoring-stack.yml up -d     # Monitoring
```

First run downloads ~8GB of Docker images and the LLM model.

---

## Services

| Service | Port | Purpose |
|---------|------|---------|
| Wazuh Dashboard | :443 | SIEM alerts and agent management |
| Alert Triage | :8100 | LLM-powered alert analysis with async worker pool |
| RAG Service | :8300 | Semantic search over MITRE ATT&CK, CVEs, runbooks |
| Feedback Service | :8400 | Alert persistence and analyst feedback collection |
| ML Inference | :8500 | Network intrusion detection (RF/XGB/DT, 99.28% accuracy) |
| Correlation Engine | :8600 | Alert-to-incident grouping and attack prediction |
| Rule Generator | :8700 | LLM-generated Sigma detection rules |
| Wazuh Integration | :8002 | Webhook receiver, alert routing, RAG enrichment |
| Grafana | :3000 | 4 monitoring dashboards |
| Prometheus | :9090 | Metrics collection (29 alert rules) |

---

## Usage Examples

### Analyze an Alert

```bash
curl -X POST http://localhost:8100/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-001",
    "rule_description": "SSH brute force attack detected",
    "rule_level": 10,
    "source_ip": "203.0.113.42",
    "dest_ip": "10.0.1.50",
    "dest_port": 22,
    "raw_log": "Failed password for root from 203.0.113.42 port 45678 ssh2"
  }'
```

Returns severity, category, confidence score, MITRE technique mapping, IOCs, and recommended actions.

### Submit Analyst Feedback

```bash
curl -X POST http://localhost:8400/feedback/test-001 \
  -H "Content-Type: application/json" \
  -d '{
    "analyst_id": "analyst1",
    "is_false_positive": false,
    "true_label": "ATTACK",
    "notes": "Confirmed brute force from known malicious range"
  }'
```

Feedback drives the learning loop — false positive markings and severity corrections improve future ML models.

### View Incidents

```bash
# List correlated incidents
curl http://localhost:8600/incidents

# Predict next attack stage
curl http://localhost:8600/predict/reconnaissance
```

Related alerts are automatically grouped into incidents. The predictor returns probable next-stage attacks with preemptive action recommendations.

### Generate Detection Rules

```bash
curl -X POST http://localhost:8700/generate \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "novel-001",
    "alert_description": "Unusual PowerShell encoded command execution",
    "mitre_techniques": ["T1059.001"],
    "severity": "high"
  }'
```

The LLM generates a Sigma detection rule, back-tests it against historical alerts, and queues it for analyst approval.

---

## ML Models

Three models trained on CICIDS2017 (2.1M network flow records, 77 features):

| Model | Accuracy | FPR | Inference |
|-------|----------|-----|-----------|
| Random Forest | 99.28% | 0.25% | <1ms |
| XGBoost | 99.10% | 0.30% | <1ms |
| Decision Tree | 98.90% | 0.50% | <0.5ms |

Models retrain from analyst-labeled feedback via the continuous retraining pipeline. Champion/challenger evaluation ensures only improved models are promoted.

---

## Knowledge Base

The RAG service provides semantic search over:
- **MITRE ATT&CK**: 835 techniques with descriptions, tactics, and platforms
- **CVE Database**: Critical/High vulnerabilities from NVD API v2
- **Security Runbooks**: 8 incident response playbooks (SSH brute force, malware, phishing, ransomware, privilege escalation, data exfiltration, unauthorized access, DDoS)

---

## Key Design Decisions

- **Local LLM** (Ollama): Security events never leave the network. No cloud API dependency.
- **Honest ML confidence**: When network flow data isn't available, ML confidence is capped at 50% and marked as "alert_metadata" source.
- **Graceful degradation**: Every service handles upstream failures — if Ollama is down, ML-only results are returned. If the feedback service is down, alerts still process normally.
- **Async worker pool**: 3 concurrent LLM workers with priority queue. Circuit breaker skips LLM for low-severity alerts during incident-scale surges.
- **Feedback flywheel**: Analyst decisions feed back into model retraining, false-positive pattern detection, and contextual LLM memory.

---

## Project Structure

```
AI_SOC/
├── services/
│   ├── alert-triage/        # LLM alert analysis (FastAPI)
│   ├── rag-service/         # Knowledge base retrieval (ChromaDB)
│   ├── feedback-service/    # Alert persistence + analyst feedback (PostgreSQL)
│   ├── correlation-engine/  # Incident grouping + attack prediction
│   ├── rule-generator/      # LLM Sigma rule generation
│   ├── wazuh-integration/   # Wazuh webhook receiver
│   ├── retraining/          # Continuous ML retraining pipeline
│   └── common/              # Shared utilities (auth, metrics, security)
├── ml_training/             # ML training pipeline + inference API
├── models/                  # Trained model artifacts (.pkl)
├── docker-compose/          # Docker Compose files for all stacks
├── config/                  # Prometheus, Grafana, Wazuh, Suricata configs
├── datasets/                # CICIDS2017 dataset
├── tests/                   # Unit, integration, E2E, load, security tests
├── docs/                    # Documentation site (MkDocs)
└── deploy-ai-soc.sh         # Single-command deployment script
```

---

## Requirements

- Docker Engine 23+ and Docker Compose v2
- 16GB RAM minimum (32GB recommended)
- 20GB disk space
- Linux for full stack (Suricata/Zeek require `network_mode: host`)
- Windows/macOS for SIEM + AI services (no network sensors)

---

## Documentation

Full documentation at [research.onyxlab.ai](https://research.onyxlab.ai)

- [Installation Guide](docs/getting-started/installation.md)
- [Architecture Overview](docs/architecture/overview.md)
- [API Documentation](http://localhost:8100/docs) (Swagger UI, live)
- [Security Guide](docs/security/guide.md)
- [Deployment Guide](docs/deployment/guide.md)

---

## Research Context

This project is a research implementation for the paper: *"AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation"*

**Author:** Abdul Bari (abdul.bari8019@coyote.csusb.edu)
**Institution:** California State University, San Bernardino
**License:** Apache 2.0
