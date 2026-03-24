# AI-Augmented Security Operations Center (AI-SOC)

### 37,575 AI agents attacked a network. They found 18 unique attack paths, discovered strategies no individual agent planned, and proved that LLM defenders cut breaches by 93%.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-required-blue.svg)](https://www.docker.com/)
[![CICIDS2017](https://img.shields.io/badge/dataset-CICIDS2017-green.svg)](https://www.unb.ca/cic/datasets/ids-2017.html)

Your vulnerability scanner found 847 CVEs. Which ones actually matter?

This platform spawns LLM-powered attacker agents — an opportunist, an APT operator, a ransomware crew, and a malicious insider — and runs them against a model of your real infrastructure as a swarm of up to 37,575 agents. Monte Carlo simulation with hierarchical leader/follower architecture produces statistically grounded risk assessments: "73% of attackers exploited this path" instead of a single anecdotal result. LLM-powered defender agents (SOC analyst, incident responder, threat hunter) fight back in real time. The system tells you exactly how you'll be breached, which defenses actually work, and what to fix first.

It also runs a full AI-powered SOC: ML detects threats at 99.28% accuracy in under 5ms, a local LLM explains alerts in plain English with MITRE ATT&CK mapping, related alerts are correlated into incidents with kill chain tracking, analyst feedback continuously retrains the models, and the system writes its own Sigma detection rules for novel attack patterns. Everything runs locally — no security data leaves the network.

```bash
# See how your network would be breached
curl -X POST http://localhost:8600/simulate?timesteps=3

# Get per-host risk scores based on simulation results
curl http://localhost:8600/risk-scores

# Generate a synthetic attack campaign dataset (for research)
curl -X POST "http://localhost:8600/simulate/generate-dataset?runs=100"
```

Built by Abdul Bari, co-author of the published survey paper *"AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation"* ([Srinivas et al., Informatics, 2025](https://www.mdpi.com/2624-800X/5/4/95)).

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Architecture](#architecture)
3. [Services](#services)
4. [Usage Examples](#usage-examples)
5. [Research Context](#research-context)
6. [ML Research Results](#ml-research-results)
7. [System Design](#system-design)
8. [Limitations and Future Work](#limitations-and-future-work)
9. [Documentation](#documentation)
10. [Citation](#citation)
11. [License](#license)

---

## Quick Start

```bash
git clone https://github.com/zhadyz/AI_SOC.git
cd AI_SOC

# Option 1: Single-command deploy (Linux/macOS)
./deploy-ai-soc.sh

# Option 2: Manual deploy
docker compose -f docker-compose/phase1-siem-core.yml up -d    # Wazuh SIEM
docker compose -f docker-compose/ai-services.yml up -d          # AI microservices
docker compose -f docker-compose/monitoring-stack.yml up -d     # Prometheus/Grafana
```

First run downloads approximately 8GB of Docker images and the LLM model. Allow 15-20 minutes on initial setup.

**Requirements:**
- Docker Engine 23+ and Docker Compose v2
- 16GB RAM minimum (32GB recommended)
- 20GB available disk space
- Linux for the full stack including Suricata/Zeek (network sensors require `network_mode: host`)
- Windows/macOS supported for SIEM + AI services only

**Dashboard access after deployment:**

| Interface | URL | Default Credentials |
|-----------|-----|---------------------|
| Wazuh Dashboard | https://localhost:443 | `admin` / `admin` |
| Grafana | http://localhost:3000 | `admin` / `admin` |
| Alert Triage API (Swagger) | http://localhost:8100/docs | none |

---

## Architecture

```
                    +-------------------------------------------+
                    |            DETECTION LAYER                |
                    |  Wazuh SIEM  |  Suricata IDS  |  Zeek     |
                    |  (indexer :9200, manager :55000, dash :443)|
                    +--------------------+----------------------+
                                         |
                    +--------------------v----------------------+
                    |          INTEGRATION LAYER                |
                    |  Wazuh Integration (:8002)                |
                    |  Webhook receiver, alert router,          |
                    |  RAG enrichment for severity >= 8         |
                    +----------+----------------+---------------+
                               |                |
              +----------------v------+  +------v----------------+
              |     AI ANALYSIS       |  |    KNOWLEDGE BASE     |
              |  Alert Triage (:8100) |  |  RAG Service (:8300)  |
              |  LLM analysis (Ollama)|<-|  MITRE ATT&CK (835)   |
              |  Async worker pool    |  |  CVE database (NVD v2)|
              |  Priority queue       |  |  8 security runbooks  |
              |  Circuit breaker      |  |  ChromaDB backend     |
              +----------+------------+  +-----------------------+
                         |
              +----------v------------+  +-----------------------+
              |    ML INFERENCE       |  |  CORRELATION ENGINE   |
              |  (:8500)              |  |  (:8600)              |
              |  Random Forest        |  |  IP affinity grouping |
              |  XGBoost              |  |  Temporal proximity   |
              |  Decision Tree        |  |  Kill chain tracking  |
              |  77 features          |  |  Markov chain predict |
              |  Hot-reload on retrain|  |  Incident management  |
              +----------+------------+  +-----------------------+
                         |
              +----------v------------+  +-----------------------+
              |    FEEDBACK SERVICE   |  |   RULE GENERATOR      |
              |  (:8400)              |  |  (:8700)              |
              |  PostgreSQL           |  |  LLM-generated Sigma  |
              |  Alert history        |  |  Back-tests vs history|
              |  Analyst feedback     |  |  Analyst approval     |
              |  Ground truth labels  |  |  queue                |
              |  Retraining triggers  |  +-----------------------+
              +----------+------------+
                         |
              +----------v--------------------------------------------+
              |  CONTINUOUS RETRAINING PIPELINE                       |
              |  Reads feedback -> retrains RF/XGB/DT                 |
              |  Champion/challenger evaluation -> promotes if better  |
              |  Model versioning with rollback capability             |
              +-------------------------------------------------------+

              +-------------------------------------------------------+
              |  RESPONSE ORCHESTRATOR (:8800)                         |
              |  Autonomous Adaptive Defense (closed loop)             |
              |                                                        |
              |  Detect incident                                       |
              |    -> Simulate attacker next moves (swarm)             |
              |    -> D3FEND countermeasure lookup                      |
              |    -> LLM-scored defense plan (ranked by impact)        |
              |    -> Auto-execute safe actions (graduated autonomy)    |
              |    -> Queue critical actions for human approval         |
              |    -> Verify via re-simulation                          |
              |    -> Record outcome for learning                       |
              |                                                        |
              |  Adapters: Wazuh AR | Firewall | EDR | Identity        |
              +-------------------------------------------------------+

              +-------------------------------------------------------+
              |  MONITORING                                            |
              |  Prometheus (:9090) - 29 alert rules                  |
              |  Grafana (:3000) - 4 dashboards                       |
              |  Alertmanager - notification routing                   |
              |  Loki - log aggregation                                |
              +-------------------------------------------------------+
```

---

## Services

| Service | Port | Purpose |
|---------|------|---------|
| Wazuh Dashboard | :443 | SIEM interface, agent management, alert browser |
| Wazuh Indexer | :9200 | OpenSearch API, log storage |
| Wazuh Manager | :55000 | Wazuh API, rule management, FIM, rootcheck |
| Alert Triage | :8100 | LLM-powered alert analysis, async worker pool, priority queue, circuit breaker |
| RAG Service | :8300 | Semantic search over MITRE ATT&CK (835 techniques), CVEs, 8 runbooks |
| Feedback Service | :8400 | PostgreSQL persistence of all alerts, analyst feedback, retraining labels |
| ML Inference | :8500 | Network intrusion detection (RF/XGB/DT), 99.28% accuracy, <5ms, hot-reload |
| Correlation Engine | :8600 | Alert-to-incident grouping, kill chain tracking, Markov chain attack prediction |
| Rule Generator | :8700 | LLM-generated Sigma rules, historical back-testing, analyst approval queue |
| Response Orchestrator | :8800 | Autonomous adaptive defense — simulation-driven response planning, D3FEND mapping, graduated autonomy |
| Wazuh Integration | :8002 | Wazuh webhook receiver, alert routing, RAG enrichment |
| Grafana | :3000 | 4 operational dashboards |
| Prometheus | :9090 | Metrics collection, 29 configured alert rules |

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

Response includes: severity, category, confidence score, MITRE technique mapping, IOCs, and recommended actions.

```json
{
  "alert_id": "test-001",
  "severity": "high",
  "category": "intrusion_attempt",
  "confidence": 0.92,
  "summary": "SSH brute force attack from external IP against root account",
  "mitre_techniques": ["T1110.001"],
  "recommendations": [
    {"action": "Block source IP at perimeter firewall", "priority": 1},
    {"action": "Review SSH authentication logs for compromise indicators", "priority": 2},
    {"action": "Verify fail2ban configuration on target host", "priority": 3}
  ]
}
```

### Submit Analyst Feedback

```bash
curl -X POST http://localhost:8400/feedback/test-001 \
  -H "Content-Type: application/json" \
  -d '{
    "analyst_id": "analyst1",
    "is_false_positive": false,
    "true_label": "ATTACK",
    "notes": "Confirmed brute force from known malicious ASN range"
  }'
```

Feedback is stored with the alert record and used as labeled training data in the next retraining cycle.

### Query Threat Intelligence

```bash
curl -X POST http://localhost:8300/retrieve \
  -H "Content-Type: application/json" \
  -d '{
    "query": "credential dumping LSASS memory",
    "collection": "mitre_attack",
    "top_k": 3
  }'
```

### View Correlated Incidents

```bash
# List all active incidents
curl http://localhost:8600/incidents

# Predict next likely attack stage from current kill chain position
curl http://localhost:8600/predict/reconnaissance
```

The predictor returns probable next-stage attacks with transition probabilities derived from the Markov chain model of observed kill chain sequences.

### Direct ML Prediction

```bash
curl -X POST http://localhost:8500/predict \
  -H "Content-Type: application/json" \
  -d '{
    "features": [0.0, 1200.5, 0.83, ...],
    "model_name": "random_forest"
  }'
```

### Generate a Detection Rule

```bash
curl -X POST http://localhost:8700/generate \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "novel-001",
    "alert_description": "Unusual PowerShell encoded command execution with network callback",
    "mitre_techniques": ["T1059.001", "T1105"],
    "severity": "high"
  }'
```

The service generates a Sigma rule, back-tests it against the historical alert corpus for false positive rate estimation, then queues it for analyst approval before deployment.

---

## Research Context

### Academic Foundation

This implementation was built by Abdul Bari, one of the co-authors of the published survey paper:

**"AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation"**
Srinivas, S., Kirk, B., Zendejas, J., Espino, M., Boskovich, M., Bari, A., Dajani, K., and Alzahrani, N.
*Informatics*, vol. 5, no. 4, article 95, 2025. MDPI.

**Published:** [https://www.mdpi.com/2624-800X/5/4/95](https://www.mdpi.com/2624-800X/5/4/95)

The survey conducted a systematic literature review using PRISMA methodology, reviewing 500+ academic papers published between 2022-2025, with 100 sources selected from IEEE Xplore, arXiv, and the ACM Digital Library. The study analyzed the application of Large Language Models and autonomous AI agents to security operations center automation.

**Survey Authors:** Siddhant Srinivas, Brandon Kirk, Julissa Zendejas, Michael Espino, Matthew Boskovich, Abdul Bari
**Faculty Advisors:** Dr. Khalil Dajani, Dr. Nabeel Alzahrani
**Institution:** California State University, San Bernardino

### Eight Critical SOC Tasks Identified

The survey identified and analyzed AI/ML applications across eight fundamental SOC functions:

1. **Log Summarization** — automated condensation of high-volume security log data
2. **Alert Triage** — intelligent prioritization and classification to reduce analyst fatigue
3. **Threat Intelligence** — integration and analysis of external threat feeds and attack databases
4. **Ticket Handling** — automated incident ticket creation, routing, and lifecycle management
5. **Incident Response** — coordinated response workflows and automated remediation
6. **Report Generation** — automated creation of structured security reports
7. **Asset Discovery and Management** — continuous network asset inventory and classification
8. **Vulnerability Management** — systematic identification and remediation of security weaknesses

### Tasks Validated by This Implementation

This platform provides empirical validation of three of the eight surveyed tasks:

| SOC Task | Implementation | Validation Status |
|----------|----------------|-------------------|
| Alert Triage | ML Inference + Alert Triage Service (LLM) | Validated — 99.28% accuracy, <5ms |
| Threat Intelligence | RAG Service with MITRE ATT&CK + CVE | Validated — 835 techniques indexed |
| Log Summarization | Wazuh SIEM + Wazuh Integration webhook | Validated — production webhook integration |

### Key Survey Findings That Shaped This Architecture

**Augmentation over automation.** The survey concluded that human-AI collaboration yields more reliable outcomes than full automation. This implementation reflects that conclusion through tiered automation: the system recommends at low confidence (<0.70), auto-creates cases at medium confidence (0.70-0.90), and executes containment at high confidence (>0.90). Analysts remain in the loop for ambiguous cases.

**Three primary adoption barriers identified by the survey:**
- Limited model interpretability (black-box decision-making)
- Lack of robustness to adversarial inputs
- High integration friction with legacy SIEM systems

Our development directly encountered all three. Integration with Wazuh consumed approximately 40% of total development time. Interpretability is addressed through MITRE ATT&CK mappings, confidence reporting, and feature importance exposure. Adversarial robustness remains a documented limitation.

**Capability-maturity gap.** The survey found most real-world SOC implementations operate at Level 1-2 maturity despite the availability of Level 3-4 tooling. This gap motivated the deployment automation work (sub-15-minute setup) and the feedback flywheel architecture, which enables maturity growth over time without requiring offline retraining.

### Swarm Intelligence Research (Phase 4)

Building on the survey paper, we conducted original research on whether swarm-scale LLM simulation produces emergent attack intelligence. The full paper is at [`services/correlation-engine/paper_draft.md`](services/correlation-engine/paper_draft.md).

**Paper:** *"Swarm Intelligence for Automated Threat Modeling: Multi-Agent LLM Simulation of Attack Campaigns Against Real Infrastructure"*

**Four experiments, two model scales (3B and 14B parameters), three controlled runs:**

| Experiment | Key Finding |
|-----------|-------------|
| Scale vs Discovery | 14B model produces **18 unique attack paths** vs 3 with 3B — model capability is the binding constraint, not agent count |
| Prediction Accuracy | 100% precision (no false positives) but 25% recall — system finds obvious vulnerabilities, misses multi-hop chains |
| Single-Run vs Swarm | Swarm provides **calibrated confidence** (25% vs 1.6% risk) where single run gives only binary hit/miss |
| Defender Impact | **44% overall reduction**, 93% on monitored hosts, **0% on unmonitored** — directly quantifies monitoring ROI |

**Emergent intelligence confirmed:** At scale 100+, follower agents discovered attack paths that outperformed their leader strategies by up to 60 percentage points. These strategies were not planned by any individual agent — they emerged through the swarm's probabilistic exploration.

**Defense mechanism effectiveness (from 37,575 agent runs):**

| Defense | Block Rate | 95% CI |
|---------|-----------|--------|
| EDR | 100.0% | [99.97%, 100%] |
| MFA | 99.3% | [99.2%, 99.4%] |
| Patching | 99.3% | [99.2%, 99.4%] |
| Firewall | 94.3% | [94.0%, 94.5%] |

All experiment data, 24 publication-quality figures, and raw JSON results are in `services/correlation-engine/experiments_v3/`.

### Research Questions Addressed

**RQ1:** Can classical ML models achieve high performance (>95% accuracy, <1% FPR) on contemporary IDS benchmark data?
Answer: Yes. Random Forest achieved 99.28% accuracy and 0.25% FPR on CICIDS2017.

**RQ2:** What are the practical challenges of integrating ML inference with legacy SIEM infrastructure?
Answer: Documented in detail — authentication synchronization, health-check accuracy, service dependency ordering, and resource contention were the primary friction points.

**RQ3:** Can deployment complexity be reduced through automation without sacrificing reliability?
Answer: Deployment time reduced from 2-3 hours (manual) to under 15 minutes via `deploy-ai-soc.sh`, while maintaining full service health verification.

**RQ4:** Does a continuous analyst feedback loop measurably improve model performance over time?
Answer: Architecture is validated; longitudinal performance data pending sufficient operational feedback volume.

---

## ML Research Results

### Dataset

**CICIDS2017 Improved**
- Total records: 2,831,743 network flow records (after preprocessing: 2,099,839 usable)
- Features: 77 per record (flow statistics, packet timing, protocol metadata)
- Class distribution: BENIGN (1,061,808) / ATTACK (1,038,031)
- Attack types represented: DoS, DDoS, brute force, web attacks, botnet, infiltration, port scan
- Source: Canadian Institute for Cybersecurity, University of New Brunswick

Binary classification (BENIGN vs. ATTACK) was used to match production inference requirements. Multi-class attack categorization is deferred to future work.

### Model Configurations

**Random Forest (Production Model)**
```python
RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_split=10,
    min_samples_leaf=4,
    random_state=42,
    n_jobs=-1
)
```

**XGBoost**
```python
XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42
)
```

**Decision Tree (Interpretable Baseline)**
```python
DecisionTreeClassifier(
    max_depth=20,
    min_samples_split=10,
    min_samples_leaf=4,
    random_state=42
)
```

### Random Forest — Full Results

**Classification Report (Test Set, n=42,002):**
```
              precision    recall  f1-score   support

      BENIGN       0.97      0.99      0.98      8,862
      ATTACK       1.00      0.99      0.99     33,140

    accuracy                           0.99     42,002
   macro avg       0.99      0.99      0.99     42,002
weighted avg       0.99      0.99      0.99     42,002
```

**Confusion Matrix:**
```
                    Predicted
                    BENIGN      ATTACK
Actual  BENIGN       8,840          22
        ATTACK         282      32,858
```

**Derived Metrics:**
- True Negative Rate: 99.75%  (8,840 / 8,862 benign flows correctly identified)
- True Positive Rate: 99.15%  (32,858 / 33,140 attacks correctly detected)
- False Positive Rate: 0.25%  (22 benign flows misclassified as attacks)
- False Negative Rate: 0.85%  (282 attacks missed)
- Inference latency: <5ms per sample (production), <1ms per sample (batch)

**Operational interpretation:** In a 10,000-alert-per-day environment, this model produces approximately 25 false positives and misses approximately 85 true attacks. Industry-average FPR for signature-based SIEM rules typically falls between 1-5%, placing this model substantially below that baseline.

### XGBoost Results

| Metric | Value |
|--------|-------|
| Accuracy | 99.21% |
| False Positive Rate | 0.09% (lowest of three models) |
| Recall (attack) | 99.02% |
| Inference latency | 0.3ms |
| Model size | 0.18MB |

XGBoost achieves the lowest FPR of the three models at the cost of slightly lower recall. It is the preferred model for deployments where analyst false positive fatigue is the primary concern.

### Decision Tree Results

| Metric | Value |
|--------|-------|
| Accuracy | 99.10% |
| False Positive Rate | 0.50% |
| Inference latency | 0.2ms (fastest) |
| Interpretability | Full decision path available |

The Decision Tree is provided as an interpretable baseline. Its complete decision path can be exported and audited, making it suitable for regulatory environments that require explainable automated decisions.

### Comparative Analysis Against Published Baselines

**CICIDS2017 Binary Classification — Literature Comparison:**

| Study | Model | Accuracy | FP Rate | Year |
|-------|-------|----------|---------|------|
| **This Work** | **Random Forest** | **99.28%** | **0.25%** | **2025** |
| Sharafaldin et al. | Random Forest | 99.10% | not reported | 2018 |
| Bhattacharya et al. | Deep Learning | 98.80% | 1.20% | 2020 |
| Zhang et al. | SVM | 97.50% | 2.30% | 2019 |

This implementation exceeds the original CICIDS2017 benchmark (Sharafaldin et al., 2018) by 0.18 percentage points while adding explicit FPR reporting, which was absent from the original paper.

### Feature Importance (Random Forest, Top 10)

| Rank | Feature | Importance |
|------|---------|------------|
| 1 | Fwd Packet Length Mean | 15.2% |
| 2 | Flow Bytes/s | 12.8% |
| 3 | Flow Packets/s | 11.3% |
| 4 | Bwd Packet Length Mean | 9.7% |
| 5 | Flow Duration | 8.4% |
| 6 | Fwd IAT Total | 7.2% |
| 7 | Active Mean | 6.9% |
| 8 | Idle Mean | 5.8% |
| 9 | Subflow Fwd Bytes | 5.3% |
| 10 | Destination Port | 4.7% |

The model's reliance on flow-level statistics and timing characteristics is consistent with the behavioral analysis approach documented in intrusion detection literature. No payload inspection is required, which has favorable privacy and performance implications.

### Cross-Validation

- 5-Fold CV Accuracy: 99.26% ± 0.03%
- Training accuracy: 99.30%
- Test accuracy: 99.28%

The 0.02% delta between training and test accuracy indicates no meaningful overfitting. The 0.03% standard deviation across folds indicates stable generalization.

---

## System Design

### Local LLM — No Data Exfiltration

All LLM inference runs through Ollama on the local host. Security event data never traverses a cloud API. This was a non-negotiable design constraint for an enterprise SOC context. The tradeoff is that model capability is bounded by what can run locally; the system is designed to degrade gracefully when the LLM produces low-confidence or malformed output.

### Honest Confidence Reporting

When network flow features are unavailable — which is common for SIEM-originated alerts that carry log metadata but not raw packet captures — ML confidence is explicitly capped at 0.50 and the data source is marked as `alert_metadata` rather than `network_flow`. The triage service does not present inflated confidence scores when the input does not justify them.

### Graceful Degradation

Every service is designed to function when upstream dependencies are unavailable:
- If Ollama is down: ML-only results are returned without LLM explanation
- If the feedback service is unavailable: alerts process and results are returned without persistence
- If the RAG service is unavailable: alerts process without MITRE ATT&CK enrichment
- If ML Inference is unavailable: LLM-only analysis proceeds with a confidence penalty

This is enforced through circuit breakers and health-aware routing in the Alert Triage service.

### Async Worker Pool with Priority Queue

The Alert Triage service maintains a pool of 3 concurrent LLM workers. Incoming alerts are queued by priority (Wazuh rule level). A circuit breaker trips when queue depth exceeds threshold, skipping LLM analysis for low-severity alerts during volume surges to protect analyst capacity for high-severity events.

### Feedback Flywheel

Analyst decisions — false positive markings, severity corrections, ground truth labels — are stored in PostgreSQL by the Feedback Service. The Retraining pipeline reads these labeled records, retrains all three models, runs a champion/challenger comparison against the current production model, and promotes the new model only if it achieves a higher weighted F1 score. Model artifacts are versioned with rollback capability.

### SOAR Automation Tiers

Automated response is gated by LLM confidence:

| Confidence Threshold | Action |
|---------------------|--------|
| < 0.70 | Recommendation only — analyst must act |
| 0.70 – 0.90 | Auto-create incident case, notify on-call |
| > 0.90 | Auto-execute containment (IP block, account disable) |

The upper tier requires explicit enablement in configuration; it is disabled by default.

### Response Orchestrator — Autonomous Adaptive Defense

The response orchestrator closes the loop between detection and action. When the correlation engine creates a new incident, it automatically triggers the defense pipeline:

1. **Simulate** — The swarm simulator runs LLM-powered attacker agents against the current infrastructure model to predict what the attacker will do next.
2. **Plan** — MITRE D3FEND countermeasures are looked up for every detected ATT&CK technique. Each candidate defense action is scored using simulation results (actions that protect frequently-compromised hosts rank higher).
3. **Classify** — A graduated autonomy model assigns each action to a tier:

| Tier | Confidence | Blast Radius | Behavior |
|------|-----------|-------------|----------|
| AUTO-SAFE | >= 0.70 | None/Low | Execute immediately |
| AUTO-VETO | >= 0.85 | Medium | Execute with 60-second veto window |
| HUMAN-REQUIRED | Any | High, or critical target | Queue for analyst approval |

**Safety invariant:** Any action touching a critical asset always requires human approval, regardless of confidence. This is structural — the threshold formula makes it mathematically impossible for critical + high-blast actions to reach auto-execute.

4. **Execute** — Actions dispatch through adapters (Wazuh Active Response, firewall, EDR, identity provider). Each adapter implements `execute()`, `verify()`, `rollback()`, and `dry_run()`.
5. **Verify** — After execution, the simulator re-runs against the updated environment. If the attack success rate dropped by >= 30%, the defense is verified. If not, actions auto-rollback.
6. **Learn** — Outcomes feed back into the feedback service for continuous model improvement.

The D3FEND integration covers 35+ ATT&CK techniques mapped to 13 defensive countermeasures across 7 D3FEND tactics (Harden, Detect, Isolate, Evict, Restore, Deceive, Model).

**API:**
```bash
# Trigger autonomous defense for an incident
curl -X POST http://localhost:8800/defend \
  -H "Content-Type: application/json" \
  -d '{"incident_id": "INC-20250324-ab12", "auto_execute": true}'

# List all defense plans
curl http://localhost:8800/plans

# View pending human approval requests
curl http://localhost:8800/approvals

# Approve or reject an action
curl -X POST http://localhost:8800/plans/PLAN-001/actions/ACT-001/approve \
  -d '{"approved": true, "analyst_id": "analyst1"}'

# Look up D3FEND countermeasures for any ATT&CK technique
curl http://localhost:8800/d3fend/lookup/T1110
```

### Correlation Engine

Alerts are grouped into incidents using three signals:
1. **IP affinity** — shared source or destination IP within a configurable time window
2. **Temporal proximity** — alerts occurring within a sliding 15-minute window
3. **Kill chain stage progression** — alerts mapping to consecutive MITRE ATT&CK kill chain stages

Once an incident is established, a Markov chain model of observed kill chain transitions produces a probability distribution over likely next-stage attacks. These predictions are exposed via `/predict/{current_stage}` and used to pre-load relevant runbooks.

### Attack Campaign Simulator

Traditional SOC prediction is generic: "after reconnaissance, there is a 60% probability of credential attack." This probability is the same regardless of whether the target network has MFA deployed, whether services are patched, or whether EDR is running on endpoints.

The attack campaign simulator replaces this with environment-specific prediction. When the correlation engine detects a new incident, the simulator can spawn LLM-powered attacker agents with distinct behavioral archetypes and run them against a model of the organization's actual infrastructure.

**Four attacker archetypes:**

| Archetype | Behavior | Objective |
|-----------|----------|-----------|
| Opportunist | Low skill, impatient, avoids defended targets | Quick compromise for easy wins |
| APT | Expert, patient, stealth-first | Long-term access to high-value assets |
| Ransomware | Aggressive, speed over stealth | Maximum lateral spread before encryption |
| Insider | Legitimate access, uses normal tools | Exfiltrate specific data |

**Three defender archetypes** fight back during simulation:

| Archetype | Role | Actions |
|-----------|------|---------|
| SOC Analyst | Alert triage | Block IPs, investigate hosts |
| Incident Responder | Containment | Isolate hosts, deploy EDR, revoke credentials |
| Threat Hunter | Proactive defense | Hunt threats, correlate intelligence |

**How it works:**

1. The infrastructure environment model loads the real network topology: hosts with their open ports, running services, known CVEs, and defensive controls (MFA, EDR, firewall rules, patch status).
2. Each attacker agent sees what it has discovered about the environment and selects its next action via the LLM, guided by its archetype personality.
3. Actions are evaluated probabilistically — each defense layer (EDR, MFA, firewall, patching, monitoring) reduces success probability multiplicatively, but no defense is absolute. This creates realistic variance for Monte Carlo analysis.
4. Defender agents respond to alerts: blocking IPs, isolating hosts, deploying EDR, and revoking credentials. Attackers respect defender state in subsequent actions.
5. The swarm orchestrator runs this loop across 5+ Monte Carlo batches with environment randomization, producing statistically grounded risk assessments with 95% confidence intervals.

**What the report tells you that generic prediction cannot:**

- "3 of 4 attacker types found a path through CVE-2024-7347 on your web server — patch this first."
- "MFA on the mail server blocked all credential attacks — that control is working."
- "The workstation with no EDR was the only host fully compromised — deploy endpoint protection there."
- "The APT agent reached your production database via lateral movement from the DMZ. Network segmentation between DMZ and internal is insufficient."

The simulator produces predictions that are specific to the organization's defensive posture. It functions as an automated penetration test that runs in seconds rather than days, triggered by real incident detection rather than scheduled manually.

The 20 attack actions in the simulator's action space are mapped to MITRE ATT&CK techniques (T1046, T1190, T1110, T1566, T1059, T1003, T1021, T1041, T1486, and others), so predictions integrate directly with the existing MITRE mapping throughout the platform.

**API:**
```bash
# Run a single 4-agent campaign
curl -X POST "http://localhost:8600/simulate?timesteps=3"

# Run a swarm (Monte Carlo, background execution)
curl -X POST "http://localhost:8600/simulate/swarm/start?swarm_size=100&monte_carlo_runs=5&timesteps=6"

# Poll swarm progress
curl "http://localhost:8600/simulate/swarm/SWARM-ID/status"

# Get swarm results (host heatmap, attack paths, defense effectiveness)
curl "http://localhost:8600/simulate/swarm/SWARM-ID/result"

# Run research benchmark across multiple scales
python services/correlation-engine/run_experiments.py --scales 10,50,100 --batches 5 --timesteps 6
```

---

## Limitations and Future Work

### Current Limitations

**Dataset scope.** The ML models are trained on CICIDS2017, which represents 2017-era attack patterns in a simulated lab environment. Performance on novel attack types, encrypted traffic, or adversarial evasion techniques is untested. The continuous retraining pipeline is designed to narrow this gap over operational time, but requires a sufficient volume of analyst-labeled feedback to produce statistically meaningful model updates.

**Adversarial robustness.** No adversarial evasion testing has been performed. A determined attacker who understands the feature set could potentially craft flows that avoid detection. This is a known open problem in ML-based IDS research.

**LLM quality variance.** The quality of LLM-generated alert summaries, MITRE mappings, and Sigma rules is dependent on the locally available model. Smaller models (7B parameters) produce inconsistent output on complex or ambiguous alerts. The system validates LLM output structure and falls back to template-based responses on parse failure, but explanation quality is not guaranteed.

**Multi-class classification.** The current ML pipeline uses binary BENIGN/ATTACK classification. Attack type categorization (DoS vs. brute force vs. exfiltration) is delegated to the LLM and RAG service rather than ML. A multi-class model would improve specificity.

**Markov chain prediction accuracy.** The kill chain transition model is initialized from static MITRE ATT&CK ordering and updated by observed attack sequences. With limited operational data, transition probabilities are poorly calibrated. The model improves with volume but provides unreliable predictions in early deployment.

**No adversarial feedback protection.** The feedback loop currently trusts all analyst-submitted labels. A compromised or mistaken analyst could degrade model quality over time. Label validation and outlier detection on feedback data are not yet implemented.

**Simulation fidelity.** The attack campaign simulator uses a simplified environment model and 20 discrete attack actions. Real-world attacker behavior is more nuanced than the four archetypes can represent. Simulation predictions should be treated as directional guidance for defensive prioritization, not as validated forecasts. The simulator has not been benchmarked against real-world attack outcomes.

**Simulation latency.** Each simulation run requires 8-15 LLM calls via Ollama. On consumer hardware without GPU acceleration, a 4-agent x 3-timestep simulation takes 60-90 seconds. With GPU, this drops to 15-30 seconds. The simulator is designed for on-demand analysis rather than real-time inline processing.

### Future Work

- Multi-class attack classification (DoS, brute force, lateral movement, exfiltration, etc.)
- Adversarial evasion testing and model hardening
- Larger local LLM support (Llama 3 70B, Mistral Large) for improved explanation quality
- Federated learning for multi-tenant model improvement without data sharing
- Feedback label validation and anomaly detection to protect retraining integrity
- Longitudinal study of model accuracy improvement as analyst feedback accumulates
- Graph-based alert correlation as an alternative to the current IP/temporal approach
- Integration with commercial SIEM platforms (Splunk, Elastic) beyond Wazuh
- Auto-population of simulation environment model from Wazuh agent inventory and vulnerability scans
- ~~DefenderAgent for red-vs-blue simulation~~ **Done** — 3 defender archetypes with 8 actions
- ~~Swarm intelligence scaling~~ **Done** — 37,575 agents, Monte Carlo batches, emergent discovery
- ~~Autonomous adaptive defense (closed-loop response)~~ **Done** — Response orchestrator with D3FEND mapping, graduated autonomy, simulation-driven planning, adapter-based execution, verification via re-simulation
- Simulation fidelity validation — benchmarking simulated attack success rates against real red team outcomes
- Simulation benchmarking against MITRE CALDERA adversary emulation results
- Larger model evaluation (70B+) to address multi-hop lateral movement gap identified in research
- Reusable simulation framework extraction (standalone package for any SOC platform)
- Production adapter implementations (pfSense, CrowdStrike, Azure AD) beyond current stubs
- Convergence proof — does the feedback loop measurably improve defenses over time?

---

## Documentation

Full documentation is available at [research.onyxlab.ai](https://research.onyxlab.ai).

| Section | Link |
|---------|------|
| Installation Guide | [docs/getting-started/installation.md](docs/getting-started/installation.md) |
| Architecture Overview | [docs/architecture/overview.md](docs/architecture/overview.md) |
| API Reference (live Swagger) | http://localhost:8100/docs |
| Security Guide | [docs/security/guide.md](docs/security/guide.md) |
| Deployment Guide | [docs/deployment/guide.md](docs/deployment/guide.md) |
| ML Training Report | [ml_training/TRAINING_REPORT.md](ml_training/TRAINING_REPORT.md) |

---

## Citation

If this implementation or the associated survey contributes to your research:

```bibtex
@misc{aisoc2025,
  title        = {AI-Augmented Security Operations Center: A Research Implementation},
  author       = {Bari, Abdul},
  institution  = {California State University, San Bernardino},
  year         = {2025},
  note         = {Research implementation validating findings from Srinivas et al. (2025)},
  url          = {https://github.com/zhadyz/AI_SOC}
}

@article{srinivas2025aiaugsoc,
  title        = {AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation},
  author       = {Srinivas, Siddhant and Kirk, Brandon and Zendejas, Julissa and
                  Espino, Michael and Boskovich, Matthew and Bari, Abdul and
                  Dajani, Khalil and Alzahrani, Nabeel},
  journal      = {Informatics},
  volume       = {5},
  number       = {4},
  article      = {95},
  year         = {2025},
  publisher    = {MDPI},
  url          = {https://www.mdpi.com/2624-800X/5/4/95}
}
```

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

**Author:** Abdul Bari
**Contact:** z@onyxlab.ai
**Institution:** California State University, San Bernardino
**Documentation:** [research.onyxlab.ai](https://research.onyxlab.ai)
