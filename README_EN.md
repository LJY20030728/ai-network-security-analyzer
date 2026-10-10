# AI Network Security Analyzer

> AI-Assisted Network Forensics System — PCAP Offline Analysis + Three-Engine Stacking Fusion Detection + LLM Threat Assessment + RAG Security Knowledge Q&A

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green.svg)](https://fastapi.tiangolo.com/)
[![Gradio](https://img.shields.io/badge/Gradio-6.x-orange.svg)](https://www.gradio.app/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-265%20passed-brightgreen.svg)](#test-coverage)

**[中文版 README](README.md) | English Version**

---

## Table of Contents

- [Project Overview](#project-overview)
- [Core Features](#core-features)
- [Technical Architecture](#technical-architecture)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [API Documentation](#api-documentation)
- [Evaluation Results](#evaluation-results)
- [Project Structure](#project-structure)
- [Development](#development)
- [FAQ](#faq)

---

## Project Overview

This system turns a raw `.pcap` capture into a human-readable, evidence-traceable
forensic conclusion. It is built for analysts who need to answer
"what happened in this traffic, and can I defend that conclusion?"

**Design principle: a claim must be reproducible, or it is removed.**
Every metric in this document is backed by a script that still exists in the
repository. When the supervised model was removed in 3.3.0, the metrics that
depended on it became unreproducible — those numbers and their result artifacts
were deleted rather than left behind (see [Evaluation Results](#evaluation-results)).

### Why This Project?

- **Offline-first.** Core detection needs no API key and no network.
- **Multi-engine by design.** Rule thresholds, an EWMA time-series baseline, and an
  unsupervised Isolation Forest feed a Stacking meta-learner, so one engine's blind
  spot is not automatically the system's blind spot.
- **Honest confidence labeling.** When the meta-learner is unavailable, the output is
  explicitly labeled `weighted_fallback` — it is never presented as a model output.
- **Evidence provenance.** Reports carry the source-file SHA-256, a case ID, the rule
  version, and a content hash in the filename.

---

## Core Features

### 🔍 Three-Engine Stacking Fusion (13-dimensional features)

| Engine | Method | What it targets |
|---|---|---|
| Rule engine | Threshold rules (9 classes, TCP + UDP + QUIC) | SYN flood, port scan, DNS tunnel, RST storm, large transfer, UDP flood, DNS amplification, QUIC flood, long-lived QUIC |
| Time-series baseline | EWMA + median/MAD robust z-score over 4 window dimensions | Magnitude shifts against a learned normal profile |
| Isolation Forest | Unsupervised; jointly models the 4 window dimensions | Coupling anomalies that no single dimension reveals |

Their outputs are fused by a `LogisticRegression` meta-learner over 13 features.

### 🛡️ Confidence Provenance Labeling

`confidence_source` is always reported as one of:

- `model` — produced by the meta-learner's `predict_proba`;
- `weighted_fallback` — a **hand-set** weight fallback for when the meta-learner is
  missing or fails. This is explicitly *not* a model output.

### 🤖 LLM Threat Assessment

The LLM converts detection output into an analyst-readable narrative with
recommended actions. It is **advisory only**: verdicts, severities and report
conclusions do not depend on it, and the system behaves identically with the AI
features disabled.

### 📚 RAG Security Knowledge Q&A

Local vector store (BGE Chinese embeddings via ONNX) + BM25 + RRF fusion +
term-aware reranking, over MITRE ATT&CK techniques and response handbooks.

> ⚠️ **Not fully offline on first run**: if the embedding model is absent, it is
> downloaded (~95 MB) on first use. See [Quick Start](#quick-start) step 3.

### 📋 Forensic Report (five elements)

Event timeline, ATT&CK kill-chain view, IOC list, evidence chain
(alert → evidence → engine), and a free-text analyst-notes area.

### 🔒 Security & Engineering

- `X-API-Token` middleware; token auto-generated on first run.
- API key stored via Windows DPAPI (ctypes `CryptProtectData`, no extra dependency).
- Pydantic-validated configuration; SQLite with WAL.
- CI matrix: Linux (3.11 / 3.13) + Windows (DPAPI-specific branches).

---

## Technical Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Presentation:  Gradio Web UI  +  FastAPI REST API  +  Desktop shell │
├─────────────────────────────────────────────────────────────────────┤
│  Service layer: run_analysis()  ← the single analysis pipeline       │
│                 (parse → detect → AI → hallucination control →       │
│                  report → persist); consumed by both UI and API      │
├─────────────────────────────────────────────────────────────────────┤
│  Detection:     rule engine │ EWMA baseline │ Isolation Forest       │
│                            → Stacking meta-learner                   │
├─────────────────────────────────────────────────────────────────────┤
│  Capture:       streaming PcapReader → PacketInfo (O(1) memory)      │
├─────────────────────────────────────────────────────────────────────┤
│  Knowledge:     RAG (BGE ONNX + BM25 + RRF) │ MITRE ATT&CK           │
├─────────────────────────────────────────────────────────────────────┤
│  Storage:       SQLite (history / baselines / audit) │ ChromaDB      │
└─────────────────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology |
|---|---|
| Web framework | FastAPI + uvicorn |
| UI | Gradio 6.x, pywebview (desktop shell) |
| Packet parsing | scapy (streaming `PcapReader`), dpkt |
| ML | scikit-learn (LogisticRegression, IsolationForest) |
| LLM / RAG | OpenAI-compatible API, ChromaDB, ONNX Runtime (BGE) |
| Storage | SQLite (WAL), JSON |
| Packaging | PyInstaller + Inno Setup; Docker |

---

## Quick Start

### Requirements

- Python ≥ 3.11
- Windows recommended (DPAPI-encrypted key storage; other platforms fall back to plaintext)

### Method 1: Run from Source

```bash
# 1. Clone the repository
git clone https://github.com/LJY20030728/ai-network-security-analyzer.git
cd ai-network-security-analyzer

# 2. Create a virtual environment and install ALL dependencies (required)
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt

# 3. Download large resources (~90 MB) — required on first run
#    The BGE embedding model is not committed to the repository.
python tools/init_resources.py

# 4. Configure the API key (only needed for AI features; core detection works without it)
copy .env.example .env
# Edit .env and set LLM_API_KEY, or configure it later in the UI Settings tab (DPAPI-encrypted)

# 5. Start
python desktop_app.py          # desktop window
# or: python run.py            # API service at http://127.0.0.1:8080
```

### Method 2: Windows Installer

Download the installer from Releases / CI artifacts (`installer_output/*.exe`) and
run it. It bundles Python and all dependencies, and installs the WebView2 runtime
if missing.

### Method 3: Docker

```bash
docker compose up -d
# then open http://localhost:8080
```

---

## Usage Guide

1. **PCAP analysis** — upload a `.pcap`/`.pcapng`, optionally pick a baseline, then
   start the analysis. Progress is streamed in four stages.
2. **Baseline management** — learn a baseline from normal traffic; the profile is
   stored in SQLite and mirrored to JSON.
3. **Security Q&A** — ask questions against the RAG knowledge base.
4. **Analysis history** — browse past analyses, reopen reports, re-analyze.
5. **Settings** — configure the LLM key and base URL; inspect diagnostics.

---

## API Documentation

Once running, Swagger is available at `http://127.0.0.1:8080/docs`.

### Core API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Health check (no token required) |
| `/api/pcap/analyze` | POST | Analyze an uploaded PCAP |
| `/api/pcap/analyze_async` | POST | Submit an async analysis task |
| `/api/tasks/{task_id}` | GET | Poll an async task |
| `/api/knowledge/search` | POST | RAG knowledge search |
| `/api/chat` | POST | Security Q&A |
| `/api/baseline/learn` | POST | Learn a baseline |
| `/api/baseline/list` | GET | List baselines |
| `/api/baseline/delete` | POST | Delete a baseline |
| `/api/forensic/stats` | GET | Forensic knowledge-base stats |
| `/api/forensic/trend` | GET | Attack trend analysis |
| `/api/forensic/related/{analysis_id}` | GET | Cross-sample correlation |
| `/api/forensic/iocs/{analysis_id}` | GET | Extract IOCs from an analysis |
| `/api/config/status` | GET | Configuration status (key masked) |
| `/api/config/validate` | POST | Validate the API key |
| `/api/config/save_secure` | POST | Save to the DPAPI-encrypted store |
| `/api/audit/logs` | GET | API audit log |
| `/api/audit/stats` | GET | Audit statistics |
| `/api/logs` | GET | Log viewer |
| `/api/logs/stats` | GET | Log statistics |
| `/api/diagnostic` | GET | One-shot diagnostic report |
| `/api/incident/report` | POST | Generate an incident report |

### Authentication

All `/api/*` endpoints except `/api/health` require an `X-API-Token` header. The
token is generated automatically on first run and persisted to `.env` as
`API_AUTH_TOKEN`. In-process Gradio UI calls are unaffected.

---

## Evaluation Results

> **Scope note.** Only metrics whose scripts remain in the repository are listed
> here, and each can be re-run. When the supervised model was removed in 3.3.0, its
> supporting scripts (`tune_thresholds.py`, `generalization_eval.py`,
> `fusion_comparison.py`, `feature_importance.py`, `eval_unsw_oot.py`) and datasets
> were deleted as well. **Metrics that could no longer be reproduced were removed
> together with their result artifacts (JSON/CSV/PNG)** rather than left in place as
> misleading numbers. Metrics not listed here belong to retired experiments and are
> not claimed by this project.

### Three-Engine Fusion: Meta-Learner Training

| Metric | Value |
|---|---|
| Training windows (after deduplication) | **1368** (664 attack / 704 normal, 17 sample groups) |
| Rows before deduplication | 1727 (359 bit-identical rows removed) |
| Window size | 10 s |
| **5-fold CV F1 (GroupKFold by source PCAP — no leakage)** | **0.7425 ± 0.2700** |
| Reference: plain stratified CV (same-sample windows across folds) | 0.9194 ± 0.0148 |

> **How to read this.** The gap between the two CV rows *is* the measured effect of
> within-sample leakage — roughly +0.18 F1 of inflation. The primary figure must be
> the GroupKFold one. The **±0.27 standard deviation** means the model is highly
> sensitive to which samples it is trained on; that is a real limitation at this data
> scale, and quoting only the mean would misrepresent it.
>
> The training data is synthetic and weakly labeled (window labels are derived from
> attack-segment timing, not per-flow human annotation). **These weights should not
> be read as an optimal fusion policy for production.** See `tools/train_stacking.py`.

### Per-Engine Independent Evaluation

| Evaluation | Script | Artifact |
|---|---|---|
| Isolation Forest vs EWMA baseline (FPR / TPR) | `tools/eval_ml_engine.py` | `data/eval_perf/ml_engine.json` |
| Baseline window/σ sensitivity grid | `tools/eval_window_sensitivity.py` | `data/eval_perf/window_sensitivity.json` |
| Baseline incremental value (rules only vs rules + baseline) | `tools/verify_baseline_value.py` | terminal output |
| Meta-learner training | `tools/train_stacking.py` | `models/stacking_meta_learner.joblib` + `data/eval_perf/stacking_training.json` |

Only `eval_ml_engine.py` uses a genuine held-out split (80/20 on the normal
capture); the sensitivity grid fits and scores on the same windows, so its FPR
values are in-sample self-tests rather than FPR estimates.

### RAG Retrieval (Dual-Caliber Recall@k / MRR)

Evaluated on a 16-question golden set against the production retrieval path
(BGE Chinese embeddings + BM25 + RRF + term-aware reranking):

| Caliber | Recall@1 | Recall@3 | Recall@5 | MRR@5 |
|---|---|---|---|---|
| **Strict** (single authoritative entry) | 0.6875 | 1.0000 | 1.0000 | 0.8333 |
| **Relevant** (relevant-document set) | **0.8750** | 1.0000 | 1.0000 | **0.9375** |

- Vector store: **1687 chunks / 63 entries** (including 697 active ATT&CK techniques).
- Two known top-1 flaws are reported rather than tuned away; see
  `data/eval_rag/rag_result.json` for raw per-query results.
- **Caveat:** Recall@3 and Recall@5 both saturate at 1.0 on this set, so only
  Recall@1 discriminates. The "Relevant" gold sets are author-defined and include
  loose protocol tokens, making 0.8750 an upper bound rather than a measurement.

### Streaming vs Full-Load Memory (300k packets / 28 MB PCAP)

All three engines run inside a single streaming pass and never hold the full packet
list.

| Mode | Time | Peak memory | Alerts |
|---|---|---|---|
| Full load (`rdpcap` + `analyze_packets`) | 380.8 s | **1207.7 MB** | 15 |
| **Streaming (`PcapReader` + `analyze_stream`)** | 325.3 s | **18.6 MB** | 15 |

- Peak memory reduced ~**65×** (1207.7 MB → 18.6 MB) with **identical alerts (15/15)**.
- ⚠️ **Timing varies**: the same file measured 244.0 s and 325.3 s on the same
  machine (33% spread). Cross-version comparison of memory and alert agreement is
  reliable; absolute timings are not.
- Raw data: `data/eval_perf/perf_baseline.json`.

### Regression Verification (multi-caliber)

| Verification | Command | Result |
|---|---|---|
| Golden-sample regression | `python tools/verify_golden.py` | Attack hits **5/5**; normal-traffic alerts **1 (threshold ≤3) → exit 0** |
| Stress-test alert consistency | `python tools/bench_stream.py` | Full-load 15 / streaming 15 → **PASS** |
| Engine independence | `python tools/eval_ml_engine.py` | Isolation Forest FPR=0.04 / TPR=0.857; EWMA baseline FPR=0 / TPR=0.4286 |

> **Fixed (previously an open issue).** `verify_golden.py` used to exit non-zero
> with 5 false positives on normal traffic, all `ML_ANOMALY` alerts. The root cause
> was a **semantics mismatch, not a tuning problem**: Isolation Forest is a
> *bidirectional* statistical outlier detector, while a security threat is
> *one-directional* (resource exhaustion, scanning, exfiltration — i.e. traffic
> *above* baseline). Four of the five alerts were windows that were quieter than
> baseline, which is not a threat. High-side deviations are now the only ones
> promoted to alerts; low-side deviations are recorded separately as
> `behavioral_observations` and carry no severity. The remaining single alert is a
> genuine high-side outlier (destination-port count above baseline).
>
> The tooling that generated the golden samples also used to overwrite
> `data/samples/golden/*.pcap` on every run, silently mutating the regression
> inputs; it now writes to `data/samples/generated/` unless `--update-golden` is
> passed explicitly.

### Test Coverage

| Metric | Value |
|---|---|
| Test result | **265 passed / 0 skipped / 0 failed** |
| Test files | 18 |
| Covered modules | Detection algorithms, API routes, storage, security, service layer, tooling |

---

## Project Structure

```
ai-network-security-analyzer/
├── config/                  # Pydantic settings (.env-driven)
├── src/
│   ├── analysis/            # flow extraction, baseline, Isolation Forest, Stacking
│   ├── ai/                  # LLM client, RAG, threat analysis, hallucination control
│   ├── api/                 # audit log, task queue, history store
│   ├── capture/             # streaming PCAP/packet parsing
│   ├── core/                # exceptions
│   ├── knowledge/           # MITRE ATT&CK, protocol and web-security corpora
│   ├── report/              # HTML forensic report, summary formatter
│   ├── security/            # DPAPI-backed secure store
│   ├── services/            # analysis pipeline (single implementation)
│   ├── storage/             # SQLite, forensic knowledge base, baseline-name rules
│   ├── ui/                  # Gradio app, charts, i18n manager
│   └── utils/               # helpers, paths, error handling, log observer
├── tools/                   # evaluation and training scripts
├── tests/                   # pytest suite
├── data/                    # samples, baselines, knowledge, run artifacts
├── models/                  # Stacking meta-learner; BGE ONNX (downloaded)
└── docs/                    # deployment guide, historical self-audit
```

---

## Development

### Adding a Detection Engine

Engines must produce alerts the fusion layer can consume:

1. Implement the detection logic, aligning with the alert schema used by
   `TrafficAnalyzer._detect_anomalies` (`type`, `severity`, `detector`,
   `time_window`, plus rule-specific evidence fields).
2. Expose the engine's contribution as features in
   `src/analysis/stacking_fusion.py` (`THREE_ENGINE_FEATURE_NAMES`), keeping the
   order consistent with `ENGINE_ORDER` — the loader refuses a model whose engine
   order does not match.
3. Retrain the meta-learner: `python tools/train_stacking.py`.

### Running Tests

```bash
pytest tests                       # full suite
pytest tests/test_charts.py -q     # security regressions only
pytest --cov=src                   # with coverage
```

### Performance Benchmark

```bash
python benchmark_performance.py    # results in data/eval_perf/benchmark_result.json
```

### RAG Evaluation

```bash
python tools/evaluate_rag.py       # results in data/eval_rag/rag_result.json
```

### Retraining the Stacking Meta-Learner

```bash
python tools/train_stacking.py     # writes models/stacking_meta_learner.joblib
```

### Code Standards

`ruff` (E, W, F, I, B, UP, S, C4, SIM) and `mypy` are configured in
`pyproject.toml` for a progressive rollout across core domain modules.

---

## FAQ

### Q1: Is the API key safe? Is it hardcoded anywhere?

No key is hardcoded. On Windows the key is encrypted with DPAPI
(`CryptProtectData`, user-scoped) via `src/security/secure_store.py`.

**Known limitation:** when the key is saved through the UI, it is currently *also*
written in plaintext to `.env` so a restart picks it up. The DPAPI copy is therefore
redundant rather than exclusive. Moving to a DPAPI-only secret path is a tracked
improvement.

### Q2: Does it need network access?

Core detection (rules / baseline / Isolation Forest / Stacking) is fully offline.
Only the AI features need an API key, and the RAG retrieval stack runs locally. Note
that the embedding model is downloaded once on first run if absent.

### Q3: Which LLMs are supported?

Any OpenAI-compatible endpoint. Defaults to Zhipu AI (`glm-4.5-air`); DeepSeek,
OpenAI, and local Ollama have all been used successfully.

### Q4: How much memory does it use?

Streaming analysis peaks at 18.6 MB on a 300k-packet / 28 MB capture, versus
1207.7 MB for the full-load path.

### Q5: How does this differ from Wireshark or Suricata?

| Dimension | Wireshark | Suricata/Snort | **This system** |
|---|---|---|---|
| Analysis | Manual packet inspection | Rule/signature matching | **Multi-engine + AI-assisted assessment** |
| Target user | Network experts | Security engineers | Security ops / analysts |
| Unknown or encrypted traffic | Manual discovery | Blind outside rules | Behavioral baseline + unsupervised anomaly detection |
| Threat interpretation | None | Raw alerts | LLM narrative + recommended actions |
| Knowledge Q&A | None | None | RAG security knowledge base (1687 chunks) |
| Output | Packet list | Alert log | Five-element HTML forensic report |
| Deployment | Local | Server | Installer / Docker / source |

### Q6: How was RAG Recall@5 measured, and is it trustworthy?

See [RAG Retrieval](#rag-retrieval-dual-caliber-recallk--mrr). Two calibers are
reported side by side, the golden set has 16 questions, and the two known top-1
failures are listed rather than tuned away. The honest reading is that Recall@1 is
the only discriminating column, and that the "Relevant" caliber is an upper bound
because its gold sets were authored by the same person who wrote the questions.
Expanding the set with negatives and independent labeling is the next step.

---

## License

MIT — see [LICENSE](LICENSE).
