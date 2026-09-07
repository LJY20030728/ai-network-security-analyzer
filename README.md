# 🛡️ AI Network Security Analyzer

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-105%20cases-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)

**Offline PCAP network traffic analysis with three-engine anomaly detection and LLM-assisted threat assessment.**

A full-stack security engineering project that combines classical network analysis with large language models. It parses Wireshark packet captures, detects attacks through a deterministic rule engine, an EWMA statistical baseline, and an unsupervised isolation-forest engine, then performs AI threat assessment grounded in a MITRE ATT&CK knowledge base (RAG) — producing structured, auditable, evidence-backed analysis reports.

> This project was built as a production-oriented engineering practice in network security + AI. All evaluation numbers in this document are reproducible from this repository.
>
> 📖 For a detailed bilingual system walkthrough (中文详解), see [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md). 中文版另有 [README.zh-CN.md](README.zh-CN.md)。

---

## Features

- **PCAP / PCAPNG analysis** — packet-level parsing with Scapy, flow extraction, protocol distribution, and communication topology
- **Three-engine anomaly detection**:
  - **Rule engine** — SYN Flood, port scan, DNS tunneling, large-flow exfiltration, RST storm
  - **EWMA statistical baseline** — behavior-drift detection (z-score > 3σ) covering sub-threshold / slow anomalies; online rolling update with anti-poisoning guard and KS drift-failure warning
  - **Isolation Forest (ML)** — joint modeling of multi-dimensional window features; captures coupled anomalies (e.g., normal packet count but surging port count)
- **LLM-assisted threat assessment** — structured judgment (JSON + Pydantic validation: threat / confidence / per-alert verdict / MITRE ATT&CK mapping / remediation), automatic fallback on validation failure
- **RAG knowledge base** — ChromaDB + local BGE Chinese embedding (ONNX, offline), hybrid retrieval (vector + hand-written BM25 with RRF fusion), query rewriting
- **Forensic HTML report** — case ID, source SHA-256, detection evidence chain (rule ID / threshold / time window / z-score), baseline deviation, AI judgment, NIST SP 800-61 aligned incident reports
- **Security by design** — local API token auth, SQLite audit logging (WAL, request body excluded), prompt-injection-resistant RAG pipeline, `.env` secrets excluded from repository
- **Engineering quality** — 105 pytest cases, streaming parser (162.8× memory reduction), async task queue for GB-scale analysis, Docker Compose deployment

---

## Architecture

```
PCAP file ──▶ Scapy streaming parser ──▶ Flow extraction / protocol stats / topology
                                              │
                    ┌─────────────────────────┼──────────────────────────┐
                    ▼                         ▼                          ▼
             Rule engine                EWMA baseline              Isolation Forest
             (5 known attacks)          (behavior drift)          (unsupervised, ML)
                    └─────────────────────────┼──────────────────────────┘
                                              ▼
                    RAG retrieval ──▶ MITRE ATT&CK + response playbooks
                                              ▼
                    LLM structured threat assessment (Pydantic-validated)
                                              ▼
                    Evidence-backed analysis report (JSON / HTML / NIST-aligned)
```

### Detection pipeline highlights

- **Rule engine + EWMA baseline are complementary**: the rule engine precisely detects 5 known attack classes with zero false positives on golden samples; the baseline catches sub-threshold slow anomalies (e.g., light scan at 15 ports < rule threshold of 20) that pure rules miss.
- **The ML engine's blind spots are covered by rules** (e.g., portscan), and the rule engine's blind spots are covered by the baseline and ML — the three engines have non-overlapping blind spots.
- **Streaming design**: `iter_packets()` + single-pass `analyze_stream()` keep memory at O(active flows + windows) instead of loading the whole capture.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Packet parsing | Scapy, dpkt |
| Analysis | Python native (flow aggregation, protocol stats, topology) |
| AI / RAG | ChromaDB, langchain, OpenAI-compatible APIs, BGE-small-zh-v1.5 (ONNX) |
| LLM backends | DeepSeek / Zhipu GLM / Qwen / SiliconFlow / local Ollama |
| Backend | FastAPI + Uvicorn |
| Frontend | Gradio (3-tab Web UI, no separate frontend build) |
| ML | scikit-learn (Isolation Forest) |
| Deployment | Docker Compose, PyInstaller + Inno Setup |
| Quality | pytest, structured logging, SQLite audit, streaming memory profiling |

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

> Windows note: this system performs **offline PCAP analysis only** — no Npcap or administrator privileges required.

### 2. Configure the LLM API

```bash
cp .env.example .env   # then edit .env
```

Any OpenAI-compatible endpoint works. Examples in `.env.example`:

```env
# SiliconFlow (free quota) / Zhipu GLM-4-Flash (free) / DeepSeek / Qwen / Ollama local
LLM_API_KEY=sk-...
LLM_BASE_URL=https://api.deepseek.com
LLM_MODEL=deepseek-chat
```

The embedding model (BGE-small-zh-v1.5) is downloaded automatically on first use; no manual model upload is needed.

### 3. Start the service

```bash
python run.py
```

- **Web UI**: http://localhost:8080
- **API docs**: http://localhost:8080/docs

### 4. Docker deployment

```bash
cp .env.example .env   # fill in LLM_API_KEY
docker compose up -d   # http://localhost:8080
```

The knowledge base initializes automatically on first RAG query (idempotent), or manually via the "Knowledge Base" tab.

---

## Usage

| Tab | Function |
|---|---|
| 📊 PCAP Analysis | Upload a `.pcap/.pcapng` file, run analysis, get traffic overview + anomaly alerts + AI threat assessment + full JSON report |
| 💬 Security Q&A | Ask questions grounded in the MITRE ATT&CK knowledge base |
| 📚 Knowledge Base | Init/rebuild, view stats, search, upload `.txt/.md` docs |
| 📈 Baseline | Learn an EWMA baseline from a normal-traffic PCAP; manage multiple baselines |
| 📄 HTML Report | Forensic-style single-file HTML report (inline styles, zero external deps) with evidence chain and source SHA-256 |

---

## Evaluation & Reproducible Results

All experiments below are re-runnable from a fresh clone:

```bash
pip install -r requirements.txt
python tools/evaluate_golden.py          # golden-sample regression
python tools/evaluate_rag.py             # RAG retrieval quality
python tools/eval_llm_judgment.py        # LLM judgment accuracy
python tools/bench_stream.py             # streaming vs full-load performance
python tools/eval_ml_engine.py           # isolation forest
python tools/eval_window_sensitivity.py  # window / sigma sensitivity grid
python -m pytest tests -q                # 105 test cases
```

### Golden-sample detection quality

| Engine | Metric | Result |
|---|---|---|
| Rule engine (5 attack classes + normal) | TP / FP / TN / FN | **5 / 0 / 1 / 0** |
| Rule engine | Precision / Recall / F1 | **1.000 / 1.000 / 1.000** |
| Baseline (normal learn → self-test) | false-positive windows | **0 / 219** |
| Baseline (σ sweep on 5 attack samples) | TPR / FPR | σ=2.0: 0.80 / 0.0046; σ=3.0: 0.60 / 0.0000 |

**Dual-engine coverage** (honest accounting): the rule engine hits all 5 known attacks with zero FP; the baseline captures statistical bursts for 3 of them (synflood z=22.3, portscan z=5.4, largeflow z=32072) but misses slow low-volume attacks (DNS tunnel, RST storm) — exactly covered by the rule engine — while filling 2 rule blind spots (lightscan z=6.07, burst z=8.67). The blind spots of the two engines do not overlap.

### Real-world validation (Lumma Stealer infection chain, 2025-12-30)

Malware traffic from malware-traffic-analysis.net (19.7 MB / 17,013 packets, C2 communication + malicious payload download):

| Check | Result |
|---|---|
| Streaming analysis time | 4.8 s (3.6k pkt/s, peak memory < 10 MB) |
| DNS tunnel detection | 2 (7 over-length DNS queries each) |
| Large-flow exfiltration | 15.0 MB to `172.67.203.237:443` (threshold 10 MB) |
| **IOC cross-check** | 4/4 DNS domains exactly matched public IOCs (`gorcerie.com`, `memory-scanner.cc`, `pastebin.com`, `t.me`) |

### Performance baseline (300,000 packets, 28.1 MB)

| Path | Time | Peak memory | Alerts |
|---|---|---|---|
| Full load (`rdpcap` + analyze) | 246.7 s | **1,112.3 MB** | 15 |
| Streaming (`iter_packets` + analyze_stream) | 244.0 s | **6.8 MB** | 15 |

Memory reduced **162.8×** at equal throughput; alert consistency PASS (15/15).

### RAG retrieval quality (16-question golden set)

| Metric | Before (vector-only) | After (hybrid retrieval) |
|---|---|---|
| Recall@1 / @3 / @5 | 0.9375 / 0.9375 / 0.9375 | **0.9375 / 0.9375 / 1.0000** |
| MRR@5 | 0.9375 | **0.9500** |

Ablation (Recall@5): vector-only 0.9375 → +BM25(RRF) **1.0000** → +query rewriting 0.9375 (improves ranking, MRR↑) → all-enabled **1.0000** (16/16).

### LLM judgment quality (8 golden alert cases, real LLM)

| Metric | Result |
|---|---|
| Structured output success | 100% (8/8) |
| Fallback rate | 0% |
| Threat-verdict accuracy | 75% (6/8) |
| RAG citation rate | 100% (8/8) |
| Avg latency | 8.4 s / call |

Honest failure-mode analysis is documented in `data/eval_perf/llm_judgment.json`: LLM is treated as an **assistant to, not a replacement for**, the deterministic engines; its non-determinism means prompt tweaks must never substitute for rule-based detection.

### LLM incremental value (A/B, L1)

| Dimension | Rules only (A) | Rules + LLM (B) | LLM increment |
|---|---|---|---|
| Information completeness | 0.875 | 0.938 | +0.062 |
| Evidence citation accuracy | 0.875 | 0.875 | 0.000 (no hallucinated citations) |
| Remediation actionability | 0.000 | 0.634 | **+0.634** |

### Isolation Forest (L2, third engine)

| Metric | EWMA baseline | Isolation Forest |
|---|---|---|
| FPR | 0.000 | 0.040 |
| TPR (7 attack samples) | 0.286 | **0.857** |

---

## API Reference

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/knowledge/init` | Initialize knowledge base |
| GET | `/api/knowledge/stats` | Knowledge base stats |
| POST | `/api/knowledge/search` | Search knowledge base |
| POST | `/api/knowledge/add` | Import knowledge documents (.txt/.md/.json) |
| POST | `/api/pcap/analyze` | Analyze PCAP file (with evidence hash) |
| POST | `/api/pcap/analyze_async` | Async analysis (returns task_id) |
| GET | `/api/tasks/{task_id}` | Poll async task status |
| POST | `/api/chat` | Security Q&A |
| POST | `/api/incident/report` | Generate incident report |
| GET | `/api/audit/logs` | Audit log query (paginated/filtered) |
| GET | `/api/audit/stats` | Audit statistics |

External calls to `/api/*` require the `X-API-Token` header (auto-generated into `.env` on first start; Gradio UI is exempt; health check exempt).

---

## Project Structure

```
ai-network-security-analyzer/
├── run.py                     # Entry point
├── requirements.txt
├── .env.example               # Env template (never commit .env)
├── config/settings.py         # Global configuration
├── src/
│   ├── capture/               # Scapy streaming parser (packet_parser / pcap_parser)
│   ├── analysis/              # Flow extraction + rule engine + EWMA baseline + isolation detector
│   ├── ai/                    # LLM client, RAG engine, hybrid retrieval, threat analyzer
│   ├── knowledge/             # MITRE ATT&CK + response playbooks + protocol knowledge
│   ├── api/                   # FastAPI + Gradio UI + task queue + audit
│   └── report/                # Forensic HTML report
├── tools/                     # Reproducible evaluation scripts
├── tests/                     # 105 pytest cases
└── data/                      # Golden samples, eval results, knowledge (reproducible)
```

---

## Security Notes

- **Never commit `.env`** — it is excluded by `.gitignore`; `git add .` will not stage it.
- The packaged installer (≈180 MB) is intended for **GitHub Releases**, not the repository (excluded).
- All traffic data is processed locally; only sanitized anomaly summaries are sent to the LLM API.
- API keys are managed via environment variables / secret services; no secrets in code.
- Every analysis report carries the source file SHA-256 for provenance and traceability.

---

## License

MIT License — see [LICENSE](LICENSE).
