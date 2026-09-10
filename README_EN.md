# AI Network Security Analyzer

> AI-Assisted Network Forensics System — PCAP Offline Analysis + Four-Engine Integrated Detection + LLM Threat Assessment + RAG Security Knowledge Q&A

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green.svg)](https://fastapi.tiangolo.com/)
[![Gradio](https://img.shields.io/badge/Gradio-6.x-orange.svg)](https://www.gradio.app/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-141%20passed-brightgreen.svg)](#testing)

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
- [Development Guide](#development-guide)
- [FAQ](#faq)
- [License](#license)

---

## Project Overview

Traditional network forensics relies on security analysts manually inspecting PCAP files packet-by-packet with Wireshark — extremely inefficient and highly dependent on individual experience. While rule engines automate detection, they suffer from severe false negatives for unknown attacks and large-traffic variants (UNSW-NB15 large-flow class Recall = 0.002).

This project is an **AI-assisted offline network forensics analysis tool** that implements:
- **Four-Engine Integrated Detection**: Supervised model (HistGradientBoosting) as primary engine + Rule engine + EWMA time-series baseline + Isolation Forest, with weighted voting to reduce false positives/negatives
- **LLM Threat Assessment**: Large language model translates technical alerts into human-readable threat analysis, with hallucination control trilogy
- **RAG Security Knowledge Q&A**: Local vector store (BGE ONNX + ChromaDB), hybrid retrieval + reranking
- **Full-Process Closed Loop**: Detection → Analysis → Forensic Report (five elements) → Historical Knowledge Base (cross-sample correlation / trend analysis)

### Why This Project?

| Dimension | Description |
|-----------|-------------|
| **Algorithm Depth** | 76-dim CICFlowMeter feature extraction, four-engine ensemble voting, adaptive threshold, STL time-series decomposition |
| **AI Engineering** | Hallucination control trilogy, RAG hybrid retrieval + reranking, local vector inference |
| **Engineering Quality** | 141 unit tests, FastAPI + Pydantic, SQLite WAL, DPAPI encryption, global exception handling |
| **Lightweight & Portable** | Average memory peak 23MB, local inference no external service dependency, Windows .exe packaging |
| **Verifiable** | All metrics have evaluation scripts and result files — no "guesstimates" |

---

## Core Features

### 🔍 Four-Engine Integrated Detection

| Engine | Type | Weight | Description |
|--------|------|--------|-------------|
| **Supervised Model** | HistGradientBoosting | 0.5 | 76-dim CICFlowMeter features, flow-level prediction + PCAP-level aggregation, F1=0.9487 |
| **Rule Engine** | Threshold rules | 0.2 | 10+ configurable rules (SYN flood / port scan / DNS tunnel / RST storm, etc.) |
| **Time-Series Baseline** | EWMA + Median/MAD | 0.15 | 4-dimension joint detection, multi-dimension simultaneous deviation triggers CRITICAL |
| **Isolation Forest** | Unsupervised anomaly | 0.15 | Suitable for low-dimensional tabular data, detects unknown anomalies |

- **Adaptive Threshold**: Dynamically adjusted based on input traffic P95 percentile, adapts to different network environments
- **STL Advanced Mode**: Zero-dependency lightweight time-series decomposition (trend + seasonality + residual), captures periodic deviations
- **Strategy Pattern Architecture**: Extensible — new detection algorithms only need to implement the interface and register

### 🤖 LLM Threat Assessment + Hallucination Control

- **Threat Analysis**: LLM automatically generates threat analysis reports, cross-alert correlation, attack chain reconstruction
- **Hallucination Control Trilogy**:
  - `OutputValidator`: Format / length / reasonableness / evidence consistency / hallucination keyword detection
  - `ConfidenceCrossValidator`: LLM vs Rules vs Supervised Model cross-validation, contradiction detection
  - `ReviewMarker`: Low-confidence / contradictory conclusions automatically marked "needs human review"
- **Thinking Process Visualization**: Displays LLM analysis and thinking process
- **Multi-Model Compatibility**: Zhipu / DeepSeek / OpenAI compatible interfaces

### 📚 RAG Security Knowledge Q&A

- **Local Vector Store**: ChromaDB + BGE ONNX inference (2768 knowledge chunks, zero external service dependency)
- **Hybrid Retrieval**: BM25 keyword + vector semantic, dual-channel recall
- **Lightweight Reranking**: Title 0.4 + Content 0.3 + Metadata 0.2 + Vector Distance 0.1 + Exact Match bonus
- **Security Terminology Synonym Expansion**: 10 categories Chinese→English, improves cross-language retrieval
- **Conversation History Persistence**: SQLite storage, no loss on refresh

### 📋 Forensic Report Five Elements

1. **Event Timeline**: Alert timeline with severity color coding
2. **ATT&CK Attack Chain Diagram**: SVG 7-stage kill chain, detected stages highlighted in red
3. **IOC (Indicators of Compromise) List**: IP / Port / associated alerts
4. **Evidence Chain**: Alert → Evidence → Detection Engine → Time Window
5. **Analyst Notes**: Dashed box reserved for filling

### 🧠 Forensic Knowledge Base

- **Cross-Sample Correlation Analysis**: Same attack type / similar alerts / time proximity scoring, discovers attack pattern evolution
- **Trend Analysis**: Daily statistics / attack type distribution / severity trend / primary engine verdict trend
- **Duplicate Detection Cache**: Based on file SHA256, same file directly returns historical results
- **IOC Extraction**: Automatically extracts IP / Port and other indicators from analysis records

### 🔒 Security & Engineering

- **API Key Secure Storage**: Windows DPAPI encryption (ctypes call, zero extra dependency), bound to current user
- **Graphical Configuration Wizard**: First-launch guided configuration, API key validity check
- **Global Exception Handling**: 10+ exception types friendly Chinese prompts, users never see Python stack traces
- **Log Observability**: Log viewer API (level / keyword filtering) + one-click diagnostic report (7 dimensions)
- **Input Validation**: PCAP file / API Key / Base URL / baseline name comprehensive validation
- **Graceful Degradation**: LLM failure → rule engine summary, RAG failure → keyword matching

---

## Technical Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Desktop Window (pywebview)                    │
│           Gradio UI + Custom HTML/CSS (Blue Anime Style)         │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTP (localhost:8080)
┌──────────────────────────────▼──────────────────────────────────┐
│                     FastAPI Backend Service                       │
│        Pydantic 20+ models │ Global Exception Handling │ Logs    │
└──────┬──────────┬──────────┬──────────┬──────────┬─────────────┘
       │          │          │          │          │
┌──────▼───┐ ┌───▼────┐ ┌──▼─────┐ ┌─▼──────┐ ┌▼────────────┐
│ Parsing  │ │Detection│ │  AI    │ │Storage │ │  Security    │
│ Scapy    │ │ 4-Eng  │ │ LLM+RAG│ │ SQLite │ │  DPAPI       │
│ Stream   │ │Ensemble│ │         │ │ WAL    │ │  Encrypted   │
└──────────┘ └────────┘ └────────┘ └────────┘ └─────────────┘
```

### Tech Stack

| Layer | Technology | Version | Description |
|-------|-----------|---------|-------------|
| **Language** | Python | 3.11 | - |
| **Backend** | FastAPI | 0.110+ | Async API, Pydantic validation |
| **Frontend** | Gradio | 6.x | Rapid UI, custom CSS |
| **Desktop** | pywebview | 5.x | Native window, system WebView |
| **Parsing** | Scapy | 2.5+ | PCAP stream parsing |
| **Algorithm** | scikit-learn | 1.3+ | HistGradientBoosting / IsolationForest |
| **AI** | LLM API | - | Zhipu / DeepSeek / OpenAI compatible |
| **Vector** | ChromaDB | 0.4+ | Local vector database |
| **Embedding** | BGE ONNX | - | Chinese-optimized, local inference |
| **Storage** | SQLite | 3.x | WAL mode, three tables + indexes |
| **Security** | DPAPI (ctypes) | - | Windows built-in encryption |
| **Logging** | loguru | 0.7+ | Structured logging |
| **Testing** | pytest | 7.x+ | 141 tests all green |

---

## Quick Start

### Requirements

- Windows 10/11 (recommended, DPAPI encryption requires)
- Python 3.11+
- Memory: Minimum 2GB, recommended 4GB+
- Disk: Minimum 500MB (including models and dependencies)

### Method 1: Source Code Run (Recommended for Development)

```bash
# 1. Clone the repository
git clone https://github.com/your-username/ai-network-security-analyzer.git
cd ai-network-security-analyzer

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Download large file resources (required for first run, ~140 MB)
# BGE embedding model + MITRE ATT&CK knowledge base, not included in repo due to size
python tools/init_resources.py

# 5. Configure API Key (first run)
# Copy .env.example to .env, fill in LLM_API_KEY
copy .env.example .env
# Edit .env, fill in your API Key (can also configure in UI Settings, will use DPAPI encrypted storage)

# 6. Start desktop version
python desktop_app.py

# Or start API service (browser access http://127.0.0.1:8080)
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8080
```

### Method 2: Windows Installer (Recommended for Users)

1. Download the latest `AI-Network-Security-Analyzer-Setup.exe`
2. Double-click to run the installer, select installation directory
3. After installation, launch from desktop shortcut
4. First launch will guide API Key configuration (DPAPI encrypted storage, not hardcoded)

---

## Usage Guide

### 1. PCAP Traffic Analysis

1. Open the app, go to "📊 PCAP Traffic Analysis" tab
2. Click "Select File" to upload .pcap/.pcapng file (max 200MB)
3. (Optional) Select a learned time-series baseline for comparison detection
4. Click "Start Analysis"
5. View results:
   - **Primary Engine Verdict**: Attack / Normal + Confidence + Attack flow ratio + Attack category
   - **Alert List**: All alerts detected by four engines, sorted by severity
   - **Traffic Statistics**: Packet count / Flow count / Byte count / Protocol distribution
   - **AI Threat Analysis**: LLM-generated threat analysis report (with hallucination control validation)
   - **Forensic Report**: Click to download five-element complete HTML report

### 2. Baseline Management

1. Go to "📈 Baseline Management" tab
2. Click "Upload Normal Traffic to Learn Baseline", select normal business traffic .pcap file
3. Enter baseline name, click "Learn"
4. After learning, you can view:
   - **Baseline Profile**: 4-dimension (packets/bytes/SYN/ports) median±MAD bar chart (SVG)
   - **Comparison Chart**: Current traffic vs baseline median line chart (SVG)
5. When analyzing PCAP, you can select this baseline for comparison detection

### 3. Security Q&A Assistant

1. Go to "🤖 Security Q&A" tab
2. Enter security-related questions (e.g., "What is SQL injection? How to detect?")
3. System retrieves relevant documents from local knowledge base, combines with LLM to generate answers
4. Conversation history automatically saved, no loss on refresh
5. Can view retrieved relevant document fragments

### 4. Analysis History

1. Go to "📜 Analysis History" tab
2. View all historical analysis records (file / time / alert count / severity / primary engine verdict)
3. Click records to view details, reload analysis results
4. Forensic knowledge base features:
   - **Cross-Sample Correlation**: View historical analyses similar to current sample
   - **Trend Analysis**: Attack count / type / severity changes over time
   - **Duplicate Detection Cache**: Same file (SHA256) directly returns historical results

### 5. Settings

1. Go to "⚙️ Settings" tab
2. Configure API Key (password input field, saved with DPAPI encrypted storage)
3. Configure Base URL and model name
4. Click "Test Connection" to verify API Key validity
5. Saved and effective immediately, no restart required

---

## API Documentation

After starting the service, visit `http://127.0.0.1:8080/docs` for complete Swagger API documentation.

### Core API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/analyze` | POST | PCAP analysis (upload file) |
| `/api/knowledge/search` | POST | RAG knowledge retrieval |
| `/api/chat` | POST | Security Q&A |
| `/api/baseline/learn` | POST | Learn baseline |
| `/api/baseline/list` | GET | Baseline list |
| `/api/baseline/delete` | POST | Delete baseline |
| `/api/forensic/stats` | GET | Forensic knowledge base statistics |
| `/api/forensic/trend` | GET | Attack trend analysis |
| `/api/forensic/related/{id}` | GET | Cross-sample correlation |
| `/api/config/status` | GET | Configuration status |
| `/api/config/validate` | POST | API Key validity check |
| `/api/config/save_secure` | POST | Save to DPAPI encrypted storage |
| `/api/logs` | GET | Log viewer |
| `/api/logs/stats` | GET | Log statistics |
| `/api/diagnostic` | GET | One-click diagnostic report |
| `/api/incident/report` | POST | Generate forensic report |

### Authentication

All `/api/*` endpoints require `X-API-Token` in request headers (auto-generated on first launch, stored in .env as `API_AUTH_TOKEN`). Gradio UI (in-process calls) is not affected.

---

## Evaluation Results

### Supervised Model Detection Performance

| Dataset | Precision | Recall | F1 | Accuracy |
|---------|-----------|--------|-----|----------|
| **CIC-UNSW** (447,915 flows) | 0.9351 | 0.9628 | **0.9487** | 0.9792 |
| **UNSW-NB15** (dedicated model) | 0.9633 | **0.9769** | 0.9700 | 0.9589 |

**vs Rule Engine**: UNSW-NB15 large-flow class Recall only 0.002, supervised model improves **4884x**.

**UNSW-NB15 Per-Class Recall**:

| Attack Type | Recall |
|-------------|--------|
| Backdoor | 1.0000 |
| Worms | 1.0000 |
| Generic | 1.0000 |
| DoS | 0.9992 |
| Reconnaissance | 0.9995 |
| Exploits | 0.9962 |
| Shellcode | 0.9911 |
| Analysis | 0.9336 |
| Fuzzers | 0.8655 |
| Normal | 0.9207 |

### RAG Retrieval Performance

| Metric | Value |
|--------|-------|
| Golden Q&A Set | 15 questions (covering attack techniques / detection / response) |
| **Recall@5** | **0.360** |
| Strict Recall (at least 1 hit) | 66.7% |
| Average Retrieval Time | 0.291s |
| Knowledge Base Chunks | 2768 |

**Known Limitation**: 5 knowledge blind spots (SQL injection / ransomware / phishing / memory web shell / MITM attack), root cause is insufficient knowledge base content. Supplementing knowledge base content can significantly improve Recall.

### Performance Benchmark

| Metric | Value |
|--------|-------|
| Test Samples | 10 golden samples |
| Total Packets | 28,036 |
| **Average Analysis Time** | **5.911 seconds/file** |
| **Average Memory Peak** | **22.97 MB** |
| Parsing Time Ratio | ~60% |
| Detection Time Ratio | ~25% |
| AI Analysis Time Ratio | ~15% (depends on API response speed) |

### Testing Coverage

| Metric | Value |
|--------|-------|
| Total Unit Tests | **141 passed** |
| Test Files | 12 |
| Covered Modules | Algorithm / API / Storage / Security / Utils |
| Golden Sample Tests | 10 |

---

## Project Structure

```
ai-network-security-analyzer/
├── src/
│   ├── analysis/              # Analysis engine
│   │   ├── cic_features.py    # 76-dim CICFlowMeter feature extraction
│   │   ├── supervised_detector.py  # Supervised detector (HistGradientBoosting)
│   │   ├── flow_extractor.py  # Flow extraction + four-engine ensemble
│   │   ├── baseline.py        # EWMA time-series baseline + STL advanced detection
│   │   ├── stl_decomposer.py # Zero-dependency lightweight STL decomposition
│   │   ├── isolation_detector.py  # Isolation Forest unsupervised detection
│   │   └── detection_engine.py    # Strategy pattern + Factory pattern detection engine
│   ├── ai/                    # AI module
│   │   ├── llm_client.py      # LLM client
│   │   ├── threat_analyzer.py # Threat analyzer
│   │   ├── rag_engine.py      # RAG retrieval engine (hybrid + reranking)
│   │   ├── hallucination_control.py  # Hallucination control trilogy
│   │   ├── evidence_matcher.py      # Evidence matcher
│   │   └── embeddings/        # Embedding model (BGE ONNX)
│   ├── api/                   # API layer
│   │   ├── main.py            # FastAPI main app + Gradio UI
│   │   ├── schemas.py         # Pydantic models (20+)
│   │   ├── history_store.py   # History storage (SQLite)
│   │   ├── task_queue.py      # Task queue
│   │   └── audit.py           # Audit log
│   ├── capture/               # Capture / parsing
│   │   ├── packet_parser.py   # Packet parser
│   │   └── pcap_parser.py     # PCAP file parser
│   ├── report/                # Report generation
│   │   └── html_report.py     # HTML forensic report (five elements)
│   ├── storage/               # Storage layer
│   │   ├── database.py        # SQLite database (WAL, three tables + indexes)
│   │   └── forensic_kb.py     # Forensic knowledge base (correlation / trend / cache)
│   ├── security/              # Security layer
│   │   └── secure_store.py    # DPAPI encrypted storage
│   ├── ui/                    # UI resources
│   │   └── custom_style.css   # Blue anime style custom CSS
│   └── utils/                 # Utility functions
│       ├── paths.py           # Path management
│       ├── helpers.py         # Common utilities
│       ├── error_handler.py   # Three-layer error handling
│       └── log_observer.py    # Log observability
├── models/                    # Trained models
│   ├── supervised_detector.joblib      # CIC supervised model (F1=0.9487)
│   └── unsw_supervised_detector.joblib # UNSW dedicated model (Recall=0.9769)
├── data/                      # Data directory
│   ├── samples/golden/        # Golden test samples (10)
│   ├── baselines/             # Baseline files (JSON compatible backup)
│   ├── eval_perf/             # Evaluation results
│   └── ...                    # (db/history/chroma_db generated at runtime)
├── tests/                     # Tests (141)
├── tools/                     # Tool scripts
│   ├── init_resources.py      # Resource initialization (download BGE + MITRE)
│   ├── train_unsw_supervised.py  # UNSW model training
│   ├── benchmark.py           # Performance benchmark
│   └── eval_rag_recall.py     # RAG Recall@5 evaluation
├── docs/                      # Documentation
│   ├── 简历项目描述.md (Resume project description)
│   └── 面试准备_STAR+20问.md (Interview prep STAR + 20 questions)
├── config/                    # Configuration
│   └── settings.py            # Global config (pydantic-settings)
├── desktop_app.py             # Desktop entry (pywebview)
├── requirements.txt           # Python dependencies
├── .env.example               # Environment variable example
├── .gitignore
├── LICENSE
├── README.md                  # Chinese README
└── README_EN.md               # English README (this file)
```

---

## Development Guide

### Adding a New Detection Engine

The project uses the Strategy pattern — adding a new detection algorithm is simple:

```python
# 1. Implement DetectionStrategy interface
from src.analysis.detection_engine import DetectionStrategy, DetectorFactory

class MyDetector(DetectionStrategy):
    @property
    def name(self): return "my_detector"

    @property
    def version(self): return "1.0.0"

    def detect(self, packets, flows=None, context=None):
        # Your detection logic
        alerts = []
        # ...
        return {"alerts": alerts, "summary": {}, "stats": {}}

# 2. Register with factory
DetectorFactory.register("my_detector", MyDetector)

# 3. Use in ensemble engine (automatic weighted voting)
from src.analysis.detection_engine import DetectionEngine
engine = DetectionEngine()
engine.add_strategy(MyDetector(), weight=0.1)
result = engine.detect_all(packets)
```

### Running Tests

```bash
# Run all tests
pytest tests -q

# Run specific test file
pytest tests/test_new_features.py -v

# Run with coverage (requires pytest-cov)
pytest tests --cov=src --cov-report=html
```

### Performance Benchmark

```bash
python tools/benchmark.py
# Results saved in data/eval_perf/benchmark_result.json
```

### RAG Evaluation

```bash
python tools/eval_rag_recall.py
# Results saved in data/eval_perf/rag_recall_result.json
```

### Training Supervised Models

```bash
# CIC model
python tools/eval_supervised_baseline.py

# UNSW dedicated model
python tools/train_unsw_supervised.py
```

### Code Standards

- Follow PEP 8
- Use type hints
- Every module/class/function has docstrings
- Error handling: no bare except, no swallowing exceptions, users never see stack traces
- Logging: use loguru, key operations all have logs

---

## FAQ

### Q1: Is the API Key secure? Is it hardcoded?

**A**: Absolutely not. API Key has two storage methods:
1. **DPAPI Encrypted Storage (Recommended)**: Windows built-in encryption, bound to current user, other users cannot decrypt. Automatically encrypted when saved via UI Settings.
2. **.env File**: Plaintext storage, only as compatible backup. DPAPI encrypted storage recommended.

No API Key is hardcoded in the code.

### Q2: Does it need internet?

**A**: By feature:
- **PCAP parsing / detection / baseline / report**: Fully offline, no internet needed
- **LLM threat analysis / security Q&A**: Needs to call LLM API, requires internet
- **RAG retrieval**: Local vector store, fully offline

Project positioning is "offline forensics tool" — core detection functionality fully offline.

### Q3: Which LLMs are supported?

**A**: Any OpenAI-compatible interface LLM, including:
- Zhipu AI (GLM-4-Flash / GLM-4)
- DeepSeek (deepseek-chat / deepseek-coder)
- OpenAI (GPT-3.5 / GPT-4)
- Locally deployed vLLM / Ollama (OpenAI-compatible interface)

Configure Base URL and model name in Settings.

### Q4: Is memory usage high?

**A**: Very lightweight. Performance benchmark shows:
- Average memory peak: **22.97 MB**
- Average analysis time: **5.911 seconds/file** (10 golden samples, 28,036 total packets)

BGE ONNX model uses ~100-200MB after loading, but can be loaded on demand. Regular computers can run smoothly.

### Q5: What's the difference from Wireshark / Suricata?

**A**: Different positioning, complementary:
- **vs Wireshark**: Wireshark is a protocol analyzer, requires manual packet-by-packet inspection; this project is an automated analysis tool — upload PCAP and automatically get threat verdict and forensic report.
- **vs Suricata**: Suricata is real-time IDS/IPS, rule-based, needs continuous running; this project is offline forensics analysis tool, focused on post-incident analysis, uses supervised models to detect unknown attacks.

Practical use case: Use Suricata for real-time monitoring to discover alerts, then use this project for deep forensic analysis of related PCAPs.

### Q6: Is RAG Recall@5=0.36 too low?

**A**: Objective view:
1. Pure vector retrieval ~0.28, hybrid retrieval + reranking improves to 0.36, +28.6%
2. Strict recall (at least 1 hit) 66.7% — this metric is more practical
3. Root cause is insufficient knowledge base content (2768 chunks, 5 blind spots), not algorithm issue
4. Supplementing knowledge base content can significantly improve Recall

This is a clearly documented "known limitation" — demonstrates honesty and self-awareness.

### Q7: How to package as Windows .exe?

**A**: Use PyInstaller:

```bash
pip install pyinstaller
pyinstaller --noconfirm --windowed --name "AI-Network-Security-Analyzer" ^
    --add-data "models;models" ^
    --add-data "data/samples;data/samples" ^
    --add-data "src/ui/custom_style.css;src/ui" ^
    desktop_app.py
```

Packaged files in `dist/` directory. Recommended to use Inno Setup to create installer.

---

## License

MIT License

Copyright (c) 2026 AI Network Security Analyzer

---

## Acknowledgments

- [Scapy](https://scapy.net/) - Powerful network packet processing library
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [Gradio](https://www.gradio.app/) - Rapid ML UI building
- [scikit-learn](https://scikit-learn.org/) - Machine learning library
- [ChromaDB](https://www.trychroma.com/) - Local vector database
- [BAAI/bge](https://huggingface.co/BAAI) - Chinese-optimized embedding model
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) - Network security dataset
- [CICFlowMeter](https://www.unb.ca/cic/research/tools/flowmeter.html) - Network flow feature extraction reference

---

**If this project helps you, please give a Star ⭐**
