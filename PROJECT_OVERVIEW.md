# 📖 Project Overview · 项目详解（中英双语 / Bilingual）

> A detailed bilingual walkthrough of the AI Network Security Analyzer — its architecture, engines, data flow, security design, and engineering practices.
> 本文件对该系统进行中英对照的详细解读：架构、检测引擎、数据流、安全设计与工程实践。

---

## 1. What It Is · 项目是什么

**English** — The AI Network Security Analyzer is a full-stack, offline network forensic analysis platform. It ingests packet captures (`.pcap` / `.pcapng`) exported from Wireshark, reconstructs network flows, detects malicious activity through three complementary engines, and uses an LLM grounded in a MITRE ATT&CK knowledge base to produce structured, evidence-backed threat assessments and NIST-aligned incident reports. Everything runs locally; only sanitized anomaly summaries ever leave the machine.

**中文** — AI 网络安全智能分析系统是一个全栈、离线的网络取证分析平台。它读取 Wireshark 导出的抓包文件（`.pcap` / `.pcapng`），重建网络流，通过三个互补引擎检测恶意活动，并利用以 MITRE ATT&CK 知识库（RAG）为依托的大模型，产出结构化、有证据支撑的威胁研判与符合 NIST 规范的安全事件报告。所有数据均在本地处理，只有消毒后的异常摘要才会离开本机。

---

## 2. System Architecture · 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│  Presentation 表现层                                              │
│  Gradio Web UI (3 Tabs) · FastAPI OpenAPI /docs                  │
└────────────────────────────┬────────────────────────────────────┘
                             │ REST + X-API-Token 鉴权 · 审计日志
┌────────────────────────────▼────────────────────────────────────┐
│  Application 应用层                                              │
│  FastAPI (async) · Task Queue (async analyze) · Audit (SQLite)   │
└────────────────────────────┬────────────────────────────────────┘
                             │ 分析请求 / 告警 / 研判请求
┌────────────────────────────▼────────────────────────────────────┐
│  Analysis 分析层（三引擎检测）                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Rule Engine  │  │ EWMA Baseline│  │ Isolation Forest (ML)│   │
│  │ 5 类攻击规则  │  │ 行为漂移检测   │  │ 多维耦合异常          │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘   │
└─────────┼─────────────────┼─────────────────────┼───────────────┘
          │ 统一告警合并（去重、分级、证据链字段）    │
┌─────────▼─────────────────▼─────────────────────▼───────────────┐
│  AI 研判层                                                       │
│  RAG（向量 + BM25 + RRF + 查询改写）→ 证据比对 → LLM 结构化研判     │
│  → Pydantic 校验 → 多温度投票（置信度一致性加权）                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│  Data & Output 数据与输出                                        │
│  MITRE ATT&CK 知识库 · ChromaDB · 取证 HTML 报告 · JSON · 审计库   │
└─────────────────────────────────────────────────────────────────┘
```

**中文分层解读**：系统自上而下分为表现层（Gradio + FastAPI 文档）、应用层（鉴权/审计/任务队列）、分析层（三引擎）、AI 研判层（RAG + LLM）、数据与输出层（知识库/向量库/报告）。

---

## 3. The Three Detection Engines · 三引擎检测机制

### 3.1 Rule Engine · 规则引擎（确定性，高精度）

| Attack 攻击 | Detection Logic 检测逻辑 |
|---|---|
| SYN Flood SYN 洪水 | 状态化握手校验：发出的 SYN 数 − 收到的 SYN-ACK 数 ≥ 阈值（区分攻击与正常握手） |
| Port Scan 端口扫描 | 方向化统计：仅发起方向 SYN（无 ACK）探测的不同目的端口数 ≥ 阈值 |
| DNS Tunnel DNS 隧道 | 超长 DNS 查询（> 阈值字符）且数量 ≥ 阈值 |
| Large-flow Exfiltration 大流量渗出 | 单条流传输字节 > 阈值（默认 10 MB） |
| RST Storm RST 风暴 | 源 IP 发出的 RST 包数 ≥ 阈值 |

**Key design 关键设计**：所有阈值参数化（`.env` 可覆盖）；每条告警携带**证据链字段**（`detector` 规则 ID / `rule_threshold` 阈值 / `time_window` 时间窗 / `description`），保证可审计、可溯源。

### 3.2 EWMA Statistical Baseline · EWMA 统计基线（行为漂移检测）

- **Why robust statistics 为何用鲁棒统计**：网络流量呈重尾分布、非平稳，均值±标准差假设正态分布，单个离群点即可拉爆阈值；故采用 **中位数 + MAD（绝对中位差）**，MAD 经 0.6745 系数换算到正态尺度，使 z-score 与 3σ 语义可比。
- **Two phases 两阶段**：`learn()` 学习正常流量画像（先粗剔除极端窗口，防攻击污染基线）→ `detect()` 按 10s 窗口聚合包数/字节/SYN/目的端口四维度，`z > σ` 标记偏差。
- **P1 self-adaptation 自适应**：EWMA 在线滚动更新（仅无偏差窗口参与，**防攻击污染基线**）；两样本 **KS 检验**（纯 Python 实现）检测业务流量画像漂移，超临界值时报告标注"基线可能失效"。
- **Value 价值**：弥补规则引擎盲区——低于规则阈值的"轻度/慢速异常"（如 15 端口轻度扫描 < 阈值 20）通过行为突变（z-score > 3σ）被发现。

### 3.3 Isolation Forest · 孤立森林（无监督 ML 第三轨）

- **Why a third engine 为何需要第三轨**：统计基线逐维度独立建模（z-score），孤立森林对**多维窗口特征联合建模**，捕捉"单维度不显著、组合才异常"的耦合异常（如包数正常但目的端口数突增）。
- **Same input, same metric 同口径**：与基线同窗口聚合、同训练/测试切分、同 TPR/FPR 指标（`tools/eval_ml_engine.py` 公平对比）。
- **Explainable 可解释**：固定 `random_state` 可复现；连续 `anomaly_score` + 阈值判定（而非二值标签）；告警附 anomaly_score 与 top 贡献维度，证据可溯源。

**Complementarity 互补关系（评测证实）**：规则引擎精确命中 5 类已知攻击且 0 误报；基线捕获其中 3 类的统计突变，并补 2 个规则盲区（lightscan / burst）；孤立森林提升 TPR 至 0.857。**三引擎盲区互不重叠，组合覆盖完整。**

---

## 4. AI Assessment Layer · AI 研判层

### 4.1 RAG Pipeline · 检索增强生成

```
Query 问题
  ├─ 查询改写（比较问句拆分子查询）┐
  ├─ 向量检索（BGE-small-zh ONNX，本地离线）│ → RRF 融合（k=60）→ 重排序 → 上下文
  └─ BM25 关键词召回（手写，中文 bigram）┘
```

- 本地 BGE 中文 Embedding（ONNX），**无需联网**；首用自动下载/内置。
- 混合检索（向量 + 手写 BM25 + RRF）相比纯向量，Recall@5 从 0.9375 → **1.0000**（消融实验证实）。
- 知识库：MITRE ATT&CK 攻击技术 + 事件处置手册 + 协议知识。

### 4.2 Structured LLM Judgment · 结构化 LLM 研判

- LLM 输出 JSON → **Pydantic 校验**（威胁判定 / 置信度 / 逐告警真伪 / MITRE 技术映射 / 处置建议）；校验失败自动降级为文本研判。
- **L4 证据比对**：告警特征 ↔ 知识库攻击模式指纹（关键词/端口共现）自动比对，匹配度注入研判 prompt，禁止 LLM 修改比对数据。
- **L3 多温度投票**：3 个温度采样（0.1/0.4/0.7）多数投票，一致性 0.875，置信度 = 平均置信 × 一致性加权；诚实记录：投票稳定结论但**不修正** LLM 的系统性偏差——因此 LLM 只作辅助，不由它做真伪判定。
- **Prompt-injection defense 注入防护**：PCAP 提取字段属不可信输入，进入 prompt 前做消毒（截断/去控制字符/注入特征标记 `[警告:疑似指令注入]`）。

### 4.3 Honest Positioning · 诚实的定位

评测结论（`data/eval_perf/`）：LLM 不提高检测率（确定性引擎兜底），真实增量在"逐告警解释 + 可执行处置建议 + 结构化叙事"（处置建议可执行性 0.000 → **+0.634**）。系统文档如实记录失败模式（如基线告警证据链弱导致 LLM 判假），**不用 prompt 微调替代确定性检测**。

---

## 5. Data Flow · 数据流

```
PCAP 文件 → 流式解析（Scapy PcapReader 逐包，内存 O(1)）
  → 规则累加器（只存计数+首末时间戳，不缓存原始包）
  → 流聚合（双向流规范化，O(活跃流数+窗口数)）
  → 基线窗口增量聚合（WindowAccumulator）
  → 三引擎告警合并（去重/分级/证据链）
  → RAG 检索 + 证据比对 → LLM 结构化研判（多温度投票）
  → 取证报告：流量概览 + 检测结果 + 证据链 + 基线对照 + AI 研判
  → 输出：JSON / 单文件 HTML（内联样式零依赖）/ NIST 对齐事件报告
```

**Streaming design 流式设计**：`iter_packets()` + `analyze_stream()` 单遍处理；实测 300,000 包（28.1MB）：全量路径峰值内存 **1,112.3MB** → 流式 **6.8MB**（**162.8× 降低**），耗时持平，告警一致性 15/15。

---

## 6. Security by Design · 安全设计

| Layer 层 | Measure 措施 |
|---|---|
| 认证 | 本地 API Token（`X-API-Token`，首启自动生成写入 `.env`），CORS 收紧到本机 |
| 审计 | SQLite WAL 审计库：所有 `/api/*` 请求留痕（401 未授权同样记录），请求体不落库防敏感数据；同步写 + 短超时降级，审计失败不阻塞业务 |
| 输入 | PCAP 类型/大小限制（200MB）；提示词注入消毒（截断/控制字符/特征标记） |
| 密钥 | API Key 仅存 `.env`（.gitignore 排除），打包版不含任何密钥 |
| 隐私 | 流量本地处理，仅消毒摘要发送 LLM；报告附源文件 **SHA-256** 可溯源 |
| 数据边界 | 知识库仅公开资料 + 自建脱敏内容；不接触生产网络 |

---

## 7. Engineering & Reproducibility · 工程化与可复现性

- **测试**：105 个 pytest 用例（算法正确性 / 流式一致性 / API 端到端 / 证据链），`python -m pytest tests -q` 秒级复跑。
- **评测体系**：`tools/` 下 9+ 个可复现实验脚本，结果固化在 `data/eval_*`（黄金样本回归、真实恶意流量验证、性能基线、RAG 检索质量、窗口敏感性、LLM 投票/研判、A/B 增量、孤立森林）。
- **真实样本验证**：Lumma Stealer 感染链（17,013 包）流式分析 4.8s / 峰值内存 <10MB，DNS 隧道 + 大流量渗出检出，**IOC 交叉验证 4/4 精确命中**。
- **部署**：Docker Compose 一键启动（依赖层缓存 + 健康检查 + 数据卷持久化）；PyInstaller + Inno Setup 产出免 Python 安装包（建议分发至 GitHub Releases）。
- **异步任务**：GB 级 PCAP 走 `POST /api/pcap/analyze_async` 入队 + 轮询，不阻塞 HTTP。

---

## 8. Tech Stack Summary · 技术栈一览

| Category 类别 | Technology 技术 |
|---|---|
| Packet 解析 | Scapy, dpkt |
| Analysis 分析 | Python native（流聚合/规则/EWMA/孤立森林） |
| AI / RAG | ChromaDB, langchain, BGE-small-zh-v1.5 (ONNX), scikit-learn |
| LLM | DeepSeek / GLM / Qwen / SiliconFlow / Ollama（OpenAI 兼容） |
| Backend 后端 | FastAPI + Uvicorn + SQLite（审计） |
| Frontend 前端 | Gradio |
| Deployment 部署 | Docker Compose, PyInstaller + Inno Setup |
| Quality 质量 | pytest (105), loguru, structured audit, streaming memory profiling |

---

*Bilingual overview maintained alongside the English README and the Chinese README (`README.zh-CN.md`). All metrics cited above are reproducible from this repository.*
*本双语详解与英文 README、中文 README 并行维护；文中所有指标均可由本仓库复现。*
