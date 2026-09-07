# 🛡️ AI网络安全智能分析系统

> 基于流行为规则检测与LLM辅助研判的 PCAP 离线分析系统
> 网络安全专业知识 + 大模型能力 的工程实践

## 📋 项目简介

本项目是一个**网络安全 + AI** 的全栈应用，核心功能：

1. **PCAP文件分析**：解析 Wireshark 导出的抓包文件（.pcap/.pcapng），提取网络流、协议分布、通信拓扑
3. **规则引擎异常检测**：自动检测 SYN Flood、端口扫描、DNS隧道、大流量数据传输等攻击
4. **AI威胁研判**：基于大模型 + RAG（MITRE ATT&CK知识库）对异常进行智能分析，输出**结构化研判**（JSON + Pydantic 校验：是否威胁/置信度/逐告警真伪判定/MITRE技术映射/处置建议），校验失败自动降级文本
5. **安全知识问答**：基于知识库的安全助手，回答网络安全问题
6. **事件响应报告**：自动生成符合 NIST SP 800-61 标准的安全事件报告

## 🎯 技术栈

| 层级 | 技术 | 说明 |
|------|------|------|
| **解析层** | Scapy | PCAP 离线解析与协议字段提取 |
| **分析层** | Python 原生 | 网络流提取、协议统计、拓扑分析 |
| **AI层** | ChromaDB + OpenAI兼容API | RAG知识库、LLM研判 |
| **大模型** | DeepSeek / 智谱GLM | OpenAI兼容接口，国内直连 |
| **Embedding** | BGE-small-zh-v1.5 (ONNX) | 中文语义向量模型（本地推理，无需联网） |
| **知识库** | MITRE ATT&CK | 攻击技术、处置手册、协议知识 |
| **后端** | FastAPI + Uvicorn | 异步Web框架 |
| **前端** | Gradio | 无需写前端代码的Web UI（3个功能Tab） |
| **部署** | PyInstaller + Inno Setup | 一键安装包分发，无需安装Python |

## 📁 项目结构

```
ai-network-security-analyzer/
├── run.py                          # 启动脚本
├── requirements.txt                # 依赖清单
├── .env.example                    # 环境变量模板
├── .gitignore
├── README.md
├── config/
│   ├── __init__.py
│   └── settings.py                 # 全局配置管理
├── src/
│   ├── __init__.py
│   ├── capture/                    # 数据包解析模块
│   │   ├── packet_parser.py        # 数据包解析（Scapy）
│   │   └── pcap_parser.py          # PCAP文件读取与解析
│   ├── analysis/                   # 流量分析模块
│   │   └── flow_extractor.py       # 网络流提取 + 综合分析 + 规则引擎
│   ├── ai/                         # AI大模型模块
│   │   ├── llm_client.py           # 大模型API客户端（流式+重试）
│   │   ├── rag_engine.py           # RAG知识库引擎（ChromaDB）
│   │   ├── threat_analyzer.py      # 威胁分析Agent（核心AI大脑）
│   │   └── prompts.py              # Prompt模板库
│   ├── knowledge/                  # 安全知识库
│   │   └── mitre_attck.py          # MITRE ATT&CK + 处置手册 + 协议知识
│   ├── api/                        # API服务层
│   │   └── main.py                 # FastAPI + Gradio Web UI
│   └── utils/                      # 工具函数
│       └── helpers.py
├── data/
│   ├── samples/                    # 抓包样本和分析报告
│   ├── uploads/                    # 上传的PCAP文件
│   ├── knowledge/                  # 知识库文件
│   └── chroma_db/                  # 向量数据库持久化
└── tests/
```

## 🚀 快速开始

### 1. 安装依赖

```bash
cd ai-network-security-analyzer
pip install -r requirements.txt
```

> **Windows注意**：本系统专注 PCAP 离线文件分析，无需 Npcap 和管理员权限。

### 2. 配置大模型API

复制环境变量模板并编辑：

```bash
cp .env.example .env
```

编辑 `.env` 文件，填写你的 API Key：

```env
# 推荐 DeepSeek（便宜、代码能力强、国内直连）
# 注册: https://platform.deepseek.com/
LLM_API_KEY=sk-你的APIKey
LLM_BASE_URL=https://api.deepseek.com
LLM_MODEL=deepseek-chat
```

> 也可以使用通义千问、智谱AI等任何OpenAI兼容接口。

### 3. 启动服务

```bash
python run.py
```

启动后访问：
- **Web UI**: http://localhost:8080
- **API文档**: http://localhost:8080/docs

### 4. 初始化知识库

系统已支持**首次检索自动初始化**：首次触发 AI 研判/知识问答时，若向量库为空会自动加载内置的 MITRE ATT&CK 攻击技术、事件处置手册、协议知识（幂等，仅执行一次）。
也可手动初始化：在 Web UI 的「📚 知识库管理」Tab 中点击「初始化/重建知识库」。

## 📖 使用指南

### 功能1：PCAP流量分析

1. 用 Wireshark 抓包，导出为 `.pcap` 或 `.pcapng` 文件
2. 在 Web UI 的「📊 PCAP流量分析」Tab 上传文件
3. 点击「开始分析」
4. 系统将自动输出：
   - 流量概览（包数、流量、协议分布、时间范围）
   - 规则引擎异常检测（SYN Flood、端口扫描、DNS隧道等）
   - AI威胁研判（大模型分析攻击手法、对应MITRE ATT&CK、处置建议）
   - 完整JSON报告

### 功能2：安全知识问答

在「💬 安全知识问答」Tab 中，直接提问网络安全问题，
系统会基于 MITRE ATT&CK 知识库检索后回答，例如：
- "什么是DNS隧道？如何检测？"
- "SYN Flood攻击的原理和防护方法"
- "端口扫描对应MITRE ATT&CK哪个技术？"

### 功能3：知识库管理

在「📚 知识库管理」Tab 中：
- 初始化/重建知识库
- 查看知识库统计（文档数、分类分布）
- 搜索知识库内容
- 上传 `.txt/.md` 文档导入知识（扩充知识库）

### 功能5：取证型 HTML 报告导出

每次 PCAP 分析自动生成完整取证型 HTML 报告（`data/reports/`），包含：

- **报告头**：案例号、生成时间、源文件名、源文件 SHA-256、规则版本（证据溯源）
- **流量概览**：包数 / 流数 / 总流量 / 协议分布
- **检测结果**：告警清单 + 证据链（检测规则ID / 触发阈值 / 时间窗 / z-score）
- **时序基线对照**：EWMA 基线画像 + 偏差数值
- **AI 研判与处置建议**、**免责声明**

报告为单文件 HTML（内联样式、零外部依赖），可离线打开、归档或转 PDF；Gradio 分析结果底部可直接下载。

### 功能4：基线管理（EWMA 时序基线）

在「📈 基线管理」Tab 中：
- 上传正常流量 PCAP 学习时序基线（系统统计每 10s 窗口的包数/字节/SYN/端口数，计算中位数+MAD）
- 查看基线画像、多基线管理（命名/删除）
- 分析时在「PCAP流量分析」Tab 选择基线，检测结果将对照基线输出统计偏差告警（z-score > 3σ）
- 系统预置一份基于合成正常流量的 default 基线，开箱即用

**P1 基线自适应升级**：
- **EWMA 在线滚动更新**：检测阶段无偏差窗口以指数加权（α=0.1）缓慢更新基线中位数/MAD，基线随业务流量缓慢漂移自适应；**偏差窗口不参与更新**（防攻击污染基线）
- **KS 漂移失效提示**：最近 10 个窗口的流量分布与学习基线做两样本 Kolmogorov-Smirnov 检验（纯 Python 实现，无 scipy 依赖），D 统计量超临界值（α=0.05）时，检测报告标注"**基线可能失效，建议重新学习**"，避免基线失真导致的盲检

## 🚀 AI 增强（L1-L4 · v1.2.0）

本版本对 AI 层做了四层增强，全部带量化评测（可复跑）：

### L1 · LLM 增量价值 A/B 评测（AI 定位证明）
同一黄金告警集，对比「纯规则输出」与「规则+LLM 结构化研判」：
| 维度 | 纯规则 A | 规则+LLM B | LLM 增量 |
|---|---|---|---|
| 信息完整性 | 0.875 | 0.938 | +0.062 |
| 证据引用准确率 | 0.875 | 0.875 | 0.000（无幻觉误引） |
| 处置建议可执行性 | 0.000 | 0.634 | **+0.634** |

结论：LLM 不提高检测率（确定性引擎兜底），真实增量在「逐告警解释 + 可执行处置建议 + 结构化叙事」。
复跑：python tools/eval_llm_ab.py → data/eval_perf/llm_ab.json

### L2 · 孤立森林无监督检测引擎（第三轨）
与 EWMA 统计基线**同输入、同口径**对比（1s 窗口，normal 前 80% 训练 / 后 20% 测 FPR / 7 攻击样本测 TPR）：
| 指标 | EWMA 基线 | 孤立森林 |
|---|---|---|
| FPR | 0.000 | 0.040 |
| TPR（7 攻击） | 0.286 | **0.857** |

设计：对多维窗口特征联合建模（捕捉「包数正常但端口数突增」类耦合异常）；固定 random_state 可复现；
告警附 anomaly_score + top 贡献维度（证据可溯源）。portscan 是 ML 盲区，由规则引擎覆盖——三引擎互补。
启用：.env 设 ML_ENGINE_ENABLED=true（默认关，开启后分析报告含 ML_ANOMALY 告警）。
复跑：python tools/eval_ml_engine.py → data/eval_perf/ml_engine.json

### L3 · LLM 多采样投票（治非确定性）
3 温度采样（0.1/0.4/0.7）多数投票：
| 指标 | 单次 | 3 温度投票 |
|---|---|---|
| 判断准确率 | 62.5% | 62.5% |
| 一致性 agreement | — | **0.875** |

**实验结论（诚实记录）**：投票提升结论稳定性（7/8 案例 3 票全一致），但**未修正准确率**——
LLM 对弱特征 SYN / 边界 RST 的「判真倾向」是跨温度的系统性偏差，多数投票无法解决。
因此工程决策：LLM 不承担真伪判定（由确定性引擎兜底），投票用于报告置信度标注（一致性加权）。
复跑：python tools/eval_llm_voting.py → data/eval_perf/llm_voting.json

### L4 · RAG 证据比对（从「塞背景」到「证据比对」）
告警 → 检索知识库攻击模式 → 抽取期望特征（关键词/端口）→ 与告警实际字段比对 → 匹配度：
- 修复隐藏 bug：原 _extract_threat_types 读取不存在的字段，RAG 查询始终退化为「网络异常」→ 现按告警 type 精确提取
- 比对结果注入研判 prompt（「证据比对结果」节），并随结构化输出返回 evidence_match
- 匹配度为启发式（关键词/端口共现 + 检索相似度），显式声明不替代检测引擎

测试：	ests/test_evidence_matcher.py（8 用例）

---
## 🧠 AI核心原理

### 双引擎检测设计验证（规则 + 无监督时序基线）

检测引擎为 **规则检测 + EWMA 无监督基线** 双引擎结构，黄金样本回归 + 增量实验数据如下：

| 场景 | 纯规则引擎 | 规则+基线引擎 | 说明 |
|---|---|---|---|
| 黄金样本攻击命中 | 5/5 | 5/5 | 规则保持全命中 |
| 黄金样本正常流量 | 0 误报 | 0 误报 | 状态化/方向化检测修复后无噪声 |
| 轻度端口扫描（15端口 < 规则阈值20） | **0 检出** | **4 条告警** | 基线 dports 维度 z=6.07（中位 2→11） |
| 流量突发（600请求/300s，不达大流量阈值） | **0 检出** | **6 条告警** | 基线包数维度 z=8.67（中位 7→34） |

> **结论**：低于规则阈值的"轻度/慢速异常"是纯规则引擎的固有盲区；时序基线通过行为突变（z-score > 3σ）补盲。
> 规则引擎保证已知攻击的高精度，基线引擎覆盖未知行为漂移——双引擎互补。
> 复现：`python tools/verify_baseline_value.py`（seed=42，可复现）

### 检测质量评测（指标化，可审计）

`tools/evaluate_golden.py` 对黄金样本集计算完整指标体系（文件级，输出写入 `data/samples/regression_result.json` 的 `evaluation` 字段）：

| 引擎 | 指标 | 结果 |
|---|---|---|
| 规则引擎（5 类攻击 + 正常） | TP / FP / TN / FN | **5 / 0 / 1 / 0** |
| 规则引擎 | Precision / Recall / F1 | **1.000 / 1.000 / 1.000** |
| 基线引擎（normal 学习→自测） | 误报窗口 | **0 / 219** |
| 基线引擎（σ 扫描，对 5 攻击样本） | TPR / FPR | σ=2.0: 0.80/0.0046；σ=3.0: 0.60/0.0000 |

**双引擎覆盖分解**（诚实口径）：规则引擎精确命中 5 类已知攻击（SYN Flood/端口扫描/DNS 隧道/大流量/RST 风暴）且 0 误报；基线引擎捕获其中 3 类的统计突变（synflood z=22.3、portscan z=5.4、largeflow z=32072），**漏检低速小流量攻击（DNS 隧道、RST 风暴）——恰由规则引擎覆盖**，并对 2 个规则盲区样本（lightscan z=6.07、burst z=8.67）补盲。两引擎盲区互不重叠，组合覆盖完整。

**CICIDS2017 独立场景佐证**（官方流级标注 CSV，`data/eval_cicids/scene_evidence.json`）：
- PortScan 文件：BENIGN 127,537 流 + PortScan 158,930 流，全文件含 SYN 流 distinct 端口 2,885（>阈值 20 → 告警）
- 关键发现：该数据集**流级标注中攻击流 SYN Flag Count=0**（CICFlowMeter 流级口径），与包级检测存在语义差异——解释了 IDS 评测必须对齐"包级 vs 流级"特征口径；同时证明**按源 IP 聚合**的端口扫描设计可避免真实多主机流量中全文件 distinct 端口导致的误报（BENIGN 流量全文件 SYN 端口即达 2,885）

> 复现：`python tools/evaluate_golden.py`（秒级）
> 局限声明：黄金样本为合成流量；CICIDS2017 镜像为裁剪版（缺 IP/时间戳列），作为场景佐证而非主评测。真实恶意流量评测见「真实数据验证（P0-2）」。

### 工程化与可审计性（P2）

**核心算法单测（pytest，105 用例，覆盖算法层 + 流式一致性 + API 端到端）**：`tests/` 覆盖基线统计正确性（中位数/MAD/换算系数）、学习清洗、检测分级、灵敏度下限、持久化往返、P1 滚动更新与漂移、5 类规则触发与状态化/方向化防误报、告警证据链、Scapy 解析层、路径/种子迁移、审计日志。复现：`python -m pytest tests -q`

**API 审计日志（SQLite）**：所有 `/api/*` 请求（健康检查豁免）记录方法/路径/状态码/耗时/客户端 IP/UA 至 `data/audit/audit.db`（WAL 模式，请求体不落库防敏感数据；单条 <1ms，DB 体积 KB 级），未授权访问同样留痕（401 + note）。查询与统计接口：
- `GET /api/audit/logs?limit=&offset=&status=&path_kw=`（分页/过滤）
- `GET /api/audit/stats`（请求量/错误率/平均耗时/端点 TOP）

> 设计取舍：审计为**同步写 + 短超时降级**——审计失败绝不阻塞业务请求；同时排除健康检查心跳，防止审计库被监控噪声刷爆。

### 流式解析与内存优化（P0-1）

`src/capture/pcap_parser.py::iter_packets()` 用 Scapy `PcapReader/PcapNgReader` 逐包迭代（不再 `rdpcap` 全量载入），`src/analysis/flow_extractor.py::analyze_stream()` 单遍流式：规则累加器（只存计数与首末时间戳，不缓存原始包）+ 流聚合（双向流规范化，与全量 `FlowExtractor` 同口径）+ `WindowAccumulator` 增量窗口聚合（内存 O(活跃流数+窗口数)）。API 与 Gradio 双入口默认走流式路径（保留 `sample_count` 采集前 N 包供 AI 研判）。

**流式 vs 全量一致性**：黄金样本 8/8 告警集合一致（`tests/test_streaming.py` 12 用例固化）。性能对比见「性能基线（P1-3）」。

### 真实数据验证（P0-2）

真实恶意流量：`malware-traffic-analysis.net` **2025-12-30 Lumma Stealer 感染链样本**（19.7MB / 17,013 包，含 C2 通信与后续恶意载荷下载）：

| 验证项 | 结果 |
|---|---|
| 流式分析耗时 | 4.8s（3.6k pkt/s，峰值内存 <10MB） |
| DNS 隧道检出 | 2 条（10.12.30.101 / 10.12.30.1 各 7 个超长 DNS 查询） |
| 大流量渗出检出 | 10.12.30.101 → 172.67.203.237:443 传输 15.0MB（>10MB 阈值） |
| **IOC 交叉验证** | pcap 内 4 个 DNS 域名**精确命中**文章公开 IOC：`gorcerie.com` / `memory-scanner.cc` / `pastebin.com` / `t.me`（C2 与数据泄露渠道） |

数据源：`data/eval_real/`（zip 密码 `infected_YYYYMMDD` 方案，见站点 about 页）；结果固化 `data/eval_real/real_analysis_result.json` + `ioc_crosscheck.json`。复现：流式分析脚本 `tools/` 下或直接 `POST /api/pcap/analyze`。

### 窗口敏感性实验（P0-3）

`tools/eval_window_sensitivity.py`：window_sec ∈ {5,10,30} × σ ∈ {2,3,4} 双因子网格（normal 学习 → 7 攻击样本检出）：

| window_sec | σ=2.0 (TPR/FPR) | σ=3.0 | σ=4.0 |
|---|---|---|---|
| 5s | 0.71 / 0.000 | 0.43 / 0.000 | 0.29 / 0.000 |
| 10s | 0.86 / 0.005 | 0.71 / 0.000 | 0.71 / 0.000 |
| 30s | 0.86 / 0.000 | 0.86 / 0.000 | 0.86 / 0.000 |

结论：窗口越大聚合越平滑、MAD 相对下限更稳定 → TPR 更高；**检测灵敏度与检测延迟存在根本权衡**（窗口 = 最短检测延迟），默认 10s 为折中；小窗口（5s）+ 高 σ 组合漏检严重（0.29），印证"基线参数不可拍脑袋"。

### LLM 研判量化（P1-1）

`tools/eval_llm_judgment.py`：8 个黄金告警案例（6 真实攻击 + 弱特征 SYN 假阳性候选 + 边界 RST 噪音）驱动真实 LLM（glm-4-flash）结构化研判（Pydantic 校验链）：

| 指标 | 结果 |
|---|---|
| 结构化成功率 | 100% (8/8) |
| 降级率 | 0% |
| 威胁判断准确率 | 75% (6/8) |
| RAG 引用率 | 100% (8/8) |
| 平均延迟 | 8.4s/次 |

**失败模式分析（诚实评估，`data/eval_perf/llm_judgment.json`）**：
- `BASELINE_DEVIATION` 被判假——时序基线告警证据链弱（无攻击类型/无 src_ip），LLM 倾向当噪音 → 需在告警上下文补充 z-score 阈值语义或人工复核
- 弱特征 SYN（20 << 阈值 100）被判真——LLM 未利用 `rule_threshold` 字段做数量级比较
- prompt 增加"阈值判读指引"后准确率反降至 62.5%（LLM 非确定性）→ 已回滚，**结论：LLM 研判适合辅助而非取代规则引擎，需人工复核，勿用 prompt 微调替代确定性检测**

### 性能基线（P1-3）

`tools/bench_stream.py`：300,000 包混合流量（28.1MB pcap，SYN 扫描/正常/DNS/大流量），全量 vs 流式（tracemalloc 峰值）：

| 路径 | 耗时 | 峰值内存 | 告警 |
|---|---|---|---|
| 全量（rdpcap + analyze_packets） | 246.7s | **1112.3MB** | 15 |
| 流式（iter_packets + analyze_stream） | 244.0s | **6.8MB** | 15 |

- **内存降低 162.8 倍**（1112.3MB → 6.8MB），耗时持平（1.01x，流式无额外开销）
- 告警一致性 PASS（15/15）；吞吐 1.2k pkt/s，**瓶颈在逐包协议解析**（两路径相同），属解析层优化空间
- 结果固化 `data/eval_perf/perf_baseline.json`

### 异步任务队列 + Docker 部署（P2）

**任务队列**（`src/api/task_queue.py`，线程池 + 内存任务表）：`POST /api/pcap/analyze_async` 大文件任务入队立即返回 task_id，`GET /api/tasks/{task_id}` 轮询状态（pending/running/success/error）——GB 级分析不再阻塞 HTTP 请求。

**Docker 化**：`Dockerfile`（python:3.11-slim + 依赖层缓存 + 健康检查）+ `docker-compose.yml`（LLM Key 运行时注入、`./data` 卷持久化基线/审计/报告）+ `.dockerignore`。一键部署：

```bash
cp .env.example .env   # 填写 LLM_API_KEY
docker compose up -d   # http://localhost:8080
```


### RAG 检索质量评测（Recall@k / MRR，P0 延伸）

`tools/evaluate_rag.py` 基于知识库真实条目构建**黄金问答集（16 问，覆盖 MITRE/手册/协议三类共 16 个条目）**，走生产检索路径（BGE 中文 Embedding + ChromaDB cosine）评测：

| 指标 | 改进前（纯向量） | 改进后（混合检索） |
|---|---|---|
| Recall@1 / @3 / @5 | 0.9375 / 0.9375 / 0.9375 | **0.9375 / 0.9375 / 1.0000** |
| MRR@5 | 0.9375 | **0.9500** |
| MITRE ATT&CK 类 | 10/10 | 10/10 |
| 事件处置手册类 | 4/4 | 4/4 |
| 协议知识类 | 1/2 | **2/2** |

**改进实现**（`src/ai/retrieval_hybrid.py`，针对评测发现的组合问题检索缺陷）：
- **① 查询改写**：显式比较问句（`X和Y的区别/对比/差异`）拆分子查询分别检索后合并——比较问句的多实体为明确并列，拆分后各自检索更聚焦；普通问句中的"和/与"是概念整体，不误拆
- **② BM25 关键词召回 + RRF 融合**：手写 BM25（英文按词 + 中文 bigram 分词、倒排索引、平滑 IDF、k1=1.5/b=0.75），与向量检索 top-20 经 **RRF（Reciprocal Rank Fusion, k=60）** 融合排序——无需调权重即可稳定融合异构排序
- 混合检索为 `RAGEngine.search` 默认路径（`use_hybrid=False` 可回退纯向量），BM25 索引惰性构建（KB 级内存）

**消融实验**（`tools/ablation_rag.py`，Recall@5）：

| 配置 | Recall@5 | 结论 |
|---|---|---|
| 纯向量（基线） | 0.9375 | — |
| 向量 + BM25(RRF) | **1.0000** | Recall 提升主因：关键词召回弥补向量对组合实体的语义重心漂移 |
| 向量 + 查询改写 | 0.9375 | 独立无 Recall 增益，但改善命中排名（MRR↑）与子查询聚焦 |
| 全开（改写 + 双路） | **1.0000** | 16/16 全命中 |

> 复现：`python tools/evaluate_rag.py`（秒级）+ `python tools/ablation_rag.py`
> 口径：黄金问答集问题措辞模拟真实用户提问（不照抄条目标题），命中判定按条目标题关键词子串匹配；改进前诊断记录见 `data/eval_rag/rag_result.json` 的 `diagnosis` 字段。

### RAG（检索增强生成）架构

```
用户问题 → Embedding向量化 → ChromaDB相似度检索 → 相关知识片段
                                                          ↓
大模型回答 ← Prompt组装（问题+检索知识+系统角色）← 知识重排序
```

### 威胁分析流程

```
PCAP文件 → Scapy解析 → 网络流提取 → 协议统计 → 拓扑分析
                                            ↓
                          规则引擎异常检测（5类攻击特征）
                                            ↓
                    RAG检索MITRE ATT&CK + 处置手册
                                            ↓
                    大模型威胁研判（攻击类型/风险等级/处置建议）
                                            ↓
                          结构化安全分析报告
```

## 🔧 API接口列表

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 健康检查 |
| POST | `/api/knowledge/init` | 初始化知识库 |
| GET | `/api/knowledge/stats` | 知识库统计 |
| POST | `/api/knowledge/search` | 搜索知识库 |
| POST | `/api/knowledge/add` | 导入知识文档（.txt/.md/.json） |
| POST | `/api/pcap/analyze` | 分析PCAP文件（含证据哈希） |
| POST | `/api/chat` | 安全问答 |
| POST | `/api/incident/report` | 生成事件报告 |

## ⚠️ 注意事项

1. **API Key安全**：`.env` 文件包含API Key，已加入 `.gitignore`，不要提交到公开仓库；打包分发版本不含任何密钥，由用户自行配置
2. **本地API鉴权**：首次启动自动生成 `API_AUTH_TOKEN` 写入 `.env`，外部调用 `/api/*` 需携带 `X-API-Token` 请求头（Gradio UI 免鉴权，健康检查 `/api/health` 豁免）
3. **上传限制**：单个 PCAP 文件上传上限 200MB，仅允许 `.pcap/.pcapng/.cap/.pcap.gz`
4. **Embedding模型**：BGE-small-zh-v1.5 中文模型（ONNX 格式，约90MB）**已内置安装包**；若文件缺失/损坏，系统首次使用知识库时**自动从镜像下载**，下载失败才降级为英文默认模型
5. **大模型成本**：DeepSeek API非常便宜，分析一个PCAP文件约消耗0.01-0.1元
6. **数据隐私**：所有流量数据本地处理，原始PCAP文件不出本地，仅消毒后的异常摘要发送到大模型API；AI分析结果附源文件SHA-256哈希可溯源

## 📈 后续扩展方向

- [ ] 集成 Suricata/Zeek 开源IDS，增强检测能力
- [ ] 添加 Elasticsearch 存储大规模流量数据
- [ ] 实现实时流量流处理（Kafka + Flink）
- [ ] 添加恶意软件流量分类模型（机器学习）
- [ ] 集成威胁情报API（AbuseIPDB、VirusTotal）
- [ ] 支持多PCAP文件批量分析和对比
- [ ] 添加用户认证和多租户支持
- [ ] Docker容器化部署

## 📄 许可证

MIT License
