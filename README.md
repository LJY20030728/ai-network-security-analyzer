# AI Network Security Analyzer | AI 网络安全分析系统

> **中文**：AI 辅助的网络取证分析系统 — PCAP 离线分析 + 四引擎集成检测 + LLM 威胁研判 + RAG 安全知识问答
>
> **English**: AI-Assisted Network Forensics System — PCAP Offline Analysis + Four-Engine Integrated Detection + LLM Threat Assessment + RAG Security Knowledge Q&A

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green.svg)](https://fastapi.tiangolo.com/)
[![Gradio](https://img.shields.io/badge/Gradio-6.x-orange.svg)](https://www.gradio.app/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-141%20passed-brightgreen.svg)](#测试)

**[中文版](#目录) | [English Version](README_EN.md)**

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [技术架构](#技术架构)
- [快速开始](#快速开始)
- [使用指南](#使用指南)
- [API 文档](#api-文档)
- [评测结果](#评测结果)
- [项目结构](#项目结构)
- [开发指南](#开发指南)
- [常见问题](#常见问题)
- [许可证](#许可证)

---

## 项目简介

传统网络取证分析依赖安全分析师用 Wireshark 逐包查看 PCAP 文件，效率极低且高度依赖个人经验。规则引擎虽然能自动化检测，但对未知攻击和大流量变种漏报严重（UNSW-NB15 大流量类 Recall 仅 0.002）。

本项目是一个 **AI 辅助的离线网络取证分析工具**，实现了：
- **四引擎集成检测**：监督模型（HistGradientBoosting）为主引擎 + 规则引擎 + EWMA 时序基线 + 孤立森林，加权投票降低误报漏报
- **LLM 威胁研判**：大模型将技术告警翻译为人类可读的威胁分析，配套幻觉控制三件套
- **RAG 安全知识问答**：本地向量库（BGE ONNX + ChromaDB），混合检索 + 重排序
- **全流程闭环**：检测 → 分析 → 取证报告（五要素）→ 历史知识库（跨样本关联/趋势分析）

### 为什么选择这个项目

| 维度 | 说明 |
|------|------|
| **算法深度** | 76 维 CICFlowMeter 特征提取、四引擎集成投票、自适应阈值、STL 时序分解 |
| **AI 工程** | 幻觉控制三件套、RAG 混合检索+重排序、本地向量推理 |
| **工程质量** | 141 单元测试、FastAPI + Pydantic、SQLite WAL、DPAPI 加密、全局异常处理 |
| **轻量可移植** | 平均内存峰值 23MB、本地推理不依赖外部服务、Windows .exe 打包 |
| **可验证** | 所有指标都有评测脚本和结果文件，不是"拍脑袋" |

---

## 核心特性

### 🔍 四引擎集成检测

| 引擎 | 类型 | 权重 | 说明 |
|------|------|------|------|
| **监督模型** | HistGradientBoosting | 0.5 | 76 维 CICFlowMeter 特征，流级预测+PCAP 级聚合，F1=0.9487 |
| **规则引擎** | 阈值规则 | 0.2 | 10+ 可配置规则（SYN 洪水/端口扫描/DNS 隧道/RST 风暴等） |
| **时序基线** | EWMA + 中位数/MAD | 0.15 | 4 维度联合检测，多维度同时偏差触发 CRITICAL |
| **孤立森林** | 无监督异常检测 | 0.15 | 低维表格数据适合，检测未知异常 |

- **自适应阈值**：基于输入流量 P95 分位数动态调整，适应不同网络环境
- **STL 高级模式**：零依赖轻量级时序分解（趋势+季节性+残差），捕捉周期性偏离
- **策略模式架构**：可扩展，新增检测算法只需实现接口并注册

### 🤖 LLM 威胁研判 + 幻觉控制

- **威胁分析**：大模型自动生成威胁分析报告，跨告警关联，攻击链还原
- **幻觉控制三件套**：
  - `OutputValidator`：格式/长度/合理性/与证据一致性/幻觉特征词检测
  - `ConfidenceCrossValidator`：LLM vs 规则 vs 监督模型交叉验证，矛盾检测
  - `ReviewMarker`：低置信度/矛盾结论自动标记"需人工复核"
- **思考过程可视化**：显示 LLM 分析和思考过程
- **多模型兼容**：智谱/DeepSeek/OpenAI 兼容接口

### 📚 RAG 安全知识问答

- **本地向量库**：ChromaDB + BGE ONNX 推理（2768 条知识片段，零外部服务依赖）
- **混合检索**：BM25 关键词 + 向量语义，双通道召回
- **轻量级重排序**：标题 0.4 + 内容 0.3 + 元数据 0.2 + 向量距离 0.1 + 精确匹配加分
- **安全术语同义词扩展**：10 类中文→英文，提升跨语言检索效果
- **对话历史持久化**：SQLite 存储，刷新不丢失

### 📋 取证报告五要素

1. **事件时间线**：告警时间轴，严重度颜色标记
2. **ATT&CK 攻击链图**：SVG 7 阶段杀伤链，检测到的阶段红色高亮
3. **IOC 失陷指标列表**：IP/端口/关联告警
4. **证据链**：告警 → 证据 → 检测引擎 → 时间窗口
5. **分析师备注**：虚线框预留填写区域

### 🧠 取证知识库

- **跨样本关联分析**：相同攻击类型/相似告警/时间相近打分，发现攻击模式演变
- **趋势分析**：按日统计/攻击类型分布/严重度趋势/主引擎判定趋势
- **重复检测缓存**：基于文件 SHA256，相同文件直接返回历史结果
- **IOC 提取**：从分析记录自动提取 IP/端口等失陷指标

### 🔒 安全与工程化

- **API Key 安全存储**：Windows DPAPI 加密（ctypes 调用，零额外依赖），绑定当前用户
- **图形化配置向导**：首次启动引导配置，API Key 有效性校验
- **全局异常处理**：10+ 异常类型友好中文提示，用户永远看不到 Python 堆栈
- **日志可观测性**：日志查看器 API（级别/关键词过滤）+ 一键诊断报告（7 大维度）
- **输入校验**：PCAP 文件/API Key/Base URL/基线名称全面校验
- **优雅降级**：LLM 失败→规则引擎摘要，RAG 失败→关键词匹配

---

## 技术架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        桌面窗口（pywebview）                       │
│              Gradio UI + 自定义 HTML/CSS（蓝色二次元风格）         │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTP (localhost:8080)
┌──────────────────────────────▼──────────────────────────────────┐
│                      FastAPI 后端服务                              │
│         Pydantic 20+ 模型 │ 全局异常处理 │ 日志可观测性            │
└──────┬──────────┬──────────┬──────────┬──────────┬─────────────┘
       │          │          │          │          │
┌──────▼───┐ ┌───▼────┐ ┌──▼─────┐ ┌─▼──────┐ ┌▼────────────┐
│  解析层   │ │ 检测层  │ │ AI 层  │ │ 存储层  │ │  安全层      │
│ Scapy    │ │ 四引擎  │ │ LLM    │ │ SQLite │ │  DPAPI      │
│ 流式解析  │ │ 集成投票│ │ +RAG   │ │ WAL    │ │  加密存储    │
└──────────┘ └────────┘ └────────┘ └────────┘ └─────────────┘
```

### 技术栈

| 层级 | 技术 | 版本 | 说明 |
|------|------|------|------|
| **语言** | Python | 3.11 | - |
| **后端** | FastAPI | 0.110+ | 异步 API，Pydantic 校验 |
| **前端** | Gradio | 6.x | 快速 UI，自定义 CSS |
| **桌面** | pywebview | 5.x | 原生窗口，系统 WebView |
| **解析** | Scapy | 2.5+ | PCAP 流式解析 |
| **算法** | scikit-learn | 1.3+ | HistGradientBoosting / IsolationForest |
| **AI** | 大模型 API | - | 智谱/DeepSeek/OpenAI 兼容 |
| **向量** | ChromaDB | 0.4+ | 本地向量库 |
| **嵌入** | BGE ONNX | - | 中文优化，本地推理 |
| **存储** | SQLite | 3.x | WAL 模式，三表+索引 |
| **安全** | DPAPI (ctypes) | - | Windows 内置加密 |
| **日志** | loguru | 0.7+ | 结构化日志 |
| **测试** | pytest | 7.x+ | 141 测试全绿 |

---

## 快速开始

### 环境要求

- Windows 10/11（推荐，DPAPI 加密需要）
- Python 3.11+
- 内存：最低 2GB，推荐 4GB+
- 磁盘：最低 500MB（含模型和依赖）

### 方式一：源码运行（推荐开发）

```bash
# 1. 克隆仓库
git clone https://github.com/your-username/ai-network-security-analyzer.git
cd ai-network-security-analyzer

# 2. 创建虚拟环境
python -m venv venv
venv\Scripts\activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. 下载大文件资源（首次运行必须，约 140 MB）
# BGE 嵌入模型 + MITRE ATT&CK 知识库，因体积较大不包含在仓库中
python tools/init_resources.py

# 5. 配置 API Key（首次运行）
# 复制 .env.example 为 .env，填写 LLM_API_KEY
copy .env.example .env
# 编辑 .env，填写你的 API Key（也可以在 UI 设置中配置，会用 DPAPI 加密存储）

# 6. 启动桌面版
python desktop_app.py

# 或者启动 API 服务（浏览器访问 http://127.0.0.1:8080）
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8080
```

### 方式二：Windows 安装包（推荐用户）

1. 下载最新发布的 `AI-Network-Security-Analyzer-Setup.exe`
2. 双击运行安装程序，选择安装目录
3. 安装完成后，桌面快捷方式启动
4. 首次启动会引导配置 API Key（DPAPI 加密存储，不写死）

### 方式三：Docker（待支持）

```bash
docker build -t ai-network-security-analyzer .
docker run -p 8080:8080 -v ./data:/app/data ai-network-security-analyzer
```

---

## 使用指南

### 1. PCAP 流量分析

1. 打开应用，进入「📊 PCAP流量分析」Tab
2. 点击「选择文件」上传 .pcap/.pcapng 文件（最大 200MB）
3. （可选）选择已学习的时序基线进行对比检测
4. 点击「开始分析」
5. 查看结果：
   - **主引擎判定**：攻击/正常 + 置信度 + 攻击流比例 + 攻击类别
   - **告警列表**：四引擎检测到的所有告警，按严重度排序
   - **流量统计**：包数/流数/字节数/协议分布
   - **AI 威胁分析**：LLM 生成的威胁分析报告（含幻觉控制校验）
   - **取证报告**：点击下载五要素完整 HTML 报告

### 2. 基线管理

1. 进入「📈 基线管理」Tab
2. 点击「上传正常流量学习基线」，选择正常业务流量的 .pcap 文件
3. 输入基线名称，点击「学习」
4. 学习完成后可查看：
   - **基线画像**：4 维度（包数/字节/SYN/端口数）中位数±MAD 条形图（SVG）
   - **对比图**：当前流量 vs 基线中位数折线图（SVG）
5. 分析 PCAP 时可选择该基线进行对比检测

### 3. 安全问答助手

1. 进入「🤖 安全问答」Tab
2. 输入安全相关问题（如"什么是 SQL 注入？如何检测？"）
3. 系统从本地知识库检索相关文档，结合 LLM 生成回答
4. 对话历史自动保存，刷新不丢失
5. 可查看检索到的相关文档片段

### 4. 分析历史

1. 进入「📜 分析历史」Tab
2. 查看所有历史分析记录（文件/时间/告警数/严重度/主引擎判定）
3. 点击记录可查看详情、重新加载分析结果
4. 取证知识库功能：
   - **跨样本关联**：查看与当前样本相似的历史分析
   - **趋势分析**：攻击数量/类型/严重度随时间的变化趋势
   - **重复检测缓存**：相同文件（SHA256）直接返回历史结果

### 5. 设置

1. 进入「⚙️ 设置」Tab
2. 配置 API Key（密码输入框，保存后用 DPAPI 加密存储）
3. 配置 Base URL 和模型名称
4. 点击「测试连接」验证 API Key 有效性
5. 保存后立即生效，无需重启

---

## API 文档

启动服务后访问 `http://127.0.0.1:8080/docs` 查看完整的 Swagger API 文档。

### 核心 API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/health` | GET | 健康检查 |
| `/api/analyze` | POST | PCAP 分析（上传文件） |
| `/api/knowledge/search` | POST | RAG 知识检索 |
| `/api/chat` | POST | 安全问答 |
| `/api/baseline/learn` | POST | 学习基线 |
| `/api/baseline/list` | GET | 基线列表 |
| `/api/baseline/delete` | POST | 删除基线 |
| `/api/forensic/stats` | GET | 取证知识库统计 |
| `/api/forensic/trend` | GET | 攻击趋势分析 |
| `/api/forensic/related/{id}` | GET | 跨样本关联 |
| `/api/config/status` | GET | 配置状态 |
| `/api/config/validate` | POST | API Key 有效性校验 |
| `/api/config/save_secure` | POST | 保存到 DPAPI 加密存储 |
| `/api/logs` | GET | 日志查看器 |
| `/api/logs/stats` | GET | 日志统计 |
| `/api/diagnostic` | GET | 一键诊断报告 |
| `/api/incident/report` | POST | 生成取证报告 |

### 认证

所有 `/api/*` 端点需要在请求头中携带 `X-API-Token`（首次启动自动生成，保存在 .env 的 `API_AUTH_TOKEN`）。Gradio UI（进程内调用）不受影响。

---

## 评测结果

### 监督模型检测效果

| 数据集 | 精确率 | 召回率 | F1 | 准确率 |
|--------|--------|--------|-----|--------|
| **CIC-UNSW**（447,915 流） | 0.9351 | 0.9628 | **0.9487** | 0.9792 |
| **UNSW-NB15**（专用模型） | 0.9633 | **0.9769** | 0.9700 | 0.9589 |

**对比规则引擎**：UNSW-NB15 大流量类 Recall 仅 0.002，监督模型提升 **4884 倍**。

**UNSW-NB15 每类别召回率**：

| 攻击类型 | 召回率 |
|----------|--------|
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

### RAG 检索效果

| 指标 | 数值 |
|------|------|
| 黄金问答集 | 15 题（覆盖攻击技术/检测/响应） |
| **Recall@5** | **0.360** |
| 严格召回率（至少命中 1 个） | 66.7% |
| 平均检索耗时 | 0.291s |
| 知识库片段数 | 2768 条 |

**已知限制**：5 个知识盲区（SQL 注入/勒索软件/钓鱼/内存马/中间人攻击），根本原因是知识库内容不足。补充知识库内容可显著提升 Recall。

### 性能基准

| 指标 | 数值 |
|------|------|
| 测试样本数 | 10 个黄金样本 |
| 总包数 | 28,036 |
| **平均分析耗时** | **5.911 秒/文件** |
| **平均内存峰值** | **22.97 MB** |
| 解析耗时占比 | ~60% |
| 检测耗时占比 | ~25% |
| AI 分析耗时占比 | ~15%（取决于 API 响应速度） |

### 测试覆盖

| 指标 | 数值 |
|------|------|
| 单元测试总数 | **141 passed** |
| 测试文件数 | 12 个 |
| 覆盖模块 | 算法/API/存储/安全/工具 |
| 黄金样本测试 | 10 个 |

---

## 项目结构

```
ai-network-security-analyzer/
├── src/
│   ├── analysis/              # 分析引擎
│   │   ├── cic_features.py    # 76 维 CICFlowMeter 特征提取
│   │   ├── supervised_detector.py  # 监督检测器（HistGradientBoosting）
│   │   ├── flow_extractor.py  # 流提取 + 四引擎集成
│   │   ├── baseline.py        # EWMA 时序基线 + STL 高级检测
│   │   ├── stl_decomposer.py # 零依赖轻量级 STL 时序分解
│   │   ├── isolation_detector.py  # 孤立森林无监督检测
│   │   └── detection_engine.py    # 策略模式 + 工厂模式检测引擎
│   ├── ai/                    # AI 模块
│   │   ├── llm_client.py      # 大模型客户端
│   │   ├── threat_analyzer.py # 威胁分析器
│   │   ├── rag_engine.py      # RAG 检索引擎（混合检索+重排序）
│   │   ├── hallucination_control.py  # 幻觉控制三件套
│   │   ├── evidence_matcher.py      # 证据匹配
│   │   └── embeddings/        # 嵌入模型（BGE ONNX）
│   ├── api/                   # API 层
│   │   ├── main.py            # FastAPI 主应用 + Gradio UI
│   │   ├── schemas.py         # Pydantic 模型（20+）
│   │   ├── history_store.py   # 历史记录存储（SQLite）
│   │   ├── task_queue.py      # 任务队列
│   │   └── audit.py           # 审计日志
│   ├── capture/               # 抓包/解析
│   │   ├── packet_parser.py   # 包解析
│   │   └── pcap_parser.py     # PCAP 文件解析
│   ├── report/                # 报告生成
│   │   └── html_report.py     # HTML 取证报告（五要素）
│   ├── storage/               # 存储层
│   │   ├── database.py        # SQLite 数据库（WAL，三表+索引）
│   │   └── forensic_kb.py     # 取证知识库（关联/趋势/缓存）
│   ├── security/              # 安全层
│   │   └── secure_store.py    # DPAPI 加密存储
│   ├── ui/                    # UI 资源
│   │   └── custom_style.css   # 蓝色二次元风格自定义 CSS
│   └── utils/                 # 工具函数
│       ├── paths.py           # 路径管理
│       ├── helpers.py         # 通用工具
│       ├── error_handler.py   # 错误处理三层
│       └── log_observer.py    # 日志可观测性
├── models/                    # 训练好的模型
│   ├── supervised_detector.joblib      # CIC 监督模型（F1=0.9487）
│   └── unsw_supervised_detector.joblib # UNSW 专用模型（Recall=0.9769）
├── data/                      # 数据目录
│   ├── samples/golden/        # 黄金测试样本（10 个）
│   ├── baselines/             # 基线文件（JSON 兼容备份）
│   ├── db/                    # SQLite 数据库
│   ├── chroma_db/             # ChromaDB 向量库
│   ├── eval_cicids/csv/       # 训练数据（CIC/UNSW）
│   └── eval_perf/             # 评测结果
├── tests/                     # 测试（141 个）
│   ├── test_new_features.py   # 新功能综合测试（34 个）
│   └── ...
├── tools/                     # 工具脚本
│   ├── train_unsw_supervised.py  # UNSW 模型训练
│   ├── eval_supervised_baseline.py
│   ├── benchmark.py           # 性能基准测试
│   └── eval_rag_recall.py     # RAG Recall@5 评测
├── docs/                      # 文档
│   ├── 简历项目描述.md
│   └── 面试准备_STAR+20问.md
├── config/                    # 配置
│   └── settings.py            # 全局配置（pydantic-settings）
├── desktop_app.py             # 桌面版入口（pywebview）
├── requirements.txt           # Python 依赖
├── .env.example               # 环境变量示例
├── .gitignore
├── LICENSE
└── README.md
```

---

## 开发指南

### 新增检测引擎

项目使用策略模式，新增检测算法非常简单：

```python
# 1. 实现 DetectionStrategy 接口
from src.analysis.detection_engine import DetectionStrategy, DetectorFactory

class MyDetector(DetectionStrategy):
    @property
    def name(self): return "my_detector"

    @property
    def version(self): return "1.0.0"

    def detect(self, packets, flows=None, context=None):
        # 你的检测逻辑
        alerts = []
        # ...
        return {"alerts": alerts, "summary": {}, "stats": {}}

# 2. 注册到工厂
DetectorFactory.register("my_detector", MyDetector)

# 3. 在集成引擎中使用（自动加权投票）
from src.analysis.detection_engine import DetectionEngine
engine = DetectionEngine()
engine.add_strategy(MyDetector(), weight=0.1)
result = engine.detect_all(packets)
```

### 运行测试

```bash
# 运行所有测试
pytest tests -q

# 运行特定测试文件
pytest tests/test_new_features.py -v

# 运行带覆盖率（需要 pytest-cov）
pytest tests --cov=src --cov-report=html
```

### 性能基准测试

```bash
python tools/benchmark.py
# 结果保存在 data/eval_perf/benchmark_result.json
```

### RAG 评测

```bash
python tools/eval_rag_recall.py
# 结果保存在 data/eval_perf/rag_recall_result.json
```

### 训练监督模型

```bash
# CIC 模型
python tools/eval_supervised_baseline.py

# UNSW 专用模型
python tools/train_unsw_supervised.py
```

### 代码规范

- 遵循 PEP 8
- 使用类型注解（Type Hints）
- 每个模块/类/函数都有 docstring
- 错误处理：不裸 except，不吞异常，用户永远看不到堆栈
- 日志：使用 loguru，关键操作都有日志

---

## 常见问题

### Q1：API Key 安全吗？会写死在代码里吗？

**A**：绝对不会。API Key 有两种存储方式：
1. **DPAPI 加密存储（推荐）**：Windows 内置加密，绑定当前用户，其他用户无法解密。通过 UI 设置保存时自动加密。
2. **.env 文件**：明文存储，仅作为兼容备份。建议使用 DPAPI 加密存储。

代码中没有任何硬编码的 API Key。

### Q2：需要联网吗？

**A**：分功能：
- **PCAP 解析/检测/基线/报告**：完全离线，不需要联网
- **LLM 威胁分析/安全问答**：需要调用大模型 API，需要联网
- **RAG 检索**：本地向量库，完全离线

项目定位是"离线取证工具"，核心检测功能完全离线可用。

### Q3：支持哪些大模型？

**A**：任何 OpenAI 兼容接口的大模型都支持，包括：
- 智谱 AI（GLM-4-Flash / GLM-4）
- DeepSeek（deepseek-chat / deepseek-coder）
- OpenAI（GPT-3.5 / GPT-4）
- 本地部署的 vLLM / Ollama（OpenAI 兼容接口）

在设置中配置 Base URL 和模型名称即可。

### Q4：内存占用大吗？

**A**：非常轻量。性能基准测试显示：
- 平均内存峰值：**22.97 MB**
- 平均分析耗时：**5.911 秒/文件**（10 个黄金样本，共 28,036 包）

BGE ONNX 模型加载后约占用 100-200MB，但可以按需加载。普通电脑完全可以流畅运行。

### Q5：和 Wireshark / Suricata 有什么区别？

**A**：定位不同，是互补关系：
- **vs Wireshark**：Wireshark 是协议分析器，需要人工逐包查看；本项目是自动化分析工具，上传 PCAP 后自动给出威胁判定和取证报告。
- **vs Suricata**：Suricata 是实时 IDS/IPS，基于规则，需要持续运行；本项目是离线取证分析工具，专注事后分析，用监督模型检测未知攻击。

实际使用场景：用 Suricata 实时监控发现告警，然后用本项目对相关 PCAP 做深度取证分析。

### Q6：RAG Recall@5=0.36 是不是太低了？

**A**：客观看待：
1. 纯向量检索约 0.28，混合检索+重排序提升到 0.36，提升 28.6%
2. 严格召回率（至少命中 1 个）66.7%，这个指标更实用
3. 根本原因是知识库内容不足（2768 条片段，5 个知识盲区），不是算法问题
4. 补充知识库内容后 Recall 可显著提升

这是项目明确标注的"已知限制"，体现了诚实和自我认知。

### Q7：如何打包成 Windows .exe？

**A**：使用 PyInstaller：

```bash
pip install pyinstaller
pyinstaller --noconfirm --windowed --name "AI-Network-Security-Analyzer" ^
    --add-data "models;models" ^
    --add-data "data/samples;data/samples" ^
    --add-data "src/ui/custom_style.css;src/ui" ^
    desktop_app.py
```

打包后的文件在 `dist/` 目录下。建议使用 Inno Setup 制作安装包。

---

## 许可证

MIT License

Copyright (c) 2026 AI Network Security Analyzer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 致谢

- [Scapy](https://scapy.net/) - 强大的网络包处理库
- [FastAPI](https://fastapi.tiangolo.com/) - 现代 Python Web 框架
- [Gradio](https://www.gradio.app/) - 快速构建 ML UI
- [scikit-learn](https://scikit-learn.org/) - 机器学习库
- [ChromaDB](https://www.trychroma.com/) - 本地向量数据库
- [BAAI/bge](https://huggingface.co/BAAI) - 中文优化的嵌入模型
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) - 网络安全数据集
- [CICFlowMeter](https://www.unb.ca/cic/research/tools/flowmeter.html) - 网络流特征提取参考

---

**如果这个项目对你有帮助，欢迎给个 Star ⭐**
