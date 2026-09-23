# AI Network Security Analyzer | AI 网络安全分析系统

> **中文**：AI 辅助的网络取证分析系统 — PCAP 离线分析 + 四引擎集成检测 + LLM 威胁研判 + RAG 安全知识问答
>
> **English**: AI-Assisted Network Forensics System — PCAP Offline Analysis + Four-Engine Integrated Detection + LLM Threat Assessment + RAG Security Knowledge Q&A

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green.svg)](https://fastapi.tiangolo.com/)
[![Gradio](https://img.shields.io/badge/Gradio-6.x-orange.svg)](https://www.gradio.app/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-148%20passed-brightgreen.svg)](#测试)

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
- [更新日志](#更新日志)
- [常见问题](#常见问题)
- [许可证](#许可证)

---

## 项目简介

传统网络取证分析依赖安全分析师用 Wireshark 逐包查看 PCAP 文件，效率极低且高度依赖个人经验。规则引擎虽然能自动化检测，但对未知攻击和大流量变种漏报严重（实测规则引擎在 UNSW-NB15 上攻击召回仅 0.0001）。

本项目是一个 **AI 辅助的离线网络取证分析工具**，实现了：
- **级联 + Stacking 融合检测**：监督模型（HistGradientBoosting）为主引擎 + 规则引擎 + EWMA 时序基线 + 孤立森林；规则引擎高置信度(≥0.85)短路返回，剩余流量由 Stacking 元学习器（LogisticRegression，UNSW 训练 F1=0.9685）自动融合
- **LLM 威胁研判**：大模型将技术告警翻译为人类可读的威胁分析，配套幻觉控制三件套
- **RAG 安全知识问答**：本地向量库（BGE ONNX + ChromaDB），混合检索 + 重排序
- **全流程闭环**：检测 → 分析 → 取证报告（五要素）→ 历史知识库（跨样本关联/趋势分析）

### 为什么选择这个项目

| 维度 | 说明 |
|------|------|
| **算法深度** | 76 维 CICFlowMeter 特征提取、四引擎 Stacking 融合、自适应阈值、STL 时序分解 |
| **AI 工程** | 幻觉控制三件套、RAG 混合检索+重排序、本地向量推理 |
| **工程质量** | 148 单元测试、FastAPI + Pydantic、SQLite WAL、DPAPI 加密、全局异常处理 |
| **轻量可移植** | 平均内存峰值 23MB、本地推理不依赖外部服务、Windows .exe 打包 |
| **可验证** | 所有指标都有评测脚本和结果文件，不是"拍脑袋" |

---

## 核心特性

### 🔍 四引擎集成检测

| 引擎 | 类型 | 运行时角色 | 说明 |
|------|------|------|------|
| **监督模型** | HistGradientBoosting | Stacking 主导（LR 系数 9.37） | 流级预测+PCAP 级聚合；UNSW-NB15（194 维）F1=0.9704、UNSW-CIC 重提取版（76 维）F1=0.9487 |
| **规则引擎** | 阈值规则 | 级联第一级（≥0.85 短路） | 10+ 可配置规则（SYN 洪水/端口扫描/DNS 隧道/RST 风暴等） |
| **时序基线** | EWMA + 中位数/MAD | Stacking 输入（LR 系数 -0.03） | 4 维度联合检测，多维度同时偏差触发 CRITICAL |
| **孤立森林** | 无监督异常检测 | Stacking 输入（LR 系数 -0.37） | 低维表格数据适合，检测未知异常 |

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

- **本地向量库**：ChromaDB + BGE ONNX 推理（1687 条知识片段，零外部服务依赖）
- **混合检索**：BM25 关键词 + 向量语义，双通道召回
- **轻量级重排序**：标题 0.4 + 内容 0.3 + 元数据 0.2 + 向量距离 0.1 + 精确匹配加分
- **安全术语同义词扩展**：10 类中文→英文，提升跨语言检索效果
- **攻击类型知识库**：5 篇专业文档（SQL注入/勒索软件/钓鱼/内存马/中间人攻击），已导入向量库
- **对话历史持久化**：SQLite 存储，刷新不丢失
- **RAG 评测**：16 题黄金问答集双口径评测，Relevant Recall@5=1.0、MRR=0.9375（Strict 口径见评测章节）

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

### 📂 历史记录报告管理

- **确认重新分析机制**：报告文件被删除时，显示确认区域询问用户是否重新执行PCAP分析，避免误操作
- **3阶段进度条**：确认后分阶段显示进度（解析PCAP+特征提取→生成报告→打开报告），用户可实时了解分析状态
- **后台独立执行**：重新分析在后台独立执行完整PCAP分析（含AI研判），不影响Tab1的PCAP分析页面操作，支持多任务并行
- **PCAP文件持久化**：分析完成后自动将PCAP文件复制到 `data/samples/analyzed/` 目录（时间戳前缀），确保重新分析时源文件一定存在，即使原始文件被删除
- **旧记录自动搜索**：对于v2.0.0之前没有 `file_path` 字段的旧记录，自动在 `data/samples/`、桌面、下载目录搜索同名PCAP文件，搜索到后自动更新历史记录
- **一一映射去重**：相同PCAP反复分析使用基于SHA256的固定文件名，覆盖旧报告，避免 `data/reports/` 目录堆积大量重复文件
- **精确记录选择**：下拉框精确选择历史记录（记录ID匹配），避免表格点击状态不同步导致打开错误报告

### 🔒 安全与工程化

- **API Key 安全存储**：Windows DPAPI 加密（ctypes 调用，零额外依赖），绑定当前用户
- **图形化配置向导**：首次启动引导配置，API Key 有效性校验
- **全局异常处理**：10+ 异常类型友好中文提示，用户永远看不到 Python 堆栈
- **日志可观测性**：日志查看器 API（级别/关键词过滤）+ 一键诊断报告（7 大维度）
- **输入校验**：PCAP 文件/API Key/Base URL/基线名称全面校验
- **优雅降级**：LLM 失败→规则引擎摘要，RAG 失败→关键词匹配

---

## 技术架构

### 分层架构（v3.0.0 激进重构）

```
┌─────────────────────────────────────────────────────────────────┐
│                        桌面窗口（pywebview）                       │
│              Gradio UI + 自定义 HTML/CSS（蓝色二次元风格）         │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTP (localhost:8080)
┌──────────────────────────────▼──────────────────────────────────┐
│                      FastAPI 后端服务                              │
│         Pydantic Settings │ 全局中间件 │ 统一异常处理              │
└─────────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                        路由层（src/api/routes/）                   │
│  analyze.py │ baseline.py │ knowledge.py │ chat.py │ system.py │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                        服务层（src/services/）                     │
│  analysis_service │ baseline_service │ knowledge_service          │
│  report_service │ history_service                                │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                        核心层（src/core/）                        │
│  errors.py（30个错误码）│ exceptions.py（8大类异常）│ middleware.py │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────┬──────────┬──────────┬──────────┬─────────────────────┘
▼          ▼          ▼          ▼          ▼
解析层     检测层     AI 层     存储层     安全层
Scapy     四引擎     LLM       SQLite    DPAPI
流式解析   Stacking融合   +RAG      WAL       加密存储
```

### 架构分层说明

| 层级 | 目录 | 职责 | 特点 |
|------|------|------|------|
| **核心层** | `src/core/` | 异常体系、错误码、中间件 | 基础设施，不依赖业务 |
| **服务层** | `src/services/` | 业务逻辑实现 | 单例模式，可独立测试 |
| **路由层** | `src/api/routes/` | API路由定义 | 参数校验，调用服务 |
| **配置层** | `config/settings.py` | 集中配置管理 | Pydantic，按功能分组 |

## 快速开始

### 环境要求

- Windows 10/11（推荐，DPAPI 加密需要）
- Python 3.11+（仅源码运行需要；安装包已内置，无需安装）
- WebView2 Runtime（桌面窗口渲染需要，Windows 10 2004+ / Windows 11 已内置；极少数精简系统缺失时，可在微软官网下载「WebView2 Runtime」）
- 内存：最低 2GB，推荐 4GB+
- 磁盘：最低 500MB（含模型和依赖）

### 方式一：源码运行（推荐开发）

> **最省事：双击运行根目录的 `安装依赖.bat`**。脚本会自动：检测 Python 3.11 → 创建虚拟环境 `venv` → 升级 pip → 安装 `requirements.txt` 中的**全部依赖**（已配置清华镜像，约需 5–15 分钟，结束会显示「依赖安装完成」并暂停，失败也会明确提示）。

手动步骤（与脚本等价）：

```bash
# 1. 克隆仓库
git clone https://github.com/LJY20030728/ai-network-security-analyzer.git
cd ai-network-security-analyzer

# 2. 创建虚拟环境并安装【全部依赖】（必须步骤）
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 3. 下载大文件资源（首次运行必须，约 90 MB）
# BGE 嵌入模型（ONNX）等，因体积较大不包含在仓库中
python tools/init_resources.py

# 4. 配置 API Key（仅 AI 功能需要，核心检测不需要）
copy .env.example .env
# 编辑 .env 填写 LLM_API_KEY；也可启动后在 UI「⚙️ 设置」中配置（DPAPI 加密）

# 5. 启动桌面版
python desktop_app.py

# 或者启动 API 服务（浏览器访问 http://127.0.0.1:8080）
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8080
```

> 核心检测（规则引擎 / 监督模型 / 时序基线 / 孤立森林）**无需任何 API Key 即可运行**；只有「AI 威胁研判」与「安全问答」需要大模型 Key。

### 方式二：Windows 安装包（推荐普通用户）

1. 前往 [Releases 页面](https://github.com/LJY20030728/ai-network-security-analyzer/releases) 下载 `AI网络安全智能分析系统_Setup_3.1.1.exe`
2. 双击运行安装程序，选择安装目录（安装包已内置全部运行依赖与模型，无需另装 Python）
3. **安装程序会自动检测 WebView2 Runtime**：若系统缺失，会先弹窗说明，点击「安装」后自动联网下载并静默安装（内置微软官方在线安装器），无需手动处理
4. 安装完成后，通过桌面 / 开始菜单快捷方式启动
5. 核心检测开箱即用；如需 AI 威胁研判与安全问答，在应用内「⚙️ 设置」中配置大模型 Key（DPAPI 加密存储，不写死）

### 方式三：Docker 部署（服务器/跨平台推荐）

```bash
# 1. 克隆项目
git clone https://github.com/LJY20030728/ai-network-security-analyzer.git
cd ai-network-security-analyzer

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env，填入你的 LLM_API_KEY

# 3. 构建并启动（推荐用 docker compose）
docker compose up -d --build

# 4. 访问服务
# 浏览器打开 http://localhost:8080
```

> 📖 完整 Docker 部署指南请查看 [docs/DOCKER_DEPLOYMENT.md](docs/DOCKER_DEPLOYMENT.md)（含环境变量配置、数据持久化、生产环境建议、故障排查）

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
3. 配置 Base URL 和模型名称（**默认：智谱 GLM，Base URL `https://open.bigmodel.cn/api/paas/v4`，模型 `glm-4.5-air`**；本地嵌入固定为 `BAAI/bge-small-zh-v1.5`）
4. 点击「保存配置」后立即生效，无需重启；也可切换为 DeepSeek / OpenAI 兼容接口或 Ollama 本地模型
5. 页面下方实时显示 **RAG 知识库路径**（向量库目录 / 知识源文档目录 / 文档块数 / 就绪状态），便于确认知识库是否已初始化

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

> 本节所有数字均为真实运行产物，原始结果保存在 `data/eval_perf/`、`data/eval_rag/`、`data/eval_cicids/`，可通过对应脚本一键复现，非估算或模拟。

### 监督模型检测效果

监督模型（HistGradientBoosting）作为**主检测器**，并在两个数据集上分别验证：

| 数据集 | 流数量 | 精确率 | 召回率 | F1 | 准确率 |
|--------|--------|--------|--------|-----|--------|
| **UNSW-NB15**（同分布划分） | 175,341 | 0.9637 | **0.9772** | **0.9704** | 0.9594 |
| **UNSW-CIC 重提取版**（76 维 CICFlowMeter，同分布分层，**非公开 CIC-IDS2017**） | 447,915 | 0.9351 | 0.9628 | **0.9487** | 0.9792 |

> **诚实说明（UNSW-CIC 重提取版）**：上表 0.9487 是二分类**聚合** F1；分攻击类别看少数类召回偏低（DoS 0.168、Analysis 0.260、Shellcode 0.241、Worms 0.306），攻击类 **macro recall 仅 0.4683**。该数据为 UNSW-NB15 底层流量经 CICFlowMeter 重提取（时间轴为行序×0.5s 合成、无真实时间戳），并非公开 CIC-IDS2017，仅用于验证 76 维 CICFlowMeter 特征体系。

**对比无监督/规则引擎**（同一 UNSW-NB15 测试集）：

| 检测器 | 攻击召回率 |
|--------|-----------|
| 规则引擎（大流量类） | 0.0001 |
| 孤立森林 | 0.2107 |
| 时序基线（σ=2 最优） | 0.5045 |
| **监督模型** | **0.9772** |

监督模型相对规则引擎把大流量攻击召回从 0.0001 提升到 0.9772（约 **9700 倍**），这正是把它设为主检测器的原因。

### 过拟合检测与模型稳定性

| 指标 | 数值 | 说明 |
|------|------|------|
| 训练集 F1 | 0.9791 | — |
| 测试集 F1 | 0.9704 | — |
| **F1 差距** | **0.0088** | ✅ 过拟合风险低（< 0.03） |
| **5 折交叉验证 F1** | **0.9394 ± 0.0429** | 整体稳定（含一折 0.86，反映少数批次波动） |
| L2 正则化 / 早停 | l2=1.0 / early_stopping=True | 双重防过拟合 |

**结论**：训练/测试 F1 差距仅 0.0088，同分布下过拟合风险低。但需注意——真正的跨数据集迁移会因特征体系不对齐而显著下降（见下文「泛化能力评估」，UNSW→NSL 仅 0.192），因此系统在新环境必须靠基线学习 / 本地重训，而不能直接套用现成模型。

### 时间外推验证（Out-of-Time，最贴近真实部署）

分层随机划分衡量的是"同一时间窗内"的泛化，但真实部署中模型总是被用在**未来**采集的流量上。为检验时间外推能力，使用 UNSW-NB15 **官方两个不同时间窗**的划分：整个官方 training-set（175,341 条）训练、官方 testing-set（82,332 条，另一时间窗）独立测试（`tools/eval_unsw_oot.py`）：

![三层验证口径对比](docs/validation_split_comparison.png)

| 验证口径 | F1 | 说明 |
|----------|-----|------|
| 同分布（分层随机） | 0.9704 | 同一时间窗，性能上界 |
| **时间外推 OOT** | **0.8924** | 另一时间窗，P 0.8187 / R 0.9808 / Acc 0.8698 |
| 跨数据集 UNSW→NSL | 0.1924 | 换特征体系 / 数据集，泛化下界 |

- 训练自身 F1=0.9783，时间外推后 F1 衰减 **0.0859**、仍保持 0.89——说明模型并非只记住同分布样本，对未来时间窗有合理外推能力。
- OOT 下 **Normal 类召回 0.734（误报偏多，P 降到 0.82）是真实短板**：模型倾向于把新时间窗里未见模式的正常流判为攻击。这指向"部署时应结合基线学习 + 本地少量校准"，而非零样本直接上线。
- 测试期出现 5 个训练时未见的 `state` 取值，按全 0 处理（类别值未知的保守兜底）。

### UNSW-NB15 每类别召回率

| 攻击类型 | 召回率 | | 攻击类型 | 召回率 |
|----------|--------|-|----------|--------|
| Backdoor | 1.0000 | | Exploits | 0.9953 |
| Worms | 1.0000 | | DoS | 0.9988 |
| Generic | 1.0000 | | Shellcode | 0.9911 |
| Reconnaissance | 0.9991 | | Analysis | 0.9171 |
| Normal | 0.9215 | | Fuzzers | 0.8715 |

### RAG 检索效果（双口径 Recall@k / MRR）

用 16 题黄金问答集（覆盖 MITRE 技术、协议、处置手册、Web 安全）评测生产检索路径
（BGE 中文向量 + BM25 + RRF 融合 + term-aware 重排），采用两种口径同时报告：

| 口径 | Recall@1 | Recall@3 | Recall@5 | MRR@5 |
|------|----------|----------|----------|-------|
| **Strict（唯一权威条目）** | 0.6875 | 1.0000 | 1.0000 | 0.8333 |
| **Relevant（相关文档集合）** | **0.8750** | 1.0000 | 1.0000 | **0.9375** |

- **Strict**：gold = 标题含技术ID / 手册全名的唯一权威文档，衡量特定权威条目的排序。
- **Relevant**：gold = 客观上能回答该问题的文档集合（信息检索标准做法，一个问题的相关文档本就不止一个），衡量首位 / top-k 相关性；每个 gold 集合依据见 `tools/evaluate_rag.py` 注释。
- 向量库规模：**1687 片段 / 63 条目**（含 **697 个有效 ATT&CK 技术**，已排除 149 撤销 + 12 弃用；15 篇全量技术展开），平均检索耗时 ~0.3s。
- 分品类 Relevant Recall@5：MITRE 1.0、处置手册 1.0、协议 1.0。
- **诚实标注的两个首位瑕疵**：横向移动问题 top1 为"端口对照表"、系统信息发现 top1 为同属侦察的 T1046（正确条目均在 top3 内；不硬调权重以免过拟合评测）。原始结果见 `data/eval_rag/rag_result.json`。

### 流式 vs 全量：内存压测（30 万包 / 28 MB PCAP）

| 模式 | 耗时 | 内存峰值 | 告警数 |
|------|------|----------|--------|
| 全量加载 | 246.7s | **1112.3 MB** | 15 |
| 流式解析 | 244.0s | **6.8 MB** | 15 |

流式处理内存峰值降低 **162.8 倍**，且告警结果完全一致（`data/eval_perf/perf_baseline.json`）。这是系统能在普通笔记本上分析 GB 级 PCAP 的关键。

### 测试覆盖

| 指标 | 数值 |
|------|------|
| 测试结果 | **148 passed / 19 skipped / 0 failed** |
| 测试文件数 | 17 个 |
| 覆盖模块 | 算法检测 / API 路由 / 存储 / 安全 / 服务层 / 工具 |

---

## 深度评测与优化实验

> 每个实验都对应根目录一个可复现脚本，图表与 CSV 数据保存在 `docs/`。

### 1. 特征重要性分析（Permutation Importance）

不拍脑袋选特征，而是在**真实未见过的测试集**（分层抽取 4000 条代表性样本）上做置换重要性（`n_repeats=3`，以 F1 为评分），逐一验证每个特征被打乱后模型性能的真实下降幅度：

![特征重要性](docs/feature_importance.png)

**Top 5 最重要特征**（置换重要性均值）：

| 排名 | 特征 | 重要性 | 含义 |
|------|------|--------|------|
| 1 | `sttl` | **0.2229** | 源到目的 TTL（攻击流 TTL 分布显著异常，是决定性特征，重要性远超其他） |
| 2 | `ct_state_ttl` | 0.0089 | 流状态 TTL 关联计数 |
| 3 | `sbytes` | 0.0072 | 源到目的字节数 |
| 4 | `ct_srv_src` | 0.0061 | 源地址同服务连接计数 |
| 5 | `ct_srv_dst` | 0.0057 | 目的地址同服务连接计数 |

另有按特征类别聚合的重要性图 `docs/feature_category_importance.png`。

---

### 2. 泛化能力与跨域迁移评估（含"失败"的真实结果）

不回避模型短板。选取 UNSW 与 NSL-KDD **语义可对应的 5 个共有特征**（时长 / 源字节 / 目的字节 / 连接计数 / 同服务计数），实测四种情形：

![泛化能力评估](docs/generalization_evaluation.png)

| 情形 | F1 | 说明 |
|------|-----|------|
| A. UNSW 同分布 | 0.9635 | 训练/测试同分布，性能上界 |
| B. NSL 独立测试集 | 0.7967 | NSL 官方独立测试，换数据集后明显下降 |
| C. UNSW → NSL 跨域迁移 | **0.1924** | 直接把 UNSW 模型用到 NSL，几乎失效 |
| D. NSL 完整 31 特征 | 0.7785 | 仅用 NSL 自身特征训练（对照） |

**域偏移鸿沟 Δ = 0.604**。这个"难看"的结果恰恰是系统设计的核心依据：**一个模型无法跨网络环境直接使用**——不同环境的协议构成、服务分布、流量基线差异巨大。因此产品没有押注"一个通用模型走天下"，而是提供「基线管理」让系统学习每个环境自身的正常画像、并支持本地重训；AI（RAG + LLM）负责跨环境通用的研判与解释。这也说明为什么基线学习是必备功能而非锦上添花。

> 关于监督模型选型：HistGradientBoosting 与 XGBoost / LightGBm 性能差距 < 0.01，但它是 sklearn 原生、零额外依赖、PyInstaller 打包最稳定，因此工程上最优，不引入两个重依赖。

---

### 3. 性能压测（10 个样本，真实计时 / 内存）

10 个样本从 10 包到 1.1 万包、最大 11.4MB，用 time + tracemalloc 实测：

![性能压测](docs/performance_benchmark.png)

| 文件 | 大小 | 包数 / 流数 | 总耗时 | 内存峰值 |
|------|------|------------|--------|----------|
| dnstunnel | <1KB | 10 / 0 | 0.03s | 0.9MB |
| portscan | <1KB | 50 / 50 | 0.09s | 0.9MB |
| rststorm | <1KB | 80 / 80 | 0.12s | 0.9MB |
| synflood | 0.01MB | 200 / 198 | 0.26s | 1.3MB |
| lightscan | 0.12MB | 1495 / 235 | 1.49s | 5.7MB |
| normal | 0.12MB | 1480 / 220 | 1.72s | 5.6MB |
| burst | 0.18MB | 2080 / 820 | 2.73s | 8.2MB |
| baseline_demo_normal | 0.63MB | 2729 / 2729 | 4.18s | 15.2MB |
| largeflow | 11.44MB | 8239 / 1 | 9.51s | 67.0MB |
| baseline_demo_attack | 1.2MB | 11673 / 11661 | **22.06s** | **124.5MB** |

**典型场景**（<3000 包的日常文件）耗时 0.03–2.7s、内存峰值 <8.2MB，普通笔记本秒级完成；10 样本平均耗时 **4.22s**、平均内存峰值 **23.0MB**。

**如实保留的瓶颈**：`baseline_demo_attack`（1.16 万个高基数短连接）耗时 22s、峰值 124MB；`largeflow`（单条 11MB 巨型流）9.5s、67MB——图中以橙色标出。瓶颈来自高基数流表的构建开销，是后续优化（流表哈希分桶、超大单流截断）的明确方向，而非用平均值掩盖。

---

### 4. RAG 效果真实对比（直接 Prompt vs RAG）

5 个真实网络安全问题，对比裸调 LLM 与 RAG 增强：

![RAG对比](docs/rag_real_comparison.png)

| 指标 | 直接 Prompt | RAG 检索 |
|------|-------------|----------|
| 平均耗时 | 6.02s | 6.34s（仅多 0.32s） |
| 平均回答长度 | 128 字 | **202 字** |
| 空/失败回答 | **3 个** | **0 个** |
| 来源可追溯 | ❌ | ✅ |

**幻觉铁证**：问「T1046 是什么技术」，直接 Prompt 答成「初始访问 / 网络共享驱动」（错误），RAG 正确答出「侦察 / 网络服务扫描」；另有 3 个问题直接 Prompt 直接返回空。RAG 用 ~0.3s 的额外检索换来准确性、完整性和稳定性的全面提升。

---

### 5. 检测融合架构（级联 + Stacking）

当前运行的检测融合架构：规则引擎第一级快速过滤，剩余流量交 Stacking 元学习器判定。在无泄漏 held-out 上（开发集 5 折 OOF 生成基引擎预测、训练融合器，独立 20% 评估）实测：

![融合架构对比](docs/fusion_architecture_comparison.png)

| 方案 | held-out F1 |
|------|------------|
| 仅监督模型 | 0.9691 |
| 级联 + Stacking（当前运行） | **0.9691** |
| Stacking 元学习器 | 0.9691 |
| GridSearch 权重 | 0.9692 |
| 人工指定权重 | 0.9577 |

**运行时路径**：
1. **规则引擎第一级**：SYN 洪水 / 端口扫描 / DNS 隧道等规则，置信度 ≥0.85 直接判定（级联短路，省 75% 计算）
2. **Stacking 元学习器**：`models/meta_learner.joblib`（LogisticRegression，UNSW OOF 训练 F1=0.9685），输入四引擎置信度，输出最终攻击概率（阈值 0.5）
3. **LR 学到的系数**：监督模型 9.37（主导）、规则 0.009、基线 -0.03、孤立森林 -0.37——数据自动告诉系统：监督模型已经很强，其他引擎在冷启动 / 未知攻击场景补充信号

---

### 6. 与现有工具的差异化对比

| 维度 | Wireshark | Suricata/Snort | **本系统** |
|------|-----------|----------------|-----------|
| 分析方式 | 人工逐包查看 | 规则/签名匹配 | **多引擎 + AI 自动研判** |
| 目标用户 | 网络专家 | 安全工程师 | 安全运维 / 分析师 |
| 未知/加密流量 | 人工发现 | 规则外漏报 | 行为基线 + 无监督 + 监督兜底 |
| 威胁解读 | 无 | 原始告警 | LLM 翻译为人类可读报告 + 处置建议 |
| 知识问答 | 无 | 无 | RAG 安全知识库（1687 片段） |
| 输出物 | 数据包列表 | 告警日志 | 取证五要素 HTML 报告 |
| 部署 | 本地 | 服务器 | 一键安装 / Docker / 源码 |

**核心定位**：Wireshark 是给专家的"显微镜"，Suricata 是规则驱动的"安检门"，本系统是给分析师的 **AI 研判助手** —— 上传 PCAP 即可得到从证据、攻击链到处置建议的完整结论。

---

## 项目结构

```
ai-network-security-analyzer/
├── config/                    # 配置层（v3.0.0 重构）
│   └── settings.py           # Pydantic Settings，按功能分组
├── src/
│   ├── core/                  # 核心层（v3.0.0 新增）
│   │   ├── errors.py          # 30个标准化错误码
│   │   ├── exceptions.py      # 8大类业务异常（AppError基类）
│   │   └── middleware.py      # 请求日志+全局异常处理中间件
│   ├── services/              # 服务层（v3.0.0 新增）
│   │   ├── analysis_service.py # PCAP分析服务
│   │   ├── baseline_service.py # 基线管理服务
│   │   ├── knowledge_service.py # 知识库服务
│   │   ├── report_service.py   # 报告生成服务
│   │   └── history_service.py # 历史记录服务
│   ├── api/                   # API 层
│   │   ├── main.py            # FastAPI 主应用（v3.0.0 精简版，~100行）
│   │   ├── routes/            # 路由层（v3.0.0 新增）
│   │   │   ├── analyze.py      # PCAP分析路由
│   │   │   ├── baseline.py    # 基线管理路由
│   │   │   ├── knowledge.py   # 知识库路由
│   │   │   ├── chat.py        # 安全问答路由
│   │   │   └── system.py      # 系统路由
│   │   ├── schemas.py         # Pydantic 模型（20+）
│   │   ├── history_store.py   # 历史记录存储（SQLite）
│   │   ├── task_queue.py      # 任务队列
│   │   └── audit.py           # 审计日志
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
│   ├── ui/                    # UI 层
│   │   ├── gradio_app.py      # Gradio UI（v3.0.0 骨架）
│   │   └── custom_style.css   # 蓝色二次元风格自定义 CSS
│   └── utils/                 # 工具函数
│       ├── paths.py           # 路径管理
│       ├── helpers.py         # 通用工具
│       ├── error_handler.py   # 错误处理三层
│       └── log_observer.py    # 日志可观测性
├── models/                    # 训练好的模型
│   ├── supervised_detector.joblib      # UNSW-CIC 重提取版监督模型（76 维，F1=0.9487）
│   └── unsw_supervised_detector.joblib # UNSW 专用模型（Recall=0.9772）
├── data/                      # 数据目录
│   ├── samples/golden/        # 黄金测试样本（10 个）
│   ├── baselines/             # 基线文件（JSON 兼容备份）
│   ├── db/                    # SQLite 数据库
│   ├── chroma_db/             # ChromaDB 向量库
│   ├── eval_cicids/csv/       # 训练数据（CIC/UNSW）
│   └── eval_perf/             # 评测结果
├── tests/                     # 测试（148 个用例 / 17 个文件）
│   ├── test_services/         # 服务层单元测试（v3.0.0 新增）
│   ├── test_routes/           # 路由层单元测试（v3.0.0 新增）
│   ├── test_new_features.py   # 新功能综合测试（34 个）
│   └── ...
├── tools/                     # 可复现实验脚本
│   ├── train_unsw_supervised.py  # UNSW 监督模型训练（分层随机）
│   ├── eval_supervised_baseline.py  # CIC 监督基线
│   ├── generalization_eval.py # 泛化 / 跨域迁移评估
│   ├── fusion_comparison.py   # 融合架构对比
│   ├── benchmark.py           # 性能基准（time + tracemalloc）
│   └── eval_rag_recall.py     # RAG Recall@k 评测
├── feature_importance.py      # 置换重要性（真实数据）
├── benchmark_performance.py   # 读取压测结果画图
├── rag_real_comparison.py     # 直接 prompt vs RAG 真实对比
├── docs/                      # 文档与实验图表
│   ├── 项目自述_REACT完整版.md
│   └── DOCKER_DEPLOYMENT.md
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

# 3. 在集成引擎中使用（Stacking 元学习器融合）
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
- 智谱 AI（GLM-4.5-Air / GLM-4）
- DeepSeek（deepseek-chat / deepseek-coder）
- OpenAI（GPT-3.5 / GPT-4）
- 本地部署的 vLLM / Ollama（OpenAI 兼容接口）

在设置中配置 Base URL 和模型名称即可。

### Q4：内存占用大吗？

**A**：非常轻量。10 样本性能基准（共 28,036 包）显示：
- 平均内存峰值：**23.0 MB**
- 平均分析耗时：**4.22 秒/文件**
- 典型 <3000 包文件：0.03–2.7s、峰值 <8.2MB（极端高基数文件可达 22s / 124MB，属已知瓶颈，见性能压测节）

BGE ONNX 模型加载后约占用 100-200MB，但可以按需加载。普通电脑完全可以流畅运行。

### Q5：和 Wireshark / Suricata 有什么区别？

**A**：定位不同，是互补关系：
- **vs Wireshark**：Wireshark 是协议分析器，需要人工逐包查看；本项目是自动化分析工具，上传 PCAP 后自动给出威胁判定和取证报告。
- **vs Suricata**：Suricata 是实时 IDS/IPS，基于规则，需要持续运行；本项目是离线取证分析工具，专注事后分析，用监督模型检测未知攻击。

实际使用场景：用 Suricata 实时监控发现告警，然后用本项目对相关 PCAP 做深度取证分析。

### Q6：RAG 的 Recall@5 是怎么测的？可信吗？

**A**：用 16 题人工标注的黄金问答集，在不看答案的情况下检索 Top-5，并以两种口径统计：
1. **Strict 口径**（gold = 唯一权威条目）：Recall@1=0.6875、@5=1.0、MRR=0.8333
2. **Relevant 口径**（gold = 客观相关文档集合）：Recall@1=0.875、@5=1.0、MRR=0.9375
3. 生产检索为 BGE 中文向量 + BM25 + RRF + term-aware 重排，平均约 0.3s
4. 评测脚本与黄金集都在仓库中（`tools/evaluate_rag.py`、`data/eval_rag/`），gold 集合依据写在脚本注释里，可一键复算；两个首位瑕疵（横向移动、系统信息发现）如实保留。

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

## 更新日志

详细更新记录请查看 [CHANGELOG.md](CHANGELOG.md)。

### [3.1.1] - 2026-09-21

**科学验证口径补强 + 知识库可复现修复**：
- 新增时间外推 OOT 评测：官方 training 训练 / 官方 testing（另一时间窗）测试，F1=0.8924，较训练自身衰减 0.0859（`tools/eval_unsw_oot.py`）
- 新增三层验证口径对比图（同分布 0.970 / 时间外推 0.892 / 跨数据集 0.192，`docs/validation_split_comparison.png`）
- 知识库构建完全脱离运行时二进制：STIX 源 → `tools/build_knowledge_base.py` 生成 docs → 一键入库，干净 clone 可复现
- 修复 STIX 解析：正确解析 course-of-action 与 mitigates 关系、建立技术→缓解映射（旧代码用了不存在的字段）
- 知识库初始化幂等化（先清空再重建），全量重建为 **1687 片段 / 63 条目 / 697 个有效 ATT&CK 技术**（已排除 149 撤销 + 12 弃用）
- RAG 评测升级为双口径（Strict / Relevant），修复 rerank 标题信号失效 bug、升级 term-aware 重排
- 模型默认名更正为 **glm-4.5-air**（与实际配置一致）
- 补 MIT LICENSE；清理过期残留文件

### [3.1.0] - 2026-09-21

**实验诚信重做（方案 A，最彻底）**：
- 全部实验图表改用真实数据重跑，删除由模拟 / 合成 / 随机数生成的旧图
- 监督训练切分纠正：由错误的"行序 80/20"改为分层随机划分（原行序切分导致测试集几乎全攻击、F1 虚高 0.995）
- 特征重要性：改为真实未见过测试集上的置换重要性（`sttl` 以 0.223 主导）
- 泛化评估：新增真正的跨域迁移实验（UNSW→NSL F1=0.192，域偏移鸿沟 0.604），纠正此前把 NSL 内部结果误标为跨域
- 融合对比：无泄漏 held-out 重跑，证实固定权重次优（0.958）、数据驱动权重回到 0.969
- 性能压测：真实 time/tracemalloc，诚实区分典型场景与高基数瓶颈

**清理**：
- 删除 dead code（假 fusion_detector、run_dev、旧 onefile 打包脚本、空 schemas）
- 删除不可复现的模型对比（依赖未声明的 xgboost/lightgbm）
- 删除重复图标、冗余 zip、运行时残留（dist/build/installer_output，约 1.1GB）
- 求职材料移出公开仓库、本地单独备份

测试：**148 passed / 19 skipped / 0 failed**

### [2.1.0] - 2026-09-14

**新增功能**：
- 历史记录报告管理完整重构：确认重新分析机制 + 3阶段进度条 + 后台独立执行
- PCAP文件持久化：分析时自动复制到 `data/samples/analyzed/`，确保重新分析时源文件存在
- 旧记录自动搜索：在 `data/samples/`、桌面、下载目录搜索同名PCAP文件
- 攻击类型知识库：5篇专业文档（SQL注入/勒索软件/钓鱼/内存马/中间人攻击）

**问题修复**：
- 修复点击打开报告同时打开两个报告的严重Bug（变量名冲突）
- 修复Gradio 6.x Dropdown不支持placeholder导致UI挂载404的问题
- 修复进度条不显示的问题（同一组件在outputs中出现两次）
- 修复 `NameError: name 'actual_id' is not defined`

**功能优化**：
- 确认区域UI优化：移到按钮紧下方，增加标题和详细说明
- 未分析时点击下载报告提示"还未进行任何分析"
- 相同PCAP反复分析使用SHA256文件名实现一一映射，不生成重复报告

### [2.0.0] - 2026-09-11

- P0-P3完整重构：四引擎集成检测 + LLM幻觉控制 + RAG混合检索 + 取证知识库 + DPAPI加密
- 141个单元测试全绿，平均分析耗时5.9s/文件，内存峰值23MB

---

## 许可证

MIT License

Copyright (c) 2026 Jingyu Liao (LJY20030728)

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





