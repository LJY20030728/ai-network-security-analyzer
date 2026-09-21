# 更新日志 | Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/) 规范。

---

## [3.1.1] - 2026-09-21

### 科学验证口径补强
- **新增时间外推 OOT 评测**（`tools/eval_unsw_oot.py`）：用 UNSW-NB15 官方两个不同时间窗，整个官方 training-set（175,341）训练、官方 testing-set（82,332）独立测试，F1=0.8924（P 0.8187 / R 0.9808 / Acc 0.8698），较训练自身 F1 0.9783 衰减 0.0859。
- **新增三层验证口径对比图**（`tools/plot_validation_comparison.py` → `docs/validation_split_comparison.png/.csv`）：同分布 0.970 / 时间外推 0.892 / 跨数据集 0.192。
- OOT 下 Normal 类召回 0.734（误报偏多）为真实短板，指向部署需结合基线学习与本地校准。

### 知识库可复现修复（P0）
- 知识库构建完全脱离运行时二进制：STIX 源（`data/knowledge/mitre_attck/enterprise-attack.json`，gitignore 不入库）→ `tools/build_knowledge_base.py` 生成 15 篇 docs → `KnowledgeService.initialize()` 一键入库；干净 clone 可一键复现。
- 修复 STIX 解析：正确解析 course-of-action（268）与 relationship(mitigates, 21262)、建立技术→缓解映射；旧代码用了不存在的 `obj.get("mitigations")`。
- 补 stealth / defense-impairment 两个新战术的中文映射。
- `KnowledgeService.initialize()` 幂等化（先 clear 再全量重建），重复点击不翻倍。
- 全量重建为 **1687 片段 / 63 条目 / 709 ATT&CK 技术**（旧库 933）。

### RAG 评测与排序
- RAG 评测升级为**双口径**（`tools/evaluate_rag.py`）：Strict（唯一权威条目）@1=0.6875 / @5=1.0 / MRR=0.8333；Relevant（相关文档集合）@1=0.875 / @5=1.0 / MRR=0.9375。
- 修复 `_rerank` 标题信号失效 bug（标题在 metadata、旧代码读顶层空值），并升级为 term-aware 语义重排（BGE 语义 + 核心词精确命中），纠正"问 DNS 隧道却把 SQL 注入排第一"。
- 保留两个首位瑕疵（横向移动、系统信息发现），不硬调权重过拟合评测。

### 配置 / 文档 / 清理
- **模型事实更正**：应用实际 LLM 为 **glm-4.5-air**（`.env` 经 Settings 的 env_file 覆盖代码默认；本条目纠正 3.1.0 误写的 glm-4-flash）；代码默认值同步改为 glm-4.5-air。
- 补 MIT LICENSE（版权 Jingyu Liao / LJY20030728）。
- 删除过期残留：`data/knowledge/` 下两个 import README、rebuild_log、build_report。

---

## [3.1.0] - 2026-09-21

### 实验诚信重做（方案 A，最彻底）
- 全部实验图表改用真实数据重跑，删除由模拟 / 合成 / 随机数生成的旧图。
- 监督训练切分纠正：由错误的"行序 80/20"改为分层随机划分（原行序切分使测试集几乎全攻击、F1 虚高 0.995）；重跑得 F1 0.9704。
- 特征重要性：改为真实未见过测试集上的置换重要性（`sttl` 以 0.223 主导）。
- 泛化评估：新增真正的跨域迁移实验（UNSW→NSL F1=0.192，域偏移鸿沟 0.604），纠正此前把 NSL 内部结果误标为跨域。
- 融合对比：无泄漏 held-out 重跑，证实固定权重次优（0.958）、数据驱动权重回到 0.969。
- 性能压测：真实 time/tracemalloc，诚实区分典型场景（<3000 包 0.03–2.7s / <8.2MB）与高基数瓶颈（22s / 124MB）。

### 清理
- 删除 dead code：假 fusion_detector、run_dev、旧 onefile 打包脚本、空 schemas。
- 删除不可复现的模型对比（依赖未声明的 xgboost/lightgbm）。
- 删除重复图标、冗余 zip、运行时残留（dist/build/installer_output，约 1.1GB）。
- 求职材料移出公开仓库、本地单独备份。

### 文档事实纠正
- 默认大模型实际为智谱 `glm-4-flash`（**非此前 v3.0.1 条目误写的 glm-4.5-air**），以 `config/settings.py` 为准。
- 知识库为 933 片段 / 20 篇源文档（纠正 2804、22 篇等不一致数字）。
- 测试：148 passed / 19 skipped / 0 failed。

---

## [3.0.1] - 2026-09-21

### 安装程序自动检测并安装 WebView2 🌐
- 安装程序启动时通过注册表（HKLM `WOW6432Node` 与 HKCU 的 `EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}` 的 `pv` 值）检测 WebView2 Runtime。
- 缺失时：**最早期弹窗告知 → 点击「安装」后自动运行内置的微软官方在线安装器（`MicrosoftEdgeWebView2Setup.exe`，约 2MB，已校验 Authenticode 签名）联网下载并静默安装（`/silent /install`）**，无需手动操作；正确处理成功 / 需重启(3010) / 已存在(1638) 等退出码，失败给出可操作提示。
- 非提权（per-user）安装，不弹 UAC。

### 依赖完整性与文档事实补正 📝
- **requirements.txt 补全 8 个项目直接 import 但此前未显式声明的依赖**：`onnxruntime`、`python-docx`、`matplotlib`、`pandas`、`numpy`、`joblib`、`openai`、`PyPDF2`，避免源码安装因间接依赖变动而缺包。
- **README 模型配置写明事实**：默认大模型为智谱 GLM `glm-4.5-air`，本地嵌入固定为 `BAAI/bge-small-zh-v1.5`（ONNX，离线）；兼容 DeepSeek / OpenAI / Ollama。
- **源码安装突出一键脚本 `安装依赖.bat`**（自动建 venv 并安装全部依赖）。
- 本次未改动检测 / AI 运行逻辑，主要增强安装与部署体验。

---

## [3.0.0] - 2026-09-20

### 架构修复 🔧

#### 1. 统一 FastAPI 应用实例（关键）
- **问题**：重构后存在两个并行 FastAPI app —— `src/api/main.py` 自建了一个残缺 app（无 Token 鉴权中间件、无审计路由），而 `src/ui/gradio_app.py` 中功能完整的 app（含鉴权/审计/全部端点）反而未被使用，导致实际运行的服务"裸奔"且审计接口 404。
- **修复**：`main.py` 改为纯 re-export 唯一完整 app，`from src.api.main import app` 与直接导入得到同一实例，彻底消除行为不一致。

#### 2. 检测引擎 Stacking 接口补全
- 补全 `_meta_learner` 初始化、`set_meta_learner()` 与 `_stacking_predict()`，修复空输入即 `AttributeError` 的崩溃；未注入元学习器时自动回退加权融合，保证开箱可用。

#### 3. 报告 case_id 改用文件内容哈希
- **问题**：API 分析路径误用"文件路径字符串的 md5"作为报告标识，同一 PCAP 每次上传路径不同就重复生成报告。
- **修复**：统一改用文件内容 SHA-256（与 Gradio 路径一致），实现"同一内容 PCAP ↔ 唯一报告"，重复分析覆盖旧版、不再产生一堆 HTML。

#### 4. 基线服务缺陷修复
- `utils/paths.py` 新增 `ensure_dir()`，修复基线服务导入即 ImportError；`delete_baseline` 改为 SQLite/JSON 双删容错。

#### 5. RAG 检索职责分离
- `rewrite_query` 回归单一职责（仅拆分"X 和 Y 的区别"类比较问句），术语缩写扩展移至检索循环按子查询独立进行，修复因职责混乱导致的测试失败。

### 测试与交付 ✅
- 完整测试：**148 passed / 19 skipped / 0 failed**（本轮开始时为 11 failed / 1 error，逐条原因级修复，未放宽断言）。
- 清理过期产物：删除 `build/`、`dist/`、`installer_output/`（约 1 GB）、54 个已入库的过期 report JSON，清空重复 uploads/reports。
- README 评测章节全面重写：全部数字对齐真实结果 JSON，并补齐 9 张实验图表。

---

## [2.1.0] - 2026-09-14

### 新增功能 ✨

#### 1. 历史记录报告管理完整重构
- **确认重新分析机制**：当历史记录的报告文件被删除时，显示确认区域询问用户是否重新执行PCAP分析
- **3阶段进度条**：确认重新分析后，分阶段显示进度（解析PCAP→生成报告→打开报告）
- **后台执行**：重新分析在后台独立执行完整PCAP分析（含AI研判），不影响Tab1的PCAP分析页面操作
- **自动更新**：分析完成后自动更新历史记录中的报告路径并打开报告

#### 2. PCAP文件持久化
- 分析完成后自动将PCAP文件复制到 `data/samples/analyzed/` 目录（时间戳前缀避免重名）
- 历史记录中保存持久化后的文件路径，确保重新分析时源文件一定存在
- 即使原始PCAP文件被移动或删除，仍可从持久化副本重新分析

#### 3. 旧记录PCAP文件自动搜索
- 对于没有 `file_path` 字段的旧记录（v2.0.0之前创建），自动在以下目录搜索同名PCAP文件：
  - `data/samples/`（含子目录）
  - 桌面目录
  - 下载目录
  - 项目根目录
- 搜索到后自动使用该文件重新分析，并更新历史记录中的 `file_path`
- 跳过 `.git`、`venv`、`node_modules` 等大目录，提升搜索效率

#### 4. 攻击类型知识库（5篇）
- 新增5篇攻击类型知识文档，已导入ChromaDB向量库：
  - SQL注入（sql_injection.md）
  - 勒索软件（ransomware.md）
  - 钓鱼攻击（phishing.md）
  - 内存马（memory_shell.md）
  - 中间人攻击（mitm.md）
- RAG安全问答助手可基于这些知识提供更精准的回答
- RAG评测结果：Recall@5=0.680

#### 5. 监督模型过拟合检测与优化
- **训练集/测试集对比**：输出训练集F1与测试集F1对比，直观检测过拟合程度
  - 训练集 F1: 0.9791
  - 测试集 F1: 0.9704
  - F1 差距: 0.0088（✅ 过拟合风险低）
- **5折交叉验证**：验证模型稳定性
  - 5折平均 F1: 0.9394 ± 0.0429
- **L2 正则化**：增加 `l2_regularization=1.0`，防止过拟合
- **早停机制**：增加 `early_stopping=True`，`validation_fraction=0.1`，`n_iter_no_change=10`，防止过拟合

### 问题修复 🐛

#### 1. 严重Bug：点击打开报告同时打开两个报告
- **根因**：Tab1和Tab2都定义了 `open_report_btn` 变量，Python中后面的定义覆盖前面的，导致Tab2的按钮被错误绑定了两个事件处理函数（`open_selected_report_ui` + `open_report_file_ui`）
- **修复**：Tab1按钮重命名为 `tab1_open_report_btn` / `tab1_open_report_dir_btn`，事件绑定分离
- **影响**：所有用户在历史记录页面点击「打开选中记录的报告」时都会同时打开选中记录的报告和最新报告

#### 2. 严重Bug：Gradio界面挂载失败显示404
- **根因**：Gradio 6.x 的 `Dropdown` 组件不支持 `placeholder` 参数，导致整个Gradio界面创建失败，UI挂载失败
- **修复**：移除下拉框的 `placeholder` 参数
- **影响**：所有用户打开桌面版时显示 `{"detail":"Not Found"}`，无法使用任何功能

#### 3. 进度条不显示
- **根因**：`regen_progress` 组件在事件绑定的outputs列表中出现了两次（一次设置value，一次设置visible），Gradio中同一组件出现两次导致更新异常
- **修复**：使用 `gr.update(value=..., visible=...)` 合并为一次更新，outputs列表去重
- **影响**：用户点击确认重新分析后看不到进度条，无法判断分析是否在执行

#### 4. `NameError: name 'actual_id' is not defined`
- **根因**：`confirm_regen_report_ui` 函数中使用了 `actual_id` 变量（用于日志输出），但该变量只在 `open_selected_report_ui` 函数中定义
- **修复**：在 `confirm_regen_report_ui` 函数中增加 `actual_id = h.get("id", record_id)` 定义
- **影响**：用户点击确认重新分析后立即报错，无法执行重新分析

### 功能优化 ⚡

#### 1. 确认区域UI优化
- 位置：从页面底部移到按钮紧下方，点击后立即可见，无需滚动
- 样式：增加标题 `### ⚠️ 报告已删除，是否重新分析？`，详细说明操作流程
- 布局：确认/取消按钮改为垂直排列，更易点击
- 提示：显示PCAP文件持久化状态（✅ 已持久化 / ⚠️ 原始路径）

#### 2. 未分析时下载报告提示
- 增加 `analysis_done` 状态变量，未进行任何分析时点击「下载取证型HTML报告」显示"还未进行任何分析"提示，不再显示虚假进度条

#### 3. 相同PCAP反复分析不生成重复报告
- 使用基于PCAP文件SHA256的固定文件名（格式 `PCAP-{sha256[:16]}`），相同PCAP反复分析覆盖旧报告，实现一一映射
- 避免 `data/reports/` 目录堆积大量重复报告文件

#### 4. .gitignore优化
- 增加临时报告文件忽略规则：`data/samples/report_*.json`
- 增加持久化PCAP目录忽略规则：`data/samples/analyzed/`
- 避免测试过程中生成的临时文件被误提交到Git

### 工程改进 🔧

- 历史记录增加 `file_path` 字段，保存PCAP文件完整路径，用于重新分析
- 所有新增功能均通过现有141个单元测试，无回归
- 代码注释完善，关键函数均有文档字符串说明参数和返回值

---

## [2.0.0] - 2026-09-11

### 主要更新
- P0-P3完整重构：四引擎集成检测 + LLM幻觉控制 + RAG混合检索 + 取证知识库 + DPAPI加密
- 监督模型为主引擎（HistGradientBoosting，F1=0.9487），UNSW-NB15专用模型Recall=0.9769
- 幻觉控制三件套：OutputValidator + ConfidenceCrossValidator + ReviewMarker
- RAG混合检索（BM25+向量）+ 轻量级重排序，Recall@5=0.36
- 取证报告五要素：事件时间线 + ATT&CK攻击链SVG图 + IOC列表 + 证据链 + 分析师备注
- Windows DPAPI加密存储API Key，图形化配置向导
- 141个单元测试全绿，平均分析耗时5.9s/文件，内存峰值23MB

---

## [1.0.0] - 2026-08-01

### 初始版本
- PCAP离线分析基础功能
- 规则引擎检测（SYN洪水/端口扫描/DNS隧道等）
- 基础HTML报告生成
- Gradio Web界面
- FastAPI后端

---

## 版本说明

- **主版本号**：不兼容的API修改
- **次版本号**：向下兼容的功能性新增
- **修订号**：向下兼容的问题修正

---

**项目地址**：https://github.com/LJY20030728/ai-network-security-analyzer
