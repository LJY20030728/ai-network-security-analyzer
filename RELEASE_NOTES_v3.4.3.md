## v3.4.3

### 修复：推理模型回答被截断（用户实测发现）

- **glm-4.5-air 是推理模型**：先输出思维链（`reasoning_content`，可占 2000+ token）再输出正式回答，
  而问答路径只给 `max_tokens=1024`，思维链就耗尽预算。
  - 实测同一问题：1024 → 等 24 秒换 34 字；2048 → 1409 字仍截断；4096 → 3866 字正常结束
  - 修复：所有 LLM 调用路径 `max_tokens` 统一提升到 4096
- **`reasoning_content` 完全未处理** → 现读取并记录其长度用于诊断
- **`finish_reason == "length"` 无检测** → 现截断时输出 warning（含各项 token 统计）
- **空内容被当正常结果缓存** → 现显式检测并返回明确错误且不缓存

### 修复：UDP/QUIC 攻击在 UI 运行时完全漏检（严重）

`TrafficAnalyzer` 有两条检测路径、规则数不一致，而 UI 走的是那条少的：

| 路径 | 调用方 | 规则数 |
|---|---|---|
| `analyze_packets()` → `_detect_anomalies()` | 脚本、CI | 11 条 |
| `analyze_stream()` | `analysis_service` → **UI 实际运行** | **5 条** |

UDP/QUIC 规则只加进了 `_detect_anomalies`，流式路径漏掉 6 条 ——
**运行时 UDP/QUIC 攻击完全检测不到**，而 CI 全绿（golden 集里没有任何 UDP/QUIC 样本）。

修复：补齐 6 条规则（UDP 洪水 / DNS 放大 / QUIC 连接风暴 / QUIC 长流 /
QUIC 初始包比例 / QUIC 未知版本）+ 补 3 个 golden 样本 + 新增路径一致性测试锁定该不变量。

### 修复：DNS 放大检测是死规则

解析器对 DNS **响应**包会**同时**填 `dns_query`（qd 段在响应中同样存在）与
`dns_response`（an 段 rdata），而规则写成 `if p.dns_query: ... elif p.dns_response:` ——
请求分支在前，响应一律被算作请求，`dns_resp_bytes` / `dns_resp_count` 恒为空，
**该规则在任何真实 PCAP 上都永不触发**。修复：两处（全量与流式）均改为响应优先判断。

### 修复：API Key 掩码事故（不可恢复的数据丢失）

UI 把掩码当作组件 `value` 填入输入框，用户点保存时掩码被原样提交并写入 DPAPI，
同时 `.env` 明文被清除 —— 真实 Key 永久丢失；且掩码含非 ASCII 字符，
使此后每次 LLM 调用都在 HTTP 头编码处抛错（表现为"AI 功能静默不可用"）。

现加三层防护：输入框真正留空（掩码绝不作为组件 value）、
主动拒绝掩码/被截断/非 ASCII 的 Key、仅当 DPAPI 回读一致时才清除 `.env` 明文。

### 修复：大流量告警源/目的写反 + 时间窗为空

`FlowExtractor` 用 `sorted([ep1, ep2])` 规范化双向流，`src_ip` 只是"字典序较小"的端点，
**与真实发包方向无关**。告警直接采用它，导致：

| 字段 | 修复前 | 修复后 |
|---|---|---|
| `src_ip` / `dst_ip` | `10.0.0.1` / `10.0.0.2`（反的） | `10.0.0.2` / `10.0.0.1` |
| `time_window` | 空字符串（报告显示 "—"） | 完整起止时间 |
| `description` | 方向写反 | 与真实包一致 |

对取证工具而言"源/目的写反"是实质性错误 —— 会让分析师追错方向。
现新增按真实包统计的主导方向字段并改用它。

### 其他

- 版本号五处统一为 3.4.3（含 `VersionInfoVersion`）
- 全仓库死代码清理：删除未接线的 `src/core/` 子系统、零引用模块，
  精简 Pydantic 模型（27 → 7）与废弃配置类
- 修复 5 条因**行尾注释**而静默失效的 `.gitignore` 规则（gitignore 不支持行尾注释）
- 修复打包失败根因：PyQt5 绑定与 PyInstaller 的 Qt5 hook 不兼容
- 测试规模 **415 passed**；`verify_golden.py` 攻击命中 **8/8**

### 安装说明

- **用户级安装，无需管理员权限**
- 若系统缺 WebView2 Runtime，安装程序会联网自动安装
- 核心检测（规则 / 时序基线 / 孤立森林 / 三引擎 Stacking 融合）**无需 API Key 即可运行**
- 仅「AI 威胁研判」与「安全问答」需要大模型 Key
