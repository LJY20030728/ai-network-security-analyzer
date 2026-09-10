"""
HTML 取证型分析报告生成器
==========================
类数字取证调查报告（NIST 风格）：
- 报告头：案例号 / 生成时间 / 源文件 / SHA-256 / 规则版本（证据溯源）
- 流量概览：包数 / 流数 / 字节 / 时间范围 / 协议分布
- 检测结果：告警清单 + 证据链字段（detector / rule_threshold / time_window / z_score）
- 时序基线对照：基线画像 + 偏差数值
- AI 研判与处置建议
- 免责声明

设计：纯字符串模板 + 内联 CSS，零外部依赖，可离线打开
"""
import html as _html
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from loguru import logger


SEVERITY_COLORS = {
    "CRITICAL": "#B23A3C",
    "HIGH": "#D94F3D",
    "MEDIUM": "#E8A33D",
    "LOW": "#5B8DB8",
}


def _esc(v: Any) -> str:
    return _html.escape(str(v if v is not None else ""))


def _fmt_bytes(n: Any) -> str:
    try:
        n = float(n)
    except Exception:
        return _esc(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def build_html_report(analysis: Dict[str, Any],
                      evidence: Dict[str, Any],
                      ai_analysis: Optional[str] = None,
                      ai_traffic_summary: Optional[str] = None,
                      structured_report: Optional[Dict[str, Any]] = None,
                      case_id: Optional[str] = None) -> str:
    """
    生成完整取证型 HTML 报告
    :param analysis: analyze_packets 返回的报告（含 summary/flow_stats/protocol_distribution/anomaly_detection/baseline_profile）
    :param evidence: 证据元信息（source_file/source_sha256/analyzed_at/rule_version）
    :param ai_analysis: AI 威胁研判文本（可选）
    :param ai_traffic_summary: AI 流量概览文本（可选）
    :param case_id: 案例号（默认自动生成）
    """
    summary = analysis.get("summary", {})
    anomalies = analysis.get("anomaly_detection", {})
    baseline_profile = analysis.get("baseline_profile")
    protocol_dist = analysis.get("protocol_distribution", {})
    alerts = anomalies.get("alerts", [])

    # P2：检测引擎贡献分解（rules / baseline / ml 各自告警数与占比）
    engine_counter = {}
    for a in alerts:
        det = (a.get("detector") or "unknown").strip() or "unknown"
        engine_counter[det] = engine_counter.get(det, 0) + 1
    engine_rows = ""
    total_alerts = len(alerts)
    for det, cnt in sorted(engine_counter.items(), key=lambda x: -x[1]):
        pct = cnt / total_alerts * 100 if total_alerts else 0.0
        engine_rows += f"<tr><td style='font-size:13px;'>{_esc(det)}</td><td style='font-size:13px;'>{cnt}</td><td style='font-size:12px;color:#666;'>{pct:.0f}%</td></tr>"
    engine_block = ""
    if engine_rows:
        engine_block = f"""
    <div style="margin-top:12px;background:#fbfaf7;border:1px solid #e4e3dd;border-radius:8px;padding:12px;">
      <div style="font-size:13px;font-weight:600;margin-bottom:8px;">检测引擎贡献分解（纵深检测）</div>
      <table>
        <tr><th style="width:200px;">引擎</th><th style="width:100px;">告警数</th><th>占比</th></tr>
        {engine_rows}
      </table>
      <div style="color:#999;font-size:12px;margin-top:6px;">rules=静态规则（阈值经 UNSW/黄金样本调优）；baseline=EWMA 时序基线（MAD 鲁棒 z-score）；ml=孤立森林。多引擎联合告警体现纵深检测。</div>
    </div>"""

    cid = case_id or f"ASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 告警行
    alert_rows = []
    for a in alerts:
        color = SEVERITY_COLORS.get(a.get("severity", "MEDIUM"), "#888")
        detector = a.get("detector", "")
        tw = a.get("time_window", "") or "—"
        extra = ""
        if a.get("z_score") is not None:
            extra = f"<div style='color:#666;font-size:12px;'>z-score: {a['z_score']} | 值: {a.get('value')} | 基线中位数: {a.get('baseline_median')}</div>"
        elif a.get("rule_threshold"):
            rt = ", ".join(f"{k}={v}" for k, v in a["rule_threshold"].items())
            extra = f"<div style='color:#666;font-size:12px;'>触发阈值: {_esc(rt)}</div>"
        alert_rows.append(f"""
        <tr>
          <td><span style="display:inline-block;padding:2px 10px;border-radius:10px;color:#fff;background:{color};font-size:12px;font-weight:600;">{_esc(a.get('severity',''))}</span></td>
          <td style="font-size:13px;"><b>{_esc(a.get('type',''))}</b></td>
          <td style="font-size:12px;color:#444;">{_esc(a.get('description',''))}{extra}</td>
          <td style="font-size:12px;color:#666;">{_esc(detector)}<br/><span style="color:#999;">{_esc(tw)}</span></td>
        </tr>""")

    # 协议分布行
    proto_rows = ""
    total_pkts = summary.get("total_packets", 0) or 1
    for proto, cnt in protocol_dist.items():
        pct = cnt / total_pkts * 100
        proto_rows += f"""
        <tr><td style="font-size:13px;">{_esc(proto)}</td>
        <td style="font-size:13px;">{cnt}</td>
        <td style="font-size:12px;color:#666;">{pct:.1f}%</td></tr>"""

    # 基线画像行
    baseline_rows = ""
    if baseline_profile and baseline_profile.get("profile"):
        dim_labels = {
            "window_packets": "窗口包数", "window_bytes": "窗口字节数",
            "window_syn": "窗口SYN数", "window_dports": "窗口目的端口数",
        }
        for dim, p in baseline_profile["profile"].items():
            baseline_rows += f"""
            <tr><td style="font-size:13px;">{_esc(dim_labels.get(dim, dim))}</td>
            <td style="font-size:13px;">{p.get('median', '—')}</td>
            <td style="font-size:12px;color:#666;">{p.get('mad', '—')}</td></tr>"""

    # P0-4: 取证报告五要素（时间线+攻击链图+IOC列表+证据链+分析师备注）
    five_elements_block = _build_five_elements(analysis, alerts, cid)

    structured_block = ""
    if structured_report and structured_report.get("attacks"):
        att_rows = ""
        for a in structured_report["attacks"]:
            tp = "✅ 真实攻击" if a.get("is_true_positive") else "⚠️ 疑似误报"
            ttp = _esc(a.get("mitre_technique") or "—")
            conf = a.get("confidence", 0)
            actions = "；".join(a.get("recommended_actions", []) or ["—"])
            att_rows += f"""
            <tr>
              <td style="font-size:13px;"><b>{_esc(a.get('alert_type',''))}</b></td>
              <td style="font-size:12px;color:#666;">{ttp}</td>
              <td style="font-size:12px;">{tp} <span style="color:#666;">(conf {conf:.2f})</span></td>
              <td style="font-size:12px;color:#444;">{_esc(a.get('evidence',''))}</td>
              <td style="font-size:12px;color:#444;">{_esc(actions)}</td>
            </tr>"""
        structured_block = f"""
        <div class="sec">
          <h2>4. AI 结构化研判</h2>
          <div style="background:#f8f6f1;border:1px solid #e4e3dd;border-radius:8px;padding:14px;font-size:13px;line-height:1.7;">
            <b>总体研判：</b>{_esc(structured_report.get('overview',''))}<br/>
            <span style="color:#666;">整体判定：{'存在威胁' if structured_report.get('is_threat') else '未发现威胁'} | 置信度 {structured_report.get('overall_confidence', 0):.2f}</span>
          </div>
          <table style="margin-top:12px;">
            <tr><th style="width:110px;">告警</th><th style="width:70px;">MITRE</th><th style="width:110px;">判定</th><th>证据</th><th style="width:180px;">处置动作</th></tr>
            {att_rows}
          </table>
        </div>"""

    ai_block = ""
    if ai_analysis:
        ai_block += f"""
        <div class="sec">
          <h2>5. AI 威胁研判</h2>
          <div style="background:#f8f6f1;border:1px solid #e4e3dd;border-radius:8px;padding:14px;white-space:pre-wrap;font-size:13px;line-height:1.7;">{_esc(ai_analysis)}</div>
        </div>"""
    if ai_traffic_summary:
        ai_block += f"""
        <div class="sec">
          <h2>6. AI 流量概览</h2>
          <div style="background:#f8f6f1;border:1px solid #e4e3dd;border-radius:8px;padding:14px;white-space:pre-wrap;font-size:13px;line-height:1.7;">{_esc(ai_traffic_summary)}</div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>安全分析报告 {_esc(cid)}</title>
<style>
  body {{ font-family: 'Microsoft YaHei', 'PingFang SC', sans-serif; margin: 0; background: #F4F3EE; color: #1A1B1C; }}
  .wrap {{ max-width: 920px; margin: 0 auto; padding: 24px 16px 48px; }}
  .report-head {{ background: linear-gradient(135deg, #1A1B1C, #333); color: #fff; border-radius: 14px; padding: 24px; }}
  .report-head h1 {{ margin: 0 0 4px; font-size: 22px; }}
  .report-head .sub {{ color: #bbb; font-size: 13px; }}
  .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 8px 16px; margin-top: 14px; font-size: 12px; }}
  .meta .k {{ color: #999; }}
  .meta .v {{ color: #eee; word-break: break-all; }}
  .sec {{ margin-top: 22px; background: #fff; border: 1px solid #e4e3dd; border-radius: 12px; padding: 18px; }}
  .sec h2 {{ margin: 0 0 12px; font-size: 16px; color: #1A1B1C; border-left: 4px solid #8BC8EA; padding-left: 10px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; font-size: 12px; color: #6B7280; font-weight: 600; padding: 8px 6px; border-bottom: 2px solid #e4e3dd; }}
  td {{ padding: 8px 6px; border-bottom: 1px solid #eee; vertical-align: top; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; }}
  .card {{ flex: 1 1 150px; min-width: 120px; background: #f8f6f1; border-radius: 10px; padding: 12px; }}
  .card .n {{ font-size: 20px; font-weight: 700; }}
  .card .l {{ font-size: 12px; color: #6B7280; }}
  .disclaimer {{ margin-top: 24px; font-size: 11px; color: #999; line-height: 1.6; }}
</style>
</head>
<body>
<div class="wrap">

  <!-- 1. 报告头（证据溯源） -->
  <div class="report-head">
    <h1>🛡️ 网络安全分析报告</h1>
    <div class="sub">基于流行为规则检测 + EWMA 时序基线 + LLM 辅助研判</div>
    <div class="meta">
      <div><span class="k">案例号</span><br/><span class="v">{_esc(cid)}</span></div>
      <div><span class="k">报告生成</span><br/><span class="v">{_esc(gen_time)}</span></div>
      <div><span class="k">分析时间</span><br/><span class="v">{_esc(evidence.get('analyzed_at',''))}</span></div>
      <div><span class="k">规则版本</span><br/><span class="v">{_esc(evidence.get('rule_version',''))}</span></div>
      <div><span class="k">源文件</span><br/><span class="v">{_esc(evidence.get('source_file',''))}</span></div>
      <div><span class="k">源文件 SHA-256</span><br/><span class="v">{_esc(evidence.get('source_sha256',''))}</span></div>
    </div>
  </div>

  <!-- 2. 流量概览 -->
  <div class="sec">
    <h2>1. 流量概览</h2>
    <div class="cards">
      <div class="card"><div class="n">{summary.get('total_packets','—')}</div><div class="l">数据包总数</div></div>
      <div class="card"><div class="n">{summary.get('total_flows','—')}</div><div class="l">网络流数量</div></div>
      <div class="card"><div class="n">{_fmt_bytes(summary.get('total_bytes', 0))}</div><div class="l">总流量</div></div>
      <div class="card"><div class="n" style="font-size:15px;">{_esc(summary.get('time_range',{}).get('start','')[:19] if summary.get('time_range',{}).get('start') else '—')}</div><div class="l">时间范围起</div></div>
    </div>
    <table style="margin-top:12px;">
      <tr><th>协议</th><th>包数</th><th>占比</th></tr>
      {proto_rows}
    </table>
  </div>

  <!-- 3. 检测结果 + 证据链 -->
  <div class="sec">
    <h2>2. 异常检测结果（共 {len(alerts)} 条告警）</h2>
    <table>
      <tr><th style="width:80px;">级别</th><th style="width:200px;">告警类型</th><th>描述与证据链</th><th style="width:120px;">检测规则</th></tr>
      {''.join(alert_rows) if alert_rows else '<tr><td colspan="4" style="color:#999;font-size:13px;">未检测到异常</td></tr>'}
    </table>
    {engine_block}
  </div>

  <!-- 基线对照 -->
  <div class="sec">
    <h2>3. 时序基线对照（EWMA 学习-检测）</h2>
    <table>
      <tr><th>维度</th><th>基线中位数</th><th>有效 MAD</th></tr>
      {baseline_rows if baseline_rows else '<tr><td colspan="3" style="color:#999;font-size:13px;">未使用基线对照</td></tr>'}
    </table>
  </div>

  {five_elements_block}

  {structured_block}

  {ai_block}

  <div class="disclaimer">
    免责声明：本报告由自动化系统生成。检测基于启发式规则与统计基线，结果可能存在误报或漏报，需结合人工研判；
    AI 分析内容由大模型生成，仅供辅助参考。源文件哈希可用于取证溯源与完整性校验。
  </div>

</div>
</body>
</html>"""


def save_html_report(analysis: Dict[str, Any],
                     evidence: Dict[str, Any],
                     ai_analysis: Optional[str] = None,
                     ai_traffic_summary: Optional[str] = None,
                     structured_report: Optional[Dict[str, Any]] = None,
                     report_dir: str = "./data/reports") -> str:
    """生成并保存 HTML 报告，返回文件路径"""
    os.makedirs(report_dir, exist_ok=True)
    cid = f"ASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    filepath = os.path.join(report_dir, f"report_{cid}.html")
    html_content = build_html_report(analysis, evidence, ai_analysis, ai_traffic_summary,
                                     structured_report=structured_report, case_id=cid)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    # 返回绝对路径（Gradio DownloadButton / 历史记录打开报告需绝对路径）
    filepath = os.path.abspath(filepath)
    logger.info(f"HTML 报告已生成: {filepath}")
    return filepath


def _build_five_elements(analysis: Dict, alerts: List[Dict], cid: str) -> str:
    """P0-4: 构建取证报告五要素（时间线+攻击链图+IOC列表+证据链+分析师备注）"""
    if not alerts:
        return ""

    # 1. 事件时间线
    timeline_items = []
    for i, a in enumerate(alerts[:10]):
        tw = a.get("time_window", "") or f"窗口{i+1}"
        sev = a.get("severity", "MEDIUM")
        color = SEVERITY_COLORS.get(sev, "#888")
        timeline_items.append(f"""
        <div style='display:flex;gap:12px;margin-bottom:8px;'>
          <div style='width:10px;height:10px;border-radius:50%;background:{color};margin-top:5px;flex-shrink:0;'></div>
          <div style='flex:1;'>
            <div style='font-size:12px;color:#999;'>{_esc(tw)}</div>
            <div style='font-size:13px;'><b>{_esc(a.get('type',''))}</b> — {_esc(a.get('description','')[:80])}</div>
          </div>
        </div>""")

    # 2. ATT&CK 攻击链图（SVG）
    attack_chain_stages = ["侦察", "武器化", "投递", "利用", "安装", "命令控制", "行动"]
    detected_stages = set()
    for a in alerts:
        atype = a.get("type", "").upper()
        if "SCAN" in atype or "RECON" in atype:
            detected_stages.add(0)
        if "SYN" in atype or "FLOOD" in atype or "DOS" in atype:
            detected_stages.add(4)
        if "DNS" in atype or "TUNNEL" in atype:
            detected_stages.add(5)
        if "RST" in atype:
            detected_stages.add(4)
        if "LARGE" in atype or "BURST" in atype:
            detected_stages.add(6)

    chain_svg = "<svg width='100%' height='60' viewBox='0 0 700 60' xmlns='http://www.w3.org/2000/svg'>"
    for i, stage in enumerate(attack_chain_stages):
        x = i * 100
        color = "#EA6668" if i in detected_stages else "#E4E3DD"
        text_color = "#fff" if i in detected_stages else "#999"
        chain_svg += f"<rect x='{x}' y='15' width='80' height='30' rx='6' fill='{color}'/>"
        chain_svg += f"<text x='{x+40}' y='35' text-anchor='middle' fill='{text_color}' font-size='11'>{stage}</text>"
        if i < 6:
            chain_svg += f"<text x='{x+88}' y='35' fill='#ccc' font-size='14'>→</text>"
    chain_svg += "</svg>"

    # 3. IOC 列表
    ioc_items = []
    seen_iocs = set()
    for a in alerts:
        for key in ["src_ip", "dst_ip", "src_ips", "dst_ips"]:
            val = a.get(key)
            if val and isinstance(val, str) and val not in seen_iocs:
                seen_iocs.add(val)
                ioc_type = "IP" if "." in val or ":" in val else "域名"
                ioc_items.append(f"<tr><td style='font-size:13px;'>{ioc_type}</td><td style='font-size:13px;font-family:monospace;'>{_esc(val)}</td><td style='font-size:12px;color:#666;'>{_esc(a.get('type',''))}</td></tr>")
        if a.get("dst_port"):
            port = str(a["dst_port"])
            if port not in seen_iocs:
                seen_iocs.add(port)
                ioc_items.append(f"<tr><td style='font-size:13px;'>端口</td><td style='font-size:13px;font-family:monospace;'>{port}</td><td style='font-size:12px;color:#666;'>{_esc(a.get('type',''))}</td></tr>")

    # 4. 证据链
    evidence_items = []
    for i, a in enumerate(alerts[:5]):
        evidence_parts = []
        if a.get("rule_threshold"):
            evidence_parts.append(f"阈值: {', '.join(f'{k}={v}' for k,v in a['rule_threshold'].items())}")
        if a.get("z_score") is not None:
            evidence_parts.append(f"z-score={a['z_score']}")
        if a.get("value") is not None:
            evidence_parts.append(f"观测值={a['value']}")
        evidence_str = "；".join(evidence_parts) if evidence_parts else "基于流量统计特征"
        evidence_items.append(f"""
        <div style='padding:8px;background:#f8f6f1;border-radius:6px;margin-bottom:6px;'>
          <div style='font-size:13px;'><b>{i+1}. {_esc(a.get('type',''))}</b></div>
          <div style='font-size:12px;color:#666;margin-top:2px;'>证据: {_esc(evidence_str)}</div>
          <div style='font-size:11px;color:#999;margin-top:2px;'>检测引擎: {_esc(a.get('detector','unknown'))} | 时间窗口: {_esc(a.get('time_window','—'))}</div>
        </div>""")

    # 5. 分析师备注（预留填写区域）
    analyst_notes = """
    <div style='border:2px dashed #ccc;border-radius:8px;padding:16px;min-height:80px;'>
      <div style='font-size:12px;color:#999;margin-bottom:8px;'>📝 分析师备注（人工填写区域）</div>
      <div style='font-size:13px;color:#bbb;'>在此处填写人工研判结论、误报说明、进一步调查建议...</div>
    </div>"""

    return f"""
  <!-- P0-4: 取证报告五要素 -->
  <div class="sec">
    <h2>4. 取证分析五要素</h2>

    <div style='margin-bottom:18px;'>
      <div style='font-size:14px;font-weight:600;margin-bottom:10px;color:#1A1B1C;'>📅 事件时间线</div>
      {''.join(timeline_items) if timeline_items else '<div style="color:#999;font-size:13px;">无时间线数据</div>'}
    </div>

    <div style='margin-bottom:18px;'>
      <div style='font-size:14px;font-weight:600;margin-bottom:10px;color:#1A1B1C;'>🔗 ATT&CK 攻击链（红色=检测到）</div>
      {chain_svg}
      <div style='font-size:11px;color:#999;margin-top:4px;'>基于告警类型映射到 MITRE ATT&CK 杀伤链阶段</div>
    </div>

    <div style='margin-bottom:18px;'>
      <div style='font-size:14px;font-weight:600;margin-bottom:10px;color:#1A1B1C;'>🎯 IOC 失陷指标列表</div>
      <table>
        <tr><th style='width:80px;'>类型</th><th>值</th><th style='width:150px;'>关联告警</th></tr>
        {''.join(ioc_items) if ioc_items else '<tr><td colspan="3" style="color:#999;font-size:13px;">未提取到 IOC（匿名化数据无 IP/端口）</td></tr>'}
      </table>
    </div>

    <div style='margin-bottom:18px;'>
      <div style='font-size:14px;font-weight:600;margin-bottom:10px;color:#1A1B1C;'>🔍 证据链（告警→证据→引擎）</div>
      {''.join(evidence_items) if evidence_items else '<div style="color:#999;font-size:13px;">无证据链数据</div>'}
    </div>

    <div>
      <div style='font-size:14px;font-weight:600;margin-bottom:10px;color:#1A1B1C;'>📝 分析师备注</div>
      {analyst_notes}
    </div>
  </div>
"""
