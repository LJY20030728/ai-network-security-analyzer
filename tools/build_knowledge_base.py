# -*- coding: utf-8 -*-
"""
P0-1 知识库扩容：MITRE ATT&CK 全量导入
========================================
1. 从 mitre-attack/attack-stix-data 官方仓库下载 enterprise-attack.json（~14MB）
2. 解析 attack-pattern（未撤销、含检测/缓解字段）
3. 按战术（Tactic）生成中文知识文档 → data/knowledge/docs/*.md
4. 产出统计落盘 data/knowledge/build_report.json（可审计）

生成的文档会被 src/knowledge/mitre_attck.get_all_knowledge() 扫描纳入 RAG。
"""
import io
import json
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
STIX_PATH = os.path.join(ROOT, "data", "knowledge", "mitre_attck", "enterprise-attack.json")
DOCS_DIR = os.path.join(ROOT, "data", "knowledge", "docs")
os.makedirs(os.path.dirname(STIX_PATH), exist_ok=True)
os.makedirs(DOCS_DIR, exist_ok=True)

TACTIC_CN = {
    "reconnaissance": "侦察 Reconnaissance", "resource-development": "资源开发 Resource Development",
    "initial-access": "初始访问 Initial Access", "execution": "执行 Execution",
    "persistence": "持久化 Persistence", "privilege-escalation": "权限提升 Privilege Escalation",
    "defense-evasion": "防御规避 Defense Evasion", "credential-access": "凭据访问 Credential Access",
    "discovery": "发现 Discovery", "lateral-movement": "横向移动 Lateral Movement",
    "collection": "收集 Collection", "command-and-control": "命令与控制 Command and Control",
    "exfiltration": "数据渗出 Exfiltration", "impact": "影响 Impact",
}


def download() -> bool:
    if os.path.exists(STIX_PATH) and os.path.getsize(STIX_PATH) > 5 * 1024 * 1024:
        print(f"[缓存] 使用已有 STIX 数据: {os.path.getsize(STIX_PATH)/1048576:.1f}MB")
        return True
    print(f"[下载] {STIX_URL}")
    try:
        req = urllib.request.Request(STIX_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120) as r, open(STIX_PATH, "wb") as f:
            f.write(r.read())
        print(f"[OK] 下载完成: {os.path.getsize(STIX_PATH)/1048576:.1f}MB")
        return True
    except Exception as e:
        print(f"[失败] 下载异常: {e}")
        return False


def parse_and_generate() -> dict:
    with open(STIX_PATH, encoding="utf-8") as f:
        data = json.load(f)

    techniques = []          # 有检测/缓解信息的 attack-pattern
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked"):
            continue
        ext_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
                ext_id = ref["external_id"]
                break
        if not ext_id:
            continue
        phases = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])
                  if p.get("kill_chain_name") == "mitre-attack"]
        if not phases:
            continue
        techniques.append({
            "id": ext_id,
            "name": obj.get("name", ""),
            "description": (obj.get("description") or "").replace("\n", " ").strip(),
            "detection": (obj.get("x_mitre_detection") or "").strip(),
            "mitigation": " ".join(
                m.get("description", "") for m in obj.get("mitigations", [])
                if m.get("description")).strip(),
            "platforms": ", ".join(obj.get("x_mitre_platforms", [])),
            "tactics": phases,
        })

    # 按战术分组生成文档
    by_tactic = {}
    for t in techniques:
        for phase in t["tactics"]:
            by_tactic.setdefault(phase, []).append(t)

    total_bytes = 0
    for phase, items in by_tactic.items():
        cn = TACTIC_CN.get(phase, phase)
        lines = [f"# MITRE ATT&CK 战术：{cn}", ""]
        lines.append(f"> 本页汇总 {len(items)} 个技术（Technique）的流量特征、检测方法与缓解措施，"
                     f"供安全分析师在事件研判与处置时参考。")
        for t in sorted(items, key=lambda x: x["id"]):
            lines.append(f"## {t['id']} {t['name']}")
            if t["platforms"]:
                lines.append(f"- **适用平台**：{t['platforms']}")
            lines.append(f"- **描述**：{t['description'][:800]}")
            if t["detection"]:
                lines.append(f"- **检测方法**：{t['detection'][:600]}")
            if t["mitigation"]:
                lines.append(f"- **缓解措施**：{t['mitigation'][:400]}")
            lines.append("")
        fname = os.path.join(DOCS_DIR, f"mitre_attck_{phase}.md")
        content = "\n".join(lines)
        with io.open(fname, "w", encoding="utf-8") as f:
            f.write(content)
        total_bytes += len(content.encode("utf-8"))
        print(f"[生成] {os.path.basename(fname)}: {len(items)} 技术, {len(content)//1024}KB")

    report = {
        "source": STIX_URL,
        "techniques_total": len(techniques),
        "tactics": {k: len(v) for k, v in by_tactic.items()},
        "docs_generated": len(by_tactic),
        "docs_bytes": total_bytes,
        "generated_at": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
    }
    with io.open(os.path.join(ROOT, "data", "knowledge", "build_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return report


if __name__ == "__main__":
    if not download():
        sys.exit(1)
    rep = parse_and_generate()
    print(f"\n===== 知识库扩容完成 =====")
    print(f"技术总数: {rep['techniques_total']}")
    print(f"生成文档: {rep['docs_generated']} 个, 总大小 {rep['docs_bytes']/1048576:.2f}MB")
