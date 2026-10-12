# -*- coding: utf-8 -*-
"""
关键资源必须在版本控制中（防系统性复发）

## 它防的是什么

本项目曾出现一类**系统性缺陷**，且反复发作：

  `.gitignore` 把**产品资源**当成**用户数据**忽略
    → 开发机磁盘上有这些文件，本地测试全绿
    → CI 的干净 checkout 里没有 → CI 全红
    → 但没人注意到（徽章还写着 passed）

同类的具体事件：
  · `data/baselines/default_baseline.json` 被忽略 → test_default_baseline 5 项必失败
  · `.gitignore` 的 `_*.py` 误匹配**所有包**的 `__init__.py` → 15 个包结构文件从未入库
  · `.gitignore` 行尾注释使 5 条规则静默失效

**共同根因**：代码依赖与版本控制之间没有任何机制保证一致，
全靠人记住"这个文件要提交"。人会忘，机器不会。

## 本文件的作用

用一张**显式登记表**把"测试与打包依赖哪些资源"写死，
逐项断言：存在 + 被 git 跟踪（在 git checkout 中）。

一旦有人再加一条 `.gitignore` 规则误伤产品资源，这个测试立刻变红，
并给出具体是哪个文件、谁在用它、为什么需要它。

（说明：`.gitignore` 对**已跟踪**文件无效，所以真正的值是断言
 `git ls-files` 包含它 —— 它能抓住"当初就没提交"和"被 git rm --cached 掉"两种情况。）
"""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ----------------------------------------------------------------------
# 资源登记表：路径 → (用途, 依赖方)
#
# 新增"测试或打包依赖的资源"时，必须同时登记到这里 ——
# 登记本身就是一次显式确认："这个文件必须随仓库分发"。
# ----------------------------------------------------------------------
REQUIRED_ASSETS = {
    "data/baselines/default_baseline.json": (
        "预置时序基线（产品资源，非用户数据）",
        "tests/test_default_baseline.py、TrafficAnalyzer 启动自动加载",
    ),
    "data/samples/golden/normal.pcap": (
        "黄金样本：正常流量基准",
        "tests/test_streaming.py、tools/verify_golden.py",
    ),
    "data/samples/golden/synflood.pcap": (
        "黄金样本：SYN 洪水",
        "tests/test_streaming.py、tools/verify_golden.py",
    ),
    "data/samples/golden/portscan.pcap": (
        "黄金样本：端口扫描",
        "tests/test_streaming.py、tools/verify_golden.py",
    ),
    "data/samples/golden/udpflood.pcap": (
        "黄金样本：UDP 洪水（v3.4.3 新增，补齐 UDP/QUIC 覆盖盲区）",
        "tests/test_streaming.py、tools/verify_golden.py",
    ),
    "data/samples/golden/dnsamp.pcap": (
        "黄金样本：DNS 放大（v3.4.3 新增）",
        "tests/test_streaming.py、tools/verify_golden.py",
    ),
    "data/samples/golden/quicflood.pcap": (
        "黄金样本：QUIC 连接风暴（v3.4.3 新增）",
        "tests/test_streaming.py、tools/verify_golden.py",
    ),
    "models/stacking_meta_learner.joblib": (
        "三引擎 Stacking 元学习器（13 维特征）",
        "src/analysis/stacking_fusion.py、打包流程",
    ),
    "src/ai/embeddings/bge_onnx.py": (
        "BGE 模型 sha256 白名单的唯一来源",
        "tools/verify_model_integrity.py、CI 校验步骤",
    ),
}

# 各包的结构文件：曾被 `.gitignore` 的 `_*.py` 误伤，导致 clone 后包结构缺失
PACKAGE_MARKERS = [
    "config/__init__.py",
    "src/__init__.py",
    "src/ai/__init__.py",
    "src/ai/embeddings/__init__.py",
    "src/analysis/__init__.py",
    "src/api/__init__.py",
    "src/capture/__init__.py",
    "src/knowledge/__init__.py",
    "src/report/__init__.py",
    "src/security/__init__.py",
    "src/services/__init__.py",
    "src/storage/__init__.py",
    "src/ui/__init__.py",
    "src/utils/__init__.py",
]


def _tracked():
    """git 跟踪的文件集合（相对路径，正斜杠）。非 git 环境返回 None。"""
    try:
        r = subprocess.run(["git", "ls-files"], cwd=ROOT,
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return None
        return {l.strip().replace("\\", "/") for l in r.stdout.split("\n") if l.strip()}
    except Exception:
        return None


TRACKED = _tracked()


# ----------------------------------------------------------------------
# 1) 资源存在（本地与 CI 共同要求）
# ----------------------------------------------------------------------

@pytest.mark.parametrize("rel", sorted(REQUIRED_ASSETS))
def test_required_asset_exists(rel):
    p = os.path.join(ROOT, rel)
    purpose, consumers = REQUIRED_ASSETS[rel]
    assert os.path.exists(p), (
        f"关键资源缺失: {rel}\n"
        f"  用途  : {purpose}\n"
        f"  依赖方: {consumers}\n"
        f"  处理  : 该文件必须随仓库分发（见本文件 REQUIREd_ASSETS 登记表）"
    )


@pytest.mark.parametrize("rel", sorted(REQUIRED_ASSETS))
def test_required_asset_is_git_tracked(rel):
    """★ 核心断言：资源必须在 git 里 —— 否则 CI 的干净 checkout 里不存在。

    `.gitignore` 对已跟踪文件无效，所以这里断言 git ls-files 包含它，
    能同时抓住「当初就没提交」与「被 git rm --cached 移除」两种退化。
    """
    if TRACKED is None:
        pytest.skip("非 git 环境，无法校验跟踪状态")
    purpose, consumers = REQUIRED_ASSETS[rel]
    assert rel in TRACKED, (
        f"关键资源未被 git 跟踪: {rel}\n"
        f"  用途  : {purpose}\n"
        f"  依赖方: {consumers}\n"
        f"  后果  : 开发机本地测试通过，但 CI 的干净 checkout 里该文件不存在\n"
        f"          → CI 必然变红，而本地看不出问题（本项目已多次发生）\n"
        f"  处理  : git add -f {rel}，并把误伤它的 .gitignore 规则改掉"
    )


# ----------------------------------------------------------------------
# 2) 包结构文件（`_*.py` 误伤事件的回归锁）
# ----------------------------------------------------------------------

@pytest.mark.parametrize("rel", PACKAGE_MARKERS)
def test_package_marker_is_tracked(rel):
    if TRACKED is None:
        pytest.skip("非 git 环境")
    assert rel in TRACKED, (
        f"包结构文件未被跟踪: {rel}\n"
        f"  后果: clone 后包结构缺失，import 可能失败\n"
        f"  历史: 曾被 .gitignore 的 `_*.py`（无前导斜杠）误匹配，15 个此类文件从未入库"
    )


# ----------------------------------------------------------------------
# 3) .gitignore 规则健康度（行尾注释会静默失效）
# ----------------------------------------------------------------------

def _gitignore_effective_lines():
    path = os.path.join(ROOT, ".gitignore")
    out = []
    for i, line in enumerate(open(path, encoding="utf-8").read().split("\n"), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append((i, s))
    return out


def test_gitignore_has_no_inline_comments():
    """`.gitignore` 不支持行尾注释 —— `pattern  # 注释` 会被整体当作模式而静默失效。

    本项目曾因此有 5 条规则从未生效（gradio/、*.runtimeconfig.json 等）。
    """
    bad = []
    for i, line in _gitignore_effective_lines():
        # 允许以 # 开头的整行注释；此处找"非注释行里出现 #"
        if "#" in line:
            bad.append((i, line))
    assert not bad, (
        "`.gitignore` 存在行尾注释，该规则会静默失效：\n"
        + "\n".join(f"  行 {i}: {l}" for i, l in bad)
        + "\n  处理：把注释移到独占一行"
    )


def test_gitignore_does_not_ignore_required_assets():
    """登记表中的资源不得被 `.gitignore` **实际**忽略。

    为什么用 `git check-ignore` 而不是自己写 fnmatch：
      本测试初版用 fnmatch 复刻忽略逻辑，**漏掉了否定规则（`!pattern`）**，
      于是把已由 `!data/baselines/default_baseline.json` 正确放行的文件
      误报为"被忽略"。gitignore 语义（顺序、否定、目录规则、`**`）足够复杂，
      重新实现只会产生假警报 —— 直接问 git 自己才是权威判定。

    注：`.gitignore` 对**已跟踪**文件无效，所以"被忽略"本身不致命；
    但它是"新文件加入时踩坑"的引信，故仍要求登记表与忽略规则互不冲突。
    """
    if TRACKED is None:
        pytest.skip("非 git 环境，无法调用 git check-ignore")

    ignored = []
    for rel in list(REQUIRED_ASSETS) + PACKAGE_MARKERS:
        try:
            r = subprocess.run(["git", "check-ignore", "-q", rel], cwd=ROOT,
                               capture_output=True, timeout=30)
            if r.returncode == 0:
                # 取具体命中的规则（便于定位）
                r2 = subprocess.run(["git", "check-ignore", "-v", rel], cwd=ROOT,
                                    capture_output=True, text=True, timeout=30)
                rule = (r2.stdout or "").strip().split("\t")[1:2]
                ignored.append(f"{rel}  <=  {rule[0] if rule else '?'}")
        except Exception:
            continue

    assert not ignored, (
        "以下关键资源被 .gitignore **实际**忽略（新文件加入时会踩坑）：\n  "
        + "\n  ".join(ignored)
        + "\n  处理：加否定规则（如 `!path/to/file`）或收紧原规则"
    )
