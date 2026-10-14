# -*- coding: utf-8 -*-
"""
密钥扫描器的有效性测试（阳性 / 阴性对照）

## 为什么需要

"零误报"不等于"检测有效" —— 一个永远返回"未发现"的扫描器同样零误报。
本测试同时验证两个方向：
  · 阳性：已知形态的密钥**必须**被抓到（不能漏报）
  · 阴性：正常代码与数据**不能**被误报

## 关键实现约束

1. **样本文本在源码里不以完整密钥形态出现**，而是运行时拼接。
   否则扫描器会（正确地）把本文件判为泄漏 —— 因为源码里确实有密钥形态字符串。
   为什么不把本文件加白名单：那会让"测试文件里藏真密钥"成为免检通道。

2. **必须用 Python 直接写探针文件**，不要经 shell。
   经 shell 时引号会被再包一层，文件内容变成 `KEY = "deadbeef…`（多一个引号），
   扫描器匹配不上 —— 表现为"本该抓到的样本全部漏报"（实测踩过这个坑，
   当时误以为扫描器失效）。

3. 直接调用 `tools/scan_secrets.py` 的**函数**而非起子进程，
   避免每个用例 ~1s 的进程开销。

## 说明

所有"密钥"均为合成值，不含任何真实凭据。
"""
import io
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from src.utils.helpers import force_utf8_stdout  # noqa: E402

force_utf8_stdout()

import scan_secrets  # noqa: E402

PROBE_DIR = os.path.join(ROOT, "_scan_probe")


# ----------------------------------------------------------------------
# 阳性样本（合成值，运行时拼接）
# ----------------------------------------------------------------------
_R = "Qw8zR3mN7pL2vK9xT4bY6cD1fG5hJ0sA"
_G = "Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7Qr9St1Uv3Wx5Y"
_A = "3XJ7QZ2M5N8P1R4T"
_S = "Zx9Kq2Wm5Tn8Bv3Lp6Rj1Yd4Hf7Gs0Ac"

SHOULD_CATCH = [
    ("智谱形态 32hex.16alnum",
     'KEY = "' + "deadbeef" * 4 + "." + "A1B2C3D4E5F6G7H8" + '"'),
    ("OpenAI 形态 sk-",
     'api_key = "' + "sk-" + _R + '"'),
    ("GitHub PAT 形态",
     'token = "' + "ghp_" + _G + '"'),
    ("AWS AccessKey 形态",
     'aws_access_key = "' + "AKIA" + _A + '"'),
    ("广义高熵 secret",
     'client_secret = "' + _S + '"'),
    ("注释中的密钥也要抓",
     "# 旧 key: " + "0123456789abcdef" * 2 + "." + "ZZZZYYYYXXXXWWWW"),
]

SHOULD_NOT_CATCH = [
    ("测试用合成假值", 'FAKE_KEY = "sk-" + "testonly" + "0" * 24'),
    ("sha256 白名单常量",
     'MODEL_SHA256 = {"model.onnx": "69a0b846f4f116b5e6aabf9546ea6754d02264f3211a13a1bd69b31b8040749a"}'),
    ("UUID", 'trace_id = "550e8400-e29b-41d4-a716-446655440000"'),
    ("MITRE 技术名（自然语言标识符）", 'name = "sk-pypi-supply-chain-compromise"'),
    ("占位符", 'api_key = "your-api-key-here-xxxxxxxxxxxx"'),
    ("纯函数名赋值", "token = _generate_and_persist_token()"),
    ("短值", 'secret = "abc123"'),
    ("纯十六进制哈希", 'digest = "a1b2c3d4e5f60718293a4b5c6d7e8f90"'),
]


def scan_line(line: str, name: str = "probe.py"):
    """把一行文本写进探针文件，用扫描器的核心函数检查是否有发现。

    直接调用函数而非子进程：更快，且失败信息更可读。
    """
    os.makedirs(PROBE_DIR, exist_ok=True)
    p = os.path.join(PROBE_DIR, name)
    with io.open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(line + "\n")
    try:
        text = io.open(p, encoding="utf-8").read()
        return scan_secrets.find_issues_in_text(text, name)
    finally:
        try:
            os.remove(p)
        except OSError:
            pass


@pytest.fixture(scope="module", autouse=True)
def _cleanup_probe_dir():
    yield
    if os.path.isdir(PROBE_DIR):
        for f in os.listdir(PROBE_DIR):
            try:
                os.remove(os.path.join(PROBE_DIR, f))
            except OSError:
                pass
        try:
            os.rmdir(PROBE_DIR)
        except OSError:
            pass


# ----------------------------------------------------------------------
# 阳性：必须抓到
# ----------------------------------------------------------------------

@pytest.mark.parametrize("label,line", SHOULD_CATCH,
                         ids=[l for l, _ in SHOULD_CATCH])
def test_scanner_catches_known_secret_shapes(label, line):
    """已知形态的密钥必须被抓到 —— 防止扫描器退化为"永远不报"。"""
    issues = scan_line(line)
    assert issues, (
        f"漏报：扫描器未识别该密钥形态（{label}）\n"
        f"  样本: {line[:80]}\n"
        f"  这意味着扫描器对该类凭据无效。"
    )


# ----------------------------------------------------------------------
# 阴性：不能误报
# ----------------------------------------------------------------------

@pytest.mark.parametrize("label,line", SHOULD_NOT_CATCH,
                         ids=[l for l, _ in SHOULD_NOT_CATCH])
def test_scanner_ignores_benign_content(label, line):
    """正常代码/数据不得被误报 —— 误报会让钩子被 --no-verify 绕过。"""
    issues = scan_line(line)
    assert not issues, (
        f"误报：把正常内容判为密钥（{label}）\n"
        f"  样本: {line[:80]}\n"
        f"  命中: {issues}"
    )


# ----------------------------------------------------------------------
# 仓库自身的清洁度（当前工作区不应有可疑密钥）
# ----------------------------------------------------------------------

def test_current_worktree_is_clean():
    """当前工作区不应存在可疑密钥（此前的真实泄漏已清除）。"""
    found = []
    for rel, text in scan_secrets.iter_worktree_files():
        for ln, rule, val in scan_secrets.find_issues_in_text(text, rel):
            found.append((rel, ln, rule, val))
    assert not found, (
        "工作区发现可疑密钥：\n  "
        + "\n  ".join(f"{r}:{ln}  [{rule}]  {v[:16]}…" for r, ln, rule, v in found[:10])
    )
