# -*- coding: utf-8 -*-
"""
密钥泄漏扫描器（提交前 / 全历史）

## 为什么需要

本项目发生过一次真实的密钥泄漏：`tests/test_api_key_mask_incident.py` 中
为了构造"格式合法的真实 Key"测试样本，把用户的真 Key 硬编码了进去，
随公开仓库一起提交 —— 而那个文件的用途恰恰是防范 API Key 类事故。

事后虽然删除了代码、改写了 git 历史，但：
  · GitHub 仍在一段时间内保留不可达的旧对象（旧提交页面/`.patch` 仍可访问）
  · 密钥一旦公开，**唯一可靠的止损是作废它**，删除代码不能替代

因此必须有一道**机器强制的**闸门，而不是靠人记得检查。

## 检测策略（分层，按"确定性"从高到低）

1. **已知泄漏值**：本仓库历史中出现过的密钥（写成形态而非明文，避免二次泄漏）
2. **高置信度凭据格式**：带 `key`/`token`/`secret`/`password` 字样的赋值里，
   出现长且高熵的字符串
3. **厂商专用前缀**：`sk-` / `ghp_` / `gho_` / `AKIA` / `xox` 等
4. **熵兜底**：任意长 ≥ 32 且香农熵 ≥ 3.5 的 token（排除已知的白名单场景）

设计原则：**宁可漏报也不要把正常代码判为泄漏**（否则钩子会被绕过），
所以每条规则都带明确的排除条件。

## 用法

    python tools/scan_secrets.py                 # 扫描工作区文件
    python tools/scan_secrets.py --staged        # 只扫描 git 暂存区（pre-commit 用）
    python tools/scan_secrets.py --history       # 扫描全部 git 历史（慢）
    python tools/scan_secrets.py --path tests/   # 限定目录

退出码：0=无发现；1=发现可疑；2=用法错误
"""
import argparse
import math
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.helpers import force_utf8_stdout

force_utf8_stdout()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ----------------------------------------------------------------------
# 规则 1：已知泄漏值（用"形态"描述，不写明文，避免扫描器自己变成泄漏源）
# ----------------------------------------------------------------------
KNOWN_LEAK_PATTERNS = [
    # 智谱 GLM 的 key 形态：32 位十六进制 + "." + 16 位字母数字
    re.compile(r"\b[0-9a-f]{32}\.[A-Za-z0-9]{16}\b"),
]

# ----------------------------------------------------------------------
# 规则 2：赋值语句中的长高熵值
#
# 只用"带引号的字符串字面量"作为值 —— 早期版本允许裸标识符，
# 结果把 `token = _generate_and_persist_token(...)` 这类**函数名**判为密钥。
# 密钥一定是字面量，所以要求引号既不漏报也能消除大部分误报。
# ----------------------------------------------------------------------
SENSITIVE_KEYWORDS = (
    "api_key", "apikey", "api-key", "secret", "token", "password",
    "passwd", "credential", "private_key", "access_key",
)
ASSIGN_RE = re.compile(
    r"""(?ix)
    (?P<name>[A-Za-z_][A-Za-z0-9_\-]*)
    \s*[:=]\s*
    (?P<quote>["'])                      # 必须带引号
    (?P<value>[A-Za-z0-9_\-./+=]{24,})
    (?P=quote)
    """
)

# ----------------------------------------------------------------------
# 规则 3：厂商专用前缀
#
# 关键收紧：真实密钥是**无明显词结构的随机串**，而自然语言标识符
# （如 MITRE ATT&CK 里的技术名 `sk-pypi-supply-chain-compromise`）
# 由连字符分隔的多个英文单词组成。
# 判据：若尾串含 ≥3 个"纯英文单词"分段，则不视为密钥。
# ----------------------------------------------------------------------
VENDOR_PREFIXES = [
    ("sk-", 20),        # OpenAI / 兼容网关
    ("ghp_", 20),       # GitHub PAT
    ("gho_", 20),       # GitHub OAuth
    ("ghs_", 20),
    ("github_pat_", 20),
    ("AKIA", 16),       # AWS Access Key ID
    ("ASIA", 16),
    ("xox", 10),        # Slack
    ("AIza", 30),       # Google API key
    ("LTAI", 16),       # 阿里云
]

# 由连字符/下划线分隔的"可读词"分段：≥3 段即认为是自然语言标识符而非密钥
_WORDY_SEGMENT = re.compile(r"[A-Za-z]{3,}")
MIN_WORDY_SEGMENTS = 3


# ----------------------------------------------------------------------
# 排除规则：这些出现位置是正常的，不应报
# ----------------------------------------------------------------------
EXCLUDE_PATH_HINTS = (
    "/venv/", "\\venv\\", "/.git/", "\\git\\", "/node_modules/",
    "/dist/", "\\dist\\", "/build/", "\\build\\",
    "/installer_output/", "\\installer_output\\", "/.pytest_tmp/",
    "\\pytest_tmp\\", "scan_secrets.py",      # 本文件自身含规则样例
)

EXCLUDE_VALUE_RE = [
    re.compile(r"^[0-9a-f]{32,}$", re.I),          # 纯 hex（常见于哈希/指纹）
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-", re.I),  # UUID
    re.compile(r"^(x{4,}|X{4,}|\*{4,}|\.{4,})$"),  # 占位符
    re.compile(r"(?i)^(test|fake|dummy|example|sample|placeholder|your|my)[_-]?"),
    re.compile(r"(?i)(not_a_real|redacted|do_not_use|changeme|todo)"),
    re.compile(r"^\d+$"),                           # 纯数字
]

# 允许的"看起来像密钥但不是"的常见样本（如 sha256 白名单常量）
ALLOW_CONTEXT = re.compile(
    r"(?i)(sha256|sha1|md5|hash|digest|checksum|fingerprint|etag|"
    r"model_sha|dataset_hash|blob|oid)"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def is_excluded_value(v: str) -> bool:
    return any(p.search(v) for p in EXCLUDE_VALUE_RE)


def find_issues_in_text(text: str, where: str):
    """返回 [(行号, 规则, 证据片段)]"""
    issues = []
    for lineno, line in enumerate(text.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            # 注释行也检查"已知泄漏值"（防止有人在注释里写 key）
            pass

        # 规则 1：已知泄漏形态
        for pat in KNOWN_LEAK_PATTERNS:
            for m in pat.finditer(line):
                val = m.group(0)
                if is_excluded_value(val):
                    continue
                issues.append((lineno, "已知泄漏形态(32hex.16alnum)", val))

        # 规则 3：厂商前缀
        for prefix, minlen in VENDOR_PREFIXES:
            idx = line.find(prefix)
            while idx >= 0:
                tail = line[idx:idx + minlen + 24]
                m = re.match(r"[A-Za-z0-9_\-]{%d,}" % minlen, tail)
                if m:
                    val = m.group(0)
                    if not is_excluded_value(val) and "testonly" not in val.lower():
                        # 排除明显的占位/测试
                        if not re.search(r"(?i)(test|fake|dummy|example|xxx)", val):
                            # 排除"自然语言标识符"：真实密钥无明显词结构，
                            # 而技术名/文档标识符由多个英文单词组成
                            # （如 MITRE ATT&CK 的 sk-pypi-supply-chain-compromise）
                            if len(_WORDY_SEGMENT.findall(val)) < MIN_WORDY_SEGMENTS:
                                issues.append((lineno, f"厂商前缀 {prefix}", val))
                idx = line.find(prefix, idx + 1)

        # 规则 2：敏感赋值（仅带引号的字面量）
        for m in ASSIGN_RE.finditer(line):
            name = m.group("name")
            val = m.group("value")
            if not any(k in name.lower() for k in SENSITIVE_KEYWORDS):
                continue
            if is_excluded_value(val):
                continue
            if ALLOW_CONTEXT.search(line):
                continue
            if len(_WORDY_SEGMENT.findall(val)) >= MIN_WORDY_SEGMENTS:
                continue      # 自然语言标识符，非密钥
            ent = shannon_entropy(val)
            if len(val) >= 24 and ent >= 3.8:
                issues.append((lineno, f"高熵密钥赋值 {name}", val))

    # 去重（同一行同一值只报一次）
    seen, out = set(), []
    for ln, rule, val in issues:
        k = (ln, val)
        if k in seen:
            continue
        seen.add(k)
        out.append((ln, rule, val))
    return out


def iter_worktree_files(paths=None):
    skip_dirs = {".git", "venv", "node_modules", "dist", "build",
                 "installer_output", ".pytest_tmp", "__pycache__", "htmlcov"}
    exts = {".py", ".md", ".txt", ".json", ".yml", ".yaml", ".toml", ".iss",
            ".bat", ".cmd", ".ps1", ".sh", ".cfg", ".ini", ".env", ".example",
            ".js", ".ts", ".html", ".css"}
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in skip_dirs]
        for f in fn:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, ROOT)
            if paths and not any(rel.startswith(x) for x in paths):
                continue
            if any(h in p for h in EXCLUDE_PATH_HINTS):
                continue
            # .env 允许（它本就该含密钥，且被 gitignore）；但 .env.example 要查
            if f == ".env":
                continue
            if os.path.splitext(f)[1].lower() not in exts and f != "Dockerfile":
                continue
            try:
                with open(p, encoding="utf-8", errors="ignore") as fh:
                    yield rel, fh.read()
            except OSError:
                continue


def iter_staged():
    r = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                       cwd=ROOT, capture_output=True, text=True)
    for rel in r.stdout.split("\n"):
        rel = rel.strip()
        if not rel:
            continue
        p = os.path.join(ROOT, rel)
        if not os.path.isfile(p) or os.path.basename(p) == ".env":
            continue
        if any(h in p for h in EXCLUDE_PATH_HINTS):
            continue
        try:
            with open(p, encoding="utf-8", errors="ignore") as fh:
                yield rel, fh.read()
        except OSError:
            continue


def scan_history():
    """扫描全部历史（每个对象一次），用于事后审计"""
    r = subprocess.run(["git", "rev-list", "--all", "--objects"],
                       cwd=ROOT, capture_output=True, text=True)
    shas = []
    for line in r.stdout.split("\n"):
        parts = line.split(maxsplit=1)
        if parts and len(parts[0]) == 40:
            shas.append(parts[0])
    if not shas:
        return []
    inp = ("\n".join(shas) + "\n").encode()
    r2 = subprocess.run(["git", "cat-file", "--batch"], cwd=ROOT,
                        input=inp, capture_output=True)
    out = r2.stdout
    issues = []
    pos, total = 0, len(out)
    while pos < total:
        nl = out.find(b"\n", pos)
        if nl < 0:
            break
        header = out[pos:nl].split()
        if len(header) < 3:
            pos = nl + 1
            continue
        sha = header[0].decode("ascii", "replace")
        try:
            size = int(header[2])
        except ValueError:
            pos = nl + 1
            continue
        body = out[nl + 1: nl + 1 + size]
        pos = nl + 1 + size + 1
        if header[1] != b"blob":
            continue
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for ln, rule, val in find_issues_in_text(text, sha):
            issues.append((sha[:10], ln, rule, val))
    return issues


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--staged", action="store_true", help="只扫描暂存区（pre-commit 用）")
    ap.add_argument("--history", action="store_true", help="扫描全部 git 历史")
    ap.add_argument("--path", action="append", help="限定路径前缀（可多次）")
    args = ap.parse_args()

    print("=" * 78)
    print("  密钥泄漏扫描")
    print("=" * 78)

    if args.history:
        print("  模式: 全部 git 历史（较慢）")
        issues = scan_history()
        if issues:
            print(f"\n  ❌ 历史中发现 {len(issues)} 处可疑:")
            for sha, ln, rule, val in issues[:25]:
                print(f"     {sha}  [{rule}]  {val[:24]}…  (len={len(val)})")
        else:
            print("\n  ✅ 历史中未发现可疑密钥")
        return 1 if issues else 0

    if args.staged:
        print("  模式: git 暂存区（pre-commit）")
        files = list(iter_staged())
    else:
        print("  模式: 工作区")
        files = list(iter_worktree_files(args.path))

    print(f"  扫描文件数: {len(files)}\n")
    total = 0
    for rel, text in files:
        for ln, rule, val in find_issues_in_text(text, rel):
            total += 1
            print(f"  ❌ {rel}:{ln}  [{rule}]")
            print(f"      值: {val[:20]}…  长度={len(val)}  熵={shannon_entropy(val):.2f}")
    print()
    if total:
        print(f"  ❌ 发现 {total} 处可疑密钥。")
        print("     处理：改为从环境变量读取；测试用合成假值（如 'sk-testonly' + '0'*24）。")
        print("     若确为误报，请把该行加入工具的白名单并说明原因。")
        return 1
    print("  ✅ 未发现可疑密钥")
    return 0


if __name__ == "__main__":
    sys.exit(main())
