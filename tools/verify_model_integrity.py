# -*- coding: utf-8 -*-
"""
模型文件完整性校验（供 CI 与本地使用）

设计要点：**期望哈希从仓库自身的白名单常量读取**（src/ai/embeddings/bge_onnx.py
的 MODEL_SHA256），而不是在 CI 配置里再硬编码一份。否则一旦上游更新白名单，
CI 会继续用旧值校验，产生"CI 绿但应用拒绝加载"的分裂状态。

用法：
    python tools/verify_model_integrity.py            # 校验本地模型文件
    python tools/verify_model_integrity.py --require  # 缺失即失败（CI 用）

退出码：0=通过；1=校验失败/缺失（--require 时）
"""
import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 必须在任何 print 之前：本脚本输出中文与 ✅ 符号，而 Windows 控制台的 stdout
# 编码取自当前代码页（CI 重定向时为 cp1252，本地中文为 gbk）→ UnicodeEncodeError。
# 复用 helpers 的既有实现（tools/ 下 21 个脚本均如此），不新造轮子。
# 实测事故：GitHub Actions 的 Windows build job 在本脚本第一行中文标题处崩溃。
from src.utils.helpers import force_utf8_stdout  # noqa: E402

force_utf8_stdout()


def sha256_of(path: str, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.join("models", "bge-small-zh-v1.5"))
    ap.add_argument("--require", action="store_true",
                    help="文件缺失时视为失败（CI 使用；默认缺失只提示）")
    args = ap.parse_args()

    # 期望值来源：仓库自身的白名单常量（单一事实来源）
    from src.ai.embeddings.bge_onnx import MODEL_FILES, expected_sha256

    print("=" * 78)
    print(f"模型完整性校验 | 目录: {args.dir}")
    print("  期望哈希来自 src/ai/embeddings/bge_onnx.py 的 MODEL_SHA256（单一来源）")
    print("=" * 78)

    failures, missing = [], []
    for fn in MODEL_FILES:
        p = os.path.join(args.dir, fn)
        want = expected_sha256(fn)
        if not os.path.isfile(p):
            print(f"  [缺失] {fn}")
            missing.append(fn)
            continue
        if not want:
            print(f"  [跳过] {fn} —— 白名单中无期望值（不校验）")
            continue
        got = sha256_of(p)
        ok = got == want
        print(f"  [{'通过' if ok else '失败'}] {fn}")
        print(f"          期望 {want}")
        print(f"          实际 {got}")
        if not ok:
            failures.append(fn)

    print("-" * 78)
    if failures:
        print(f"❌ {len(failures)} 个文件哈希不匹配: {failures}")
        print("   可能原因：上游内容变更 / 传输损坏 / 被替换。")
        print("   处理：人工核对来源后更新 MODEL_SHA256，不要直接删除校验。")
        return 1
    if missing:
        if args.require:
            print(f"❌ 缺少必需文件: {missing}")
            return 1
        print(f"⚠️ 缺少文件（未要求必需）: {missing}")
        return 0
    print("✅ 全部模型文件哈希校验通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
