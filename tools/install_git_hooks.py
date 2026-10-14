# -*- coding: utf-8 -*-
"""
安装 git 钩子（密钥扫描）—— 跨平台实现

用法：
    python tools/install_git_hooks.py

为什么钩子文件放在 tools/ 而由脚本复制到 .git/hooks/：
    .git/ 不进版本控制，钩子必须先纳入仓库（tools/pre-commit），
    再由本脚本安装。这样其他人 clone 后跑一次即可生效。

为什么用 Python 而不是 .sh：
    Windows 上 `bash` 可能指向损坏的 WSL 发行版（实测报
    ERROR_FILE_NOT_FOUND），不可依赖。Python 已由项目 venv 保证存在。
"""
import os
import stat
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.helpers import force_utf8_stdout

force_utf8_stdout()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "tools", "pre-commit")


def git_hooks_dir():
    r = subprocess.run(["git", "rev-parse", "--git-dir"], cwd=ROOT,
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    gd = r.stdout.strip()
    if not os.path.isabs(gd):
        gd = os.path.join(ROOT, gd)
    return os.path.join(gd, "hooks")


def main():
    if not os.path.isfile(SRC):
        print(f"  ❌ 未找到 {SRC}")
        return 1

    hooks = git_hooks_dir()
    if not hooks:
        print("  ❌ 当前目录不是 git 仓库")
        return 1

    os.makedirs(hooks, exist_ok=True)
    dst = os.path.join(hooks, "pre-commit")

    with open(SRC, "r", encoding="utf-8", newline="\n") as f:
        content = f.read()
    with open(dst, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

    # 在类 Unix 上补可执行位；Windows 无此概念，忽略失败
    try:
        st = os.stat(dst)
        os.chmod(dst, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass

    print(f"  ✅ 已安装 pre-commit 钩子 -> {dst}")
    print(f"     大小: {os.path.getsize(dst)} B")

    # 自检：扫描工作区，确认扫描器可运行
    print("\n  自检：扫描工作区")
    r = subprocess.run([sys.executable, os.path.join("tools", "scan_secrets.py")],
                       cwd=ROOT, capture_output=True, text=True, timeout=600)
    tail = (r.stdout or "").strip().split("\n")
    for line in tail[-3:]:
        print(f"    {line.strip()}")

    print("\n  安装完成。此后每次 git commit 会自动扫描暂存区。")
    print("  确认为误报时可用：git commit --no-verify（并请更新扫描器白名单）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
