# -*- coding: utf-8 -*-
"""
版本号一致性 的回归测试

背景：修复前版本号四处漂移——`config/settings.py` 与 `pyproject.toml` 停在
3.3.0，而 `installer.iss` 已是 3.4.2，Dockerfile 更是 2.1.0、compose 镜像标签
1.1.0。由于取证报告头的 `rule_version` 取自 `settings.version`，
3.4.2 生成的报告会被标注为 3.3.0 —— 证据溯源直接失真。

本测试把「版本单一来源」固化为契约：所有**活跃的版本声明**必须一致。
（CHANGELOG 与 README 中的历史版本号属更新日志，不在校验范围内。）

本文件为新增测试，不修改任何既有测试。
"""
import io
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _read(rel):
    return io.open(os.path.join(ROOT, rel), encoding="utf-8").read().replace("\r", "")


def _settings_versions():
    """返回 config/settings.py 中所有 version 声明值"""
    import ast
    src = _read("config/settings.py")
    out = {}
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, ast.AnnAssign) \
                        and getattr(sub.target, "id", "") == "version":
                    out[node.name] = ast.literal_eval(sub.value)
    return out


def test_settings_declarations_agree():
    """ProjectSettings 与 Settings 的 version 必须一致。"""
    vs = _settings_versions()
    assert vs, "未在 config/settings.py 找到 version 声明"
    assert len(set(vs.values())) == 1, f"settings.py 内部版本不一致: {vs}"
    for name, v in vs.items():
        assert SEMVER.match(v), f"{name}.version 不是 semver: {v!r}"


def test_runtime_settings_version_matches_declarations():
    """运行时 settings.version 必须等于声明值（防止被其他配置覆盖）。"""
    from config.settings import settings
    declared = set(_settings_versions().values())
    assert settings.version in declared, (
        f"运行时 settings.version={settings.version!r} 与声明 {declared} 不一致")


def test_pyproject_matches_settings():
    src = _read("pyproject.toml")
    m = re.search(r'^version\s*=\s*"([^"]+)"', src, re.M)
    assert m, "pyproject.toml 缺少 version"
    assert m.group(1) == _settings_versions()["Settings"], (
        f"pyproject.toml={m.group(1)} 与 settings={_settings_versions()['Settings']} 不一致")


def test_installer_matches_settings():
    src = _read("installer.iss")
    want = _settings_versions()["Settings"]
    for key in ("AppVersion", "AppVerName", "OutputBaseFilename", "VersionInfoVersion"):
        m = re.search(rf"^{key}\s*=\s*(.+)$", src, re.M)
        assert m, f"installer.iss 缺少 {key}"
        line = m.group(1)
        # VersionInfoVersion 形如 3.4.2.0，取前三段比较
        found = re.search(r"(\d+\.\d+\.\d+)", line)
        assert found, f"{key} 未找到版本号: {line!r}"
        assert found.group(1) == want, (
            f"installer.iss {key}={found.group(1)} 与 settings={want} 不一致")


def test_dockerfile_matches_settings():
    src = _read("Dockerfile")
    want = _settings_versions()["Settings"]
    versions = set(re.findall(r'version="(\d+\.\d+\.\d+)"', src))
    versions |= set(re.findall(r"docker build -t ai-nsa:(\d+\.\d+\.\d+)", src))
    assert versions, "Dockerfile 未声明版本"
    assert versions == {want}, f"Dockerfile 版本 {versions} 与 settings={want} 不一致"


def test_compose_image_tag_matches_settings():
    src = _read("docker-compose.yml")
    want = _settings_versions()["Settings"]
    tags = set(re.findall(r"image:\s*ai-nsa:(\d+\.\d+\.\d+)", src))
    assert tags, "docker-compose.yml 未声明镜像标签版本"
    assert tags == {want}, f"compose 镜像标签 {tags} 与 settings={want} 不一致"


def test_report_rule_version_comes_from_settings():
    """报告头 rule_version 必须取自 settings.version（单一来源）。"""
    import inspect
    from src.report import html_report
    from src.services import analysis_service
    hs = inspect.getsource(html_report)
    asrc = inspect.getsource(analysis_service)
    assert "settings.version" in hs, "报告生成未使用 settings.version"
    assert "settings.version" in asrc, "证据元信息未使用 settings.version"


def test_changelog_has_entry_for_current_version():
    """当前版本必须在 CHANGELOG 中有条目（否则发布记录与版本号脱节）。"""
    want = _settings_versions()["Settings"]
    src = _read("CHANGELOG.md")
    assert f"[{want}]" in src, f"CHANGELOG 缺少 [{want}] 条目"
