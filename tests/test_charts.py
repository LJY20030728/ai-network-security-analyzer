# -*- coding: utf-8 -*-
"""
图表渲染转义 + 基线名称校验 的回归测试

这两者是一组双层防御，针对同一个已确认漏洞：
基线名（用户可写、且被持久化到 SQLite）此前原样拼进 SVG，而该 SVG 由
`gr.HTML` 渲染——`gr.HTML` 没有 `sanitize_html`（与 `gr.Markdown` 不同），
且图表由 `demo.load(...)` 驱动，等于**每次页面加载都执行存储型 XSS**。

  · 渲染层：src/ui/charts.py 的 `_esc()` 兜住历史脏数据
  · 写入层：src/storage/baseline_name.py 让脏数据无法入库

本文件为新增测试，不修改任何既有测试。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage.baseline_name import (  # noqa: E402
    MAX_BASELINE_NAME_LEN,
    safe_baseline_name,
    validate_baseline_name,
)
from src.ui.charts import (  # noqa: E402
    _build_baseline_compare_svg,
    _build_baseline_profile_svg,
)

# 已确认可穿透 gr.HTML 的真实载荷形态
XSS_PAYLOAD = '</svg><img src=x onerror=alert(document.domain)><svg>'
PROFILE = {"window_packets": {"median": 10.0, "mad": 2.0},
           "window_bytes": {"median": 500.0, "mad": 50.0},
           "window_syn": {"median": 3.0, "mad": 1.0},
           "window_dports": {"median": 4.0, "mad": 1.0}}


# ----------------------------------------------------------------------
# 渲染层：转义
# ----------------------------------------------------------------------

def test_profile_svg_escapes_malicious_baseline_name():
    """核心回归：恶意基线名不得原文出现在 SVG 中。"""
    svg = _build_baseline_profile_svg(PROFILE, XSS_PAYLOAD)
    assert svg is not None
    assert XSS_PAYLOAD not in svg, "恶意载荷原样进入 SVG —— XSS 未修复"
    assert "<img" not in svg, "SVG 中出现了未转义的 <img> 标签"
    assert "onerror" not in svg or "&" in svg, "onerror 未被转义"
    # 转义后应为实体形式
    assert "&lt;/svg&gt;" in svg


def test_profile_svg_escapes_quotes_and_ampersand():
    """引号与 & 也必须转义（使插值在属性上下文同样安全）。"""
    svg = _build_baseline_profile_svg(PROFILE, '" onload="alert(1)" & <b>')
    assert svg is not None
    assert 'onload="alert(1)"' not in svg
    assert "&quot;" in svg
    assert "&amp;" in svg
    assert "&lt;b&gt;" in svg


def test_profile_svg_renders_normal_names_intact():
    """正常名称（中英文/数字/_-. 与空格）不应被破坏。"""
    for name in ["default", "my-network", "demo_baseline.v2", "我的家庭网络", "test net 01"]:
        svg = _build_baseline_profile_svg(PROFILE, name)
        assert svg is not None, f"{name} 渲染失败"
        assert name in svg, f"正常名称被破坏: {name}"


def test_profile_svg_handles_missing_name():
    """空/None 名称回退为 ?，且不抛异常。"""
    for bad in [None, ""]:
        svg = _build_baseline_profile_svg(PROFILE, bad)
        assert svg is not None
        assert "基线「?」" in svg


def test_profile_svg_rejects_bad_profile_without_raising():
    """非 dict / 空 profile 返回 None（保持原契约）。"""
    assert _build_baseline_profile_svg(None, "x") is None
    assert _build_baseline_profile_svg({}, "x") is None


def test_compare_svg_still_works_and_escapes_numeric_only():
    """对比图只插数值，应正常产出且不解析失败。"""
    series = [{"packets": 10}, {"packets": 30}, {"packets": 12}]
    svg = _build_baseline_compare_svg(series, {"window_sec": 10, "profile": PROFILE})
    assert svg is not None
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert "基线中位数" in svg


def test_compare_svg_empty_series_returns_none():
    assert _build_baseline_compare_svg([], {}) is None
    assert _build_baseline_compare_svg(None, {}) is None


# ----------------------------------------------------------------------
# 写入层：名称校验
# ----------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "default", "my-network", "demo_baseline", "base-attack",
    "我的网络", "测试 基线", "net.v2", "A" * MAX_BASELINE_NAME_LEN,
])
def test_validate_accepts_legal_names(name):
    assert validate_baseline_name(name) == name


def test_validate_strips_outer_whitespace_only():
    """只 strip 首尾，内部空白原样保留。"""
    assert validate_baseline_name("  my net  ") == "my net"
    assert validate_baseline_name("\tmy net\n") == "my net"


@pytest.mark.parametrize("name", [
    XSS_PAYLOAD,
    "<script>alert(1)</script>",
    'name" onload="x',
    "a<b>c",
    "semi;colon",
    "pipe|char",
    "back\\slash",
    "star*",
    "question?",
    "colon:name",
    "slash/name",
    "new\nline",
    "tab\tchar",
])
def test_validate_rejects_illegal_chars(name):
    with pytest.raises(ValueError):
        validate_baseline_name(name)


@pytest.mark.parametrize("name", ["CON", "con", "PRN", "AUX", "NUL", "COM1", "com9", "LPT1", "NUL.json"])
def test_validate_rejects_windows_reserved_names(name):
    with pytest.raises(ValueError):
        validate_baseline_name(name)


@pytest.mark.parametrize("name", [None, "", "   ", "\t\n"])
def test_validate_rejects_empty(name):
    with pytest.raises(ValueError):
        validate_baseline_name(name)


def test_validate_rejects_overlong():
    with pytest.raises(ValueError):
        validate_baseline_name("A" * (MAX_BASELINE_NAME_LEN + 1))


@pytest.mark.parametrize("name", ["name.", ".", ".."])
def test_validate_rejects_trailing_dot(name):
    """以点结尾会被 Windows 截断，必须拒绝。

    注意：以「空格」结尾不在此列——首尾空格由 strip 主动清理（设计行为），
    因此 "name " 是合法输入，会被规范化为 "name"。
    """
    with pytest.raises(ValueError):
        validate_baseline_name(name)


def test_trailing_space_is_stripped_not_rejected():
    assert validate_baseline_name("name ") == "name"


def test_validate_rejects_non_string():
    with pytest.raises(ValueError):
        validate_baseline_name(123)  # type: ignore[arg-type]


def test_safe_baseline_name_falls_back_instead_of_raising():
    """历史 JSON 导入路径用宽松版：非法则回退，不抛。"""
    assert safe_baseline_name(XSS_PAYLOAD, fallback="from-file") == "from-file"
    assert safe_baseline_name("good", fallback="x") == "good"
    assert safe_baseline_name(None, fallback="") == ""


# ----------------------------------------------------------------------
# 写入层：storage 单一入口
# ----------------------------------------------------------------------

@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """把 Database 单例临时指向 tmp 库（monkeypatch 自动还原）。"""
    from src.storage.database import Database

    db = Database()
    monkeypatch.setattr(db, "_db_path", str(tmp_path / "test.db"), raising=False)
    monkeypatch.setattr(db, "_local", __import__("threading").local(), raising=False)
    db._init_tables()
    return db


def test_save_baseline_rejects_illegal_name(temp_db):
    with pytest.raises(ValueError):
        temp_db.save_baseline(name=XSS_PAYLOAD, profile=PROFILE)


def test_save_baseline_accepts_and_roundtrips_legal_name(temp_db):
    assert temp_db.save_baseline(name="我的网络", profile=PROFILE) is True
    got = temp_db.get_baseline("我的网络")
    assert got is not None
    assert got["name"] == "我的网络"


def test_save_baseline_rejects_reserved_and_overlong(temp_db):
    with pytest.raises(ValueError):
        temp_db.save_baseline(name="CON", profile=PROFILE)
    with pytest.raises(ValueError):
        temp_db.save_baseline(name="A" * 200, profile=PROFILE)


# ----------------------------------------------------------------------
# 派生文件名：不得含路径分隔符，且与名称策略一致
# ----------------------------------------------------------------------

def test_baseline_path_is_sanitized_and_bounded():
    from src.ui.gradio_app import _baseline_path

    p = _baseline_path(XSS_PAYLOAD)
    base = os.path.basename(p)
    assert "/" not in base and "\\" not in base
    assert base.endswith(".json")
    assert "<" not in base and ">" not in base
    assert len(base) <= MAX_BASELINE_NAME_LEN + len(".json")


def test_baseline_path_falls_back_when_name_all_illegal():
    from src.ui.gradio_app import _baseline_path

    assert os.path.basename(_baseline_path("<<>>")).startswith("baseline")


# ----------------------------------------------------------------------
# API 路径参数：必须编译为真参数，而非字面花括号
# ----------------------------------------------------------------------

def test_forensic_routes_compile_params_not_literals():
    """回归：`{{analysis_id}}` 会被当成字面量 `{`，导致路由永远 404。

    这里直接断言编译后的正则不含字面花括号，并用 url_path_for 验证可解析。
    """
    from src.ui.gradio_app import app

    for route_name, path in (("forensic_related", "/api/forensic/related/{analysis_id}"),
                             ("forensic_iocs", "/api/forensic/iocs/{analysis_id}")):
        # 1) url_path_for 必须能把参数填进去（原来会解析失败）
        built = app.url_path_for(route_name, analysis_id="abc123")
        assert built == path.replace("{analysis_id}", "abc123"), built

        # 2) 编译后的正则中不得出现字面 `{`
        matched = [r for r in app.routes if getattr(r, "path", "") == path]
        assert matched, f"路由未注册: {path}"
        pattern = matched[0].path_regex.pattern
        assert r"\{" not in pattern, f"路径参数退化为字面花括号: {pattern}"


def test_forensic_routes_are_not_404():
    """端到端：带合法 token 请求应到达处理函数（不得为 404）。"""
    from fastapi.testclient import TestClient

    from config.settings import settings
    from src.ui.gradio_app import app

    token = settings.api_auth_token or "test-token"
    original = settings.api_auth_token
    settings.api_auth_token = token
    try:
        client = TestClient(app, raise_server_exceptions=False)
        headers = {"X-API-Token": token}
        for url in ("/api/forensic/related/nonexistent-id",
                    "/api/forensic/iocs/nonexistent-id"):
            resp = client.get(url, headers=headers)
            assert resp.status_code != 404, f"{url} 仍然 404（路由不可达）"
    finally:
        settings.api_auth_token = original


# ----------------------------------------------------------------------
# gradio 可选性：无 gradio 时模块仍须可导入（API 服务不能一起死）
# ----------------------------------------------------------------------

def test_module_imports_without_gradio():
    """回归：模块级 `gr.themes.Soft(...)` 会让无 gradio 环境导入即崩，
    连带 re-export 本模块的 src/api/main.py 一起失败。

    用子进程隔离：屏蔽 gradio 后导入 src.api.main，应成功且 API 路由齐全。
    """
    import subprocess

    script = (
        "import sys\n"
        "class B:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'gradio' or name.startswith('gradio.'):\n"
        "            raise ImportError('blocked')\n"
        "        return None\n"
        "sys.meta_path.insert(0, B())\n"
        "import src.api.main as m\n"
        "assert m.app is not None\n"
        "n = sum(1 for r in m.app.routes if getattr(r, 'path', '').startswith('/api/'))\n"
        "assert n >= 20, n\n"
        "print('GRADIO_BLOCKED_IMPORT_OK', n)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True, text=True, timeout=180,
        # 子进程会输出中文日志；Windows 默认 GBK 解码会炸，显式指定 UTF-8
        encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    assert result.returncode == 0, (
        f"无 gradio 时导入失败（stdout={result.stdout!r} stderr={result.stderr[-800:]!r}）"
    )
    # 日志会先写到 stdout，因此用包含判断而非前缀判断
    assert "GRADIO_BLOCKED_IMPORT_OK" in result.stdout, result.stdout
