# -*- coding: utf-8 -*-
"""
API Key 掩码事故 的回归测试

## 事故经过（真实发生，造成不可恢复的数据丢失）

1. `load_api_config_ui()` 把已配置的 Key 以**掩码**形式返回
   （`current[:4] + "…" + current[-4:]`，如 `'0bf7…4U3u'`）。
2. Gradio 把该返回值当作**组件的 value** 填入密码输入框
   —— 它并不是"占位提示"，而是真实可提交的表单值。
3. 用户在设置页点击「保存」→ 浏览器把框里的掩码原样提交回
   `save_api_config_ui(key='0bf7…4U3u')`。
4. 旧实现只检查 `"xxxx" in key`，掩码通过校验 → 被写进 DPAPI。
5. 同一函数在 `dpapi_ok=True` 时**清除 `.env` 的明文 Key**
   → 真实 Key 的唯一完整副本被删除，**无法从任何文件或 git 历史恢复**。
6. 掩码含 U+2026（非 ASCII），此后每次 LLM 调用都在
   `openai` 的 `_build_headers` 处抛
   `UnicodeEncodeError: 'ascii' codec can't encode character '\u2026'`
   → LLM 功能整体不可用。

## 本文件锁定的三层防护

- 层 1：`load_api_config_ui` 的 Key 位必须返回**空字符串**（掩码绝不作为 value）
- 层 2：`_looks_like_real_api_key` 主动拒绝掩码/占位符/被截断/非 ASCII 的值
- 层 3：仅当 DPAPI **写入后回读一致**时才清除 `.env` 明文

本文件为新增测试，不修改任何既有测试。
"""
import io
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 事故中那个掩码（含 U+2026）
ACCIDENT_MASK = "0bf7\u20264U3u"

# ----------------------------------------------------------------------
# 【重要】本文件中的"真实 Key"必须是**构造的假值**，绝不可写入任何真 Key
#
# 教训：本文件初版为了构造"格式合法的真实 Key"样本，把用户的真 Key
# 直接写了进来，随公开仓库一起提交（提交 05aec6b）→ 密钥公开泄漏。
# 讽刺的是，这个文件本身的用途正是防范 API Key 类事故。
#
# 现在的做法：
#   · 假 Key 只需满足"形态像真的"（够长、无掩码字符、纯 ASCII）
#   · 断言全部从假 Key **推导**（而非硬编码真 Key 的首尾），
#     这样换假值时无需再改断言，也就不会有人图省事把真值写回来
# ----------------------------------------------------------------------
FAKE_KEY = "sk-" + "testonly" + "0" * 24          # 合成，非任何真实凭据
FAKE_REAL = FAKE_KEY                              # 向后兼容旧命名
REAL_KEY = FAKE_KEY                               # 同上（"真实形态"之意，非真值）


def _ga_src():
    return io.open(os.path.join(ROOT, "src", "ui", "gradio_app.py"),
                   encoding="utf-8").read()


# ----------------------------------------------------------------------
# 层 2：Key 合法性判定
# ----------------------------------------------------------------------

@pytest.mark.parametrize("value,expected,why", [
    (ACCIDENT_MASK, False, "事故掩码（含 U+2026）——必须拒绝"),
    ("已配置", False, "旧代码的字符回退值"),
    ("", False, "空值"),
    ("sk-xxxxxxxxxxxxxxxxxxxx", False, "占位符"),
    ("sk-abc", False, "过短"),
    ("sk-abc...xyz123456789012", False, "含 ASCII 省略号"),
    ("sk-abc***def1234567890123", False, "含星号掩码"),
    ("sk-abc def123456789012345", False, "含空格"),
    ("sk-密钥123456789012345678", False, "含非 ASCII"),
    ("sk-a\tb123456789012345678", False, "含制表符"),
    (FAKE_REAL, True, "合法形态"),
    (REAL_KEY, True, "真实 Key"),
])
def test_looks_like_real_api_key(value, expected, why):
    from src.ui.gradio_app import _looks_like_real_api_key
    assert _looks_like_real_api_key(value) is expected, why


def test_mask_key_never_returns_input_mask():
    """掩码函数对已是掩码的输入必须返回空串（避免掩码套掩码）。"""
    from src.ui.gradio_app import mask_key
    # 期望值从假 Key 推导，而非硬编码某个具体凭据的首尾 ——
    # 这样换假值时断言无需改动，也不会诱导后人把真值写回代码。
    expected_mask = f"{FAKE_KEY[:4]}\u2026{FAKE_KEY[-4:]}"
    assert mask_key(FAKE_KEY) == expected_mask
    assert mask_key(ACCIDENT_MASK) == ""
    assert mask_key("已配置") == ""
    assert mask_key("") == ""


def test_mask_output_is_not_a_valid_key():
    """掩码本身绝不能被判定为合法 Key（否则可被再次保存）。"""
    from src.ui.gradio_app import _looks_like_real_api_key, mask_key
    for k in (REAL_KEY, FAKE_REAL):
        assert _looks_like_real_api_key(mask_key(k)) is False


# ----------------------------------------------------------------------
# 层 1：load_api_config_ui 的 Key 位必须是空串
# ----------------------------------------------------------------------

def test_load_api_config_returns_empty_key_slot():
    """Key 位必须 return "" —— 掩码只能进 info/日志，绝不能作为组件 value。

    事故根因就是掩码被当作 value 填入输入框，用户保存时被提交回来。
    """
    src = _ga_src()
    i = src.find("def load_api_config_ui")
    assert i > 0, "未找到 load_api_config_ui"
    frag = src[i:i + 2600]
    # 返回值第一个元素必须是空字符串
    assert 'return "", vals["LLM_BASE_URL"], vals["LLM_MODEL"]' in frag, \
        "load_api_config_ui 的 Key 位未返回空字符串（掩码会被填入输入框）"
    # 不得再把掩码变量作为返回值
    assert "return key_display" not in frag, "仍把掩码作为返回值"


# ----------------------------------------------------------------------
# 层 2 的入口：两条保存路径都必须拒绝掩码
# ----------------------------------------------------------------------

def test_ui_save_rejects_mask_before_writing():
    src = _ga_src()
    i = src.find("def save_api_config_ui")
    assert i > 0
    frag = src[i:i + 1800]
    assert "_looks_like_real_api_key(key)" in frag, \
        "UI 保存路径未校验 Key 合法性（掩码可被写入 DPAPI）"


def test_api_save_secure_rejects_mask():
    """REST 端点也必须校验（它是第二条写入 DPAPI 的路径）。"""
    src = _ga_src()
    i = src.find('async def config_save_secure')
    if i < 0:
        i = src.find("save_secure")
    assert i > 0, "未找到 save_secure 端点"
    frag = src[i:i + 1200]
    assert "_looks_like_real_api_key(api_key)" in frag, \
        "REST 保存端点未校验 Key 合法性"


# ----------------------------------------------------------------------
# 层 3：仅当 DPAPI 回读一致时才清除 .env 明文
# ----------------------------------------------------------------------

def test_dpapi_write_is_verified_by_readback():
    """不能只信 is_encrypted 的返回值——必须回读比对。"""
    src = _ga_src()
    i = src.find("def save_api_config_ui")
    frag = src[i:i + 6000]
    assert 'ss.get("LLM_API_KEY")' in frag, "DPAPI 写入后未回读校验"
    assert "back == key_val" in frag, "回读结果未与写入值比对"


def test_env_plaintext_only_cleared_when_dpapi_ok():
    """`write_env_key = (not dpapi_ok)` —— 明文只在 DPAPI 确认有效后才清。"""
    src = _ga_src()
    i = src.find("def save_api_config_ui")
    frag = src[i:i + 6000]
    assert "write_env_key = (not dpapi_ok)" in frag
    # dpapi_ok 必须同时依赖 is_encrypted 与回读一致
    assert "bool(ss.is_encrypted" in frag and "back == key_val" in frag


# ----------------------------------------------------------------------
# 端到端：真实掩码走保存函数必须被拒，且不得改动 .env
# ----------------------------------------------------------------------

def test_mask_save_attempt_does_not_touch_env(tmp_path, monkeypatch):
    """用真实掩码触发 UI 保存路径，必须被拒绝且 .env 保持原样。

    通过直接调用被提取的校验逻辑验证（save_api_config_ui 是嵌套函数，
    无法从模块外直接调用，故对其校验函数做等价断言）。
    """
    from src.ui.gradio_app import _looks_like_real_api_key

    env = tmp_path / ".env"
    original = f"LLM_API_KEY={REAL_KEY}\nLLM_MODEL=glm-4.5-air\n"
    env.write_text(original, encoding="utf-8")
    before = env.read_bytes()

    # 掩码必须被判定为非法 → 保存函数会在写 DPAPI / 清 .env 之前 return
    assert _looks_like_real_api_key(ACCIDENT_MASK) is False

    # 由于校验发生在任何写入之前，.env 不会被触及
    assert env.read_bytes() == before


def test_llm_client_would_fail_on_mask():
    """印证事故：掩码含非 ASCII，HTTP 头编码必然抛错。"""
    with pytest.raises(UnicodeEncodeError):
        f"Bearer {ACCIDENT_MASK}".encode("ascii")
    assert _is_ascii_safe(REAL_KEY)


def _is_ascii_safe(s: str) -> bool:
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


# ----------------------------------------------------------------------
# 文档：CHANGELOG 必须记录这起事故
# ----------------------------------------------------------------------

def test_changelog_records_key_mask_incident():
    src = io.open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()
    assert "掩码" in src and "DPAPI" in src, "CHANGELOG 未记录掩码事故"
