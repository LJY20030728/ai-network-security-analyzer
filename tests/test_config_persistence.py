"""
配置与令牌持久化安全测试

覆盖 src/ui/gradio_app.py 的 _generate_and_persist_token（写入 .env 的唯一路径）。

背景（真实数据破坏缺陷）：
  原实现在 .env 存在但读取失败（编码/权限/被占用）时把内容当作空列表，
  随后仍以写模式打开并写回 —— 效果是整个 .env 被覆盖成只剩 API_AUTH_TOKEN，
  用户的 LLM_API_KEY / LLM_BASE_URL / LLM_MODEL 全部丢失。
  且因为 token 已生成、鉴权看似正常，故障被自我掩盖。
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import src.ui.gradio_app as ga


class TestTokenPersistenceSafety:
    """_generate_and_persist_token 不得破坏已有 .env 内容"""

    def _call(self, monkeypatch, env_path):
        monkeypatch.setattr(ga, "find_env_file", lambda: str(env_path), raising=True)
        return ga._generate_and_persist_token()

    def test_unreadable_env_is_not_overwritten(self, tmp_path, monkeypatch):
        """★ 核心回归：.env 存在但读取失败时，必须放弃写入，绝不覆盖"""
        env = tmp_path / ".env"
        original = b"LLM_API_KEY=sk-real-key\nLLM_MODEL=glm-4.5-air\n"
        env.write_bytes(original)

        # 让读取必然失败：写入非法 UTF-8 字节
        env.write_bytes(b"LLM_API_KEY=\xff\xfe\x00bad\nLLM_MODEL=glm-4.5-air\n")
        before = env.read_bytes()

        token = self._call(monkeypatch, env)
        after = env.read_bytes()

        assert token, "仍应返回一个可用的内存 token"
        assert len(token) == 32, "token 应为 32 位 hex"
        assert after == before, (
            "读取失败时 .env 被改写，用户配置可能已丢失\n"
            f"before={before!r}\nafter={after!r}"
        )

    def test_existing_token_is_replaced_in_place(self, tmp_path, monkeypatch):
        """正常情况：原地替换 API_AUTH_TOKEN，其余内容保持不变"""
        env = tmp_path / ".env"
        env.write_text(
            "# 注释行\nLLM_API_KEY=sk-real-key\nAPI_AUTH_TOKEN=oldtoken\nLLM_MODEL=glm-4.5-air\n",
            encoding="utf-8",
        )
        token = self._call(monkeypatch, env)
        content = env.read_text(encoding="utf-8")

        assert f"API_AUTH_TOKEN={token}" in content
        assert "oldtoken" not in content
        # 其他配置项与注释必须保留
        assert "LLM_API_KEY=sk-real-key" in content
        assert "LLM_MODEL=glm-4.5-air" in content
        assert "# 注释行" in content

    def test_missing_token_is_appended_without_losing_config(self, tmp_path, monkeypatch):
        """.env 存在但没有 token 项：追加，且不丢其他配置"""
        env = tmp_path / ".env"
        env.write_text("LLM_API_KEY=sk-real-key\nLLM_MODEL=glm-4.5-air\n", encoding="utf-8")
        token = self._call(monkeypatch, env)
        content = env.read_text(encoding="utf-8")

        assert f"API_AUTH_TOKEN={token}" in content
        assert "LLM_API_KEY=sk-real-key" in content
        assert "LLM_MODEL=glm-4.5-air" in content

    def test_nonexistent_env_is_created(self, tmp_path, monkeypatch):
        """文件本不存在时允许创建（首次启动场景）"""
        env = tmp_path / ".env"
        assert not env.exists()
        token = self._call(monkeypatch, env)
        assert env.exists()
        assert f"API_AUTH_TOKEN={token}" in env.read_text(encoding="utf-8")
