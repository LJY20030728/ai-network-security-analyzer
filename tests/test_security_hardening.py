# -*- coding: utf-8 -*-
"""
安全四项 的回归测试

锁定四个已确认缺陷（均已实测复现并修复）：

1. **Gradio UI 零鉴权**：token 中间件只覆盖 `/api/*`，而 UI 挂载在 `/`，
   于是 UI 全部事件回调（打开文件、写配置、触发分析）在对外暴露时可被无鉴权
   调用。现通过 `auth_dependency` 覆盖 UI 整体：回环免 token，非回环强制。

2. **`os.startfile()` 任意路径打开**：4 处无条件调用，且与"递归搜索文件系统
   找文件再打开"组合。现默认禁用，需 `AI_NSA_ALLOW_OPEN_PATH=1` 显式启用，
   且路径必须位于程序 data 目录内。

3. **API Key 明文落 `.env`**：DPAPI 写入后仍把明文再写一份到 `.env`；
   且预填函数由 `demo.load()` 每次页面加载调用，把真实 Key 推送到浏览器。
   现 Windows 仅 DPAPI（并清除 .env 明文），预填只回掩码。

4. **SSRF + 凭据外带**：`/api/config/validate` 把用户传入的 `base_url` 直接
   请求，并携带 `Authorization: Bearer <真实 Key>`，仅校验非空。
   现强制 https、拒绝回环/私网/保留地址与非标端口。
   另：移除 `allowed_paths`，不再无鉴权对外服务 reports/uploads/history。

5. **RAG 静默下载未校验模型**：现内置 sha256 白名单并支持禁用自动下载；
   移除 chromadb 默认 EF 降级（它会从 AWS S3 下载第二个模型）。

本文件为新增测试，不修改任何既有测试。
"""
import os
import re
import sys

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ----------------------------------------------------------------------
# 1. 回环判定与 UI 鉴权依赖
# ----------------------------------------------------------------------

@pytest.mark.parametrize("host,expected", [
    ("127.0.0.1", True), ("::1", True), ("localhost", True),
    ("192.168.1.5", False), ("10.0.0.1", False), ("172.16.0.1", False),
    ("example.com", False), ("", False), ("0.0.0.0", False),
])
def test_loopback_detection(host, expected):
    from src.ui.gradio_app import _is_loopback_host
    assert _is_loopback_host(host) is expected


class _FakeRequest:
    def __init__(self, client_ip, host_header, headers=None, method="GET", path="/"):
        class _C:
            host = client_ip
        self.client = _C()
        self.headers = {"host": host_header, **(headers or {})}
        self.method = method
        self.query_params = {}

        class _U:
            pass
        self.url = _U()
        self.url.path = path


@pytest.mark.parametrize("client_ip,host_header,expected", [
    ("127.0.0.1", "127.0.0.1:8080", True),
    ("::1", "[::1]:8080", True),              # IPv6 字面量（曾因 host.count(':')==1 判断而漏判）
    ("127.0.0.1", "localhost:7860", True),
    ("192.168.1.9", "192.168.1.9:8080", False),
    ("172.17.0.1", "example.com", False),     # Docker 端口映射场景
    ("127.0.0.1", "example.com", False),      # 客户端回环但 Host 非回环 → 不放行
])
def test_request_is_local(client_ip, host_header, expected):
    from src.ui.gradio_app import _request_is_local
    assert _request_is_local(_FakeRequest(client_ip, host_header)) is expected


def test_auth_dependency_returns_user_id_not_exception():
    """Gradio 6 要求 auth_dependency 返回用户 ID 字符串，返回 None 表示未认证。

    自己抛 HTTPException 会被 Gradio 视为依赖异常（曾导致带 token 也 401）。
    """
    import inspect
    from src.ui.gradio_app import require_token_for_external_access
    src = inspect.getsource(require_token_for_external_access)
    assert "return \"local\"" in src or "return 'local'" in src
    assert "raise HTTPException" not in src, "不应自行抛异常，交由 Gradio 处理"
    # 返回值注解应为 Optional[str]
    sig = inspect.signature(require_token_for_external_access)
    assert "str" in str(sig.return_annotation)


def test_ui_rejects_unauthenticated_non_loopback():
    """端到端：非回环无 token 访问 UI 必须被拒；带 token 必须放行。"""
    from fastapi.testclient import TestClient

    from config.settings import settings
    from src.ui.gradio_app import app

    tok = settings.api_auth_token or "test-token"
    original = settings.api_auth_token
    settings.api_auth_token = tok
    try:
        client = TestClient(app, raise_server_exceptions=False)
        # TestClient 默认 client/host 均为非回环（testclient / testserver）
        assert client.get("/").status_code == 401
        assert client.get("/", headers={"X-API-Token": tok}).status_code == 200
        assert client.get(f"/?token={tok}").status_code == 200
        # 健康检查仍豁免
        assert client.get("/api/health").status_code == 200
    finally:
        settings.api_auth_token = original


def test_allowed_paths_not_exposing_data_dirs():
    """reports/uploads/history 不得进入 Gradio 的文件服务白名单。"""
    import inspect
    from src.ui import gradio_app
    src = inspect.getsource(gradio_app)
    assert 'allowed_paths"] = [data_dir("reports")' not in src, \
        "仍把业务数据目录加入 allowed_paths（会无鉴权对外服务报告）"


# ----------------------------------------------------------------------
# 2. 受控的系统打开
# ----------------------------------------------------------------------

def test_open_path_disabled_by_default(tmp_path, monkeypatch):
    from src.ui.gradio_app import _open_path_with_shell
    from src.utils.paths import data_dir

    monkeypatch.delenv("AI_NSA_ALLOW_OPEN_PATH", raising=False)
    target = os.path.join(data_dir("reports"), "_test_open.html")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        f.write("x")
    try:
        opened, msg = _open_path_with_shell(target)
        assert opened is False, "默认必须不执行打开"
        assert "AI_NSA_ALLOW_OPEN_PATH" in msg
        assert target in msg, "应给出可复制的路径"
    finally:
        os.remove(target)


def test_open_path_rejects_outside_data_dir(monkeypatch):
    from src.ui.gradio_app import _open_path_with_shell
    monkeypatch.delenv("AI_NSA_ALLOW_OPEN_PATH", raising=False)
    outside = os.path.join(ROOT, "README.md")
    opened, msg = _open_path_with_shell(outside)
    assert opened is False
    assert "仅允许" in msg


def test_open_path_rejects_missing_file():
    from src.ui.gradio_app import _open_path_with_shell
    from src.utils.paths import data_dir
    opened, msg = _open_path_with_shell(os.path.join(data_dir("reports"), "nope_xyz.html"))
    assert opened is False


def test_no_unconditional_startfile_calls():
    """`os.startfile` 只能出现在受控助手内部（且以 `_os.startfile` 形式）。

    用 AST 精确判定：找出所有对 `startfile` 的调用，确认其宿主函数是
    `_open_path_with_shell`。
    """
    import ast
    import io
    path = os.path.join(ROOT, "src", "ui", "gradio_app.py")
    src = io.open(path, encoding="utf-8").read()
    tree = ast.parse(src)

    allowed_host = "_open_path_with_shell"
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                        and sub.func.attr == "startfile":
                    if node.name != allowed_host:
                        offenders.append((node.name, sub.lineno))
    assert not offenders, f"startfile 出现在非受控函数中: {offenders}"


def test_pcap_search_is_confined_to_data_dir():
    """不得再递归搜索 ~/Desktop、~/Downloads 或 cwd。

    判定方式：检查函数体内是否真的出现了**访问用户目录的调用**
    （`expanduser` / `getcwd`）。仅凭字符串内容判断会被 docstring 里的
    "原实现曾搜索 Desktop" 说明误伤。
    """
    import ast
    import io
    path = os.path.join(ROOT, "src", "ui", "gradio_app.py")
    src = io.open(path, encoding="utf-8").read()
    tree = ast.parse(src)

    target = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_search_pcap_file":
            target = node
            break
    assert target is not None, "未找到 _search_pcap_file"

    # 收集函数体内的属性名（属性访问不会被 docstring 影响）
    attrs = {n.attr for n in ast.walk(target) if isinstance(n, ast.Attribute)}
    for bad in ("expanduser", "getcwd"):
        assert bad not in attrs, f"_search_pcap_file 仍调用 {bad}（越权访问用户目录）"

    # 必须限定在 data_dir 内
    assert "data_dir" in {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}, \
        "搜索范围未限定在 data_dir 内"
    # 必须做纯文件名校验
    assert "basename" in attrs, "缺少纯文件名校验"


# ----------------------------------------------------------------------
# 4. SSRF 防护
# ----------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://169.254.169.254",           # 云元数据 + 明文
    "https://169.254.169.254",          # 云元数据
    "https://127.0.0.1",                # 回环
    "https://localhost",                # 回环名
    "https://10.0.0.1",                 # 私网
    "https://192.168.1.1",
    "https://172.16.0.1",
    "http://open.bigmodel.cn/api/paas/v4",   # 明文 http
    "https://attacker.local",           # 内网名
    "https://evil.internal",
    "https://open.bigmodel.cn:8080",    # 非标端口
    "https://0.0.0.0",
    "ftp://example.com",
    "",
])
def test_ssrf_targets_rejected(url):
    from src.ui.gradio_app import _assert_safe_llm_base_url
    with pytest.raises(HTTPException):
        _assert_safe_llm_base_url(url)


@pytest.mark.parametrize("url", [
    "https://open.bigmodel.cn/api/paas/v4",
    "https://api.deepseek.com/v1",
    "https://api.openai.com/v1",
])
def test_legitimate_endpoints_allowed(url):
    from src.ui.gradio_app import _assert_safe_llm_base_url
    assert _assert_safe_llm_base_url(url) == url


def test_validate_endpoint_does_not_echo_response_body():
    """校验接口不得回显上游响应正文（避免把探测结果当回显通道）。"""
    import inspect
    from src.ui.gradio_app import config_validate
    src = inspect.getsource(config_validate)
    assert "resp.text[:200]" not in src, "仍在回显上游响应正文"
    assert "follow_redirects=False" in src, "应禁止跟随重定向（防重定向绕过 SSRF 校验）"


# ----------------------------------------------------------------------
# 5. 模型下载校验与降级移除
# ----------------------------------------------------------------------

def test_expected_hashes_present_and_match_local_files():
    from src.ai.embeddings.bge_onnx import MODEL_FILES, expected_sha256, sha256_of
    md = os.path.join(ROOT, "models", "bge-small-zh-v1.5")
    for fn in MODEL_FILES:
        p = os.path.join(md, fn)
        if not os.path.isfile(p):
            pytest.skip(f"缺少本地模型文件 {fn}")
        assert expected_sha256(fn), f"{fn} 缺期望哈希"
        assert sha256_of(p) == expected_sha256(fn), f"{fn} 哈希与本地文件不符"


def test_tampered_model_file_is_rejected(tmp_path):
    import shutil
    from src.ai.embeddings.bge_onnx import MODEL_FILES, _dir_complete
    md = os.path.join(ROOT, "models", "bge-small-zh-v1.5")
    if not all(os.path.isfile(os.path.join(md, f)) for f in MODEL_FILES):
        pytest.skip("缺少本地模型文件")
    for f in MODEL_FILES:
        shutil.copy2(os.path.join(md, f), os.path.join(str(tmp_path), f))
    assert _dir_complete(str(tmp_path)) is True
    # 篡改最后一个字节
    p = os.path.join(str(tmp_path), "model.onnx")
    with open(p, "r+b") as fh:
        fh.seek(-1, os.SEEK_END)
        fh.write(b"\x00")
    assert _dir_complete(str(tmp_path)) is False, "被篡改的模型必须被拒绝"


def test_auto_download_can_be_disabled(monkeypatch):
    from src.ai.embeddings.bge_onnx import MODEL_AUTO_DOWNLOAD_ENV, auto_download_enabled
    monkeypatch.delenv(MODEL_AUTO_DOWNLOAD_ENV, raising=False)
    assert auto_download_enabled() is True
    for v in ("0", "false", "no", "off", "FALSE"):
        monkeypatch.setenv(MODEL_AUTO_DOWNLOAD_ENV, v)
        assert auto_download_enabled() is False


def test_missing_model_fails_loudly_when_download_disabled(monkeypatch, tmp_path):
    from src.ai.embeddings.bge_onnx import (
        BGEOnnxEmbeddingFunction, MODEL_AUTO_DOWNLOAD_ENV)
    monkeypatch.setenv(MODEL_AUTO_DOWNLOAD_ENV, "0")
    fn = BGEOnnxEmbeddingFunction(model_dir=str(tmp_path / "nonexistent"))
    with pytest.raises(FileNotFoundError):
        fn._prepare_model_dir()


def test_rag_has_no_default_embedding_fallback():
    """不得再引用 chromadb 的 DefaultEmbeddingFunction（它会从 S3 下载模型）。"""
    import ast
    import io
    src = io.open(os.path.join(ROOT, "src", "ai", "rag_engine.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "DefaultEmbeddingFunction":
            found.append(node.lineno)
        if isinstance(node, ast.Name) and node.id == "DefaultEmbeddingFunction":
            found.append(node.lineno)
    assert not found, f"仍引用 DefaultEmbeddingFunction: 行 {found}"


# ----------------------------------------------------------------------
# 6. Docker / 部署一致性
# ----------------------------------------------------------------------

def test_dockerfile_copy_sources_all_exist():
    """Dockerfile 中每个 COPY 的源路径都必须存在（曾引用不存在的 run_dev.py）。"""
    import re
    dockerfile = os.path.join(ROOT, "Dockerfile")
    src = open(dockerfile, encoding="utf-8").read()
    missing = []
    for m in re.finditer(r"^COPY\s+(\S+)\s+", src, re.M):
        p = m.group(1)
        if not os.path.exists(os.path.join(ROOT, p)):
            missing.append(p)
    assert not missing, f"Dockerfile COPY 了不存在的路径: {missing}"


def test_dockerfile_copy_sources_not_dockerignored():
    """COPY 的源不得同时被 .dockerignore 排除（否则构建失败）。

    实际发生过：Dockerfile `COPY models ./models`，而 .dockerignore 排除了
    `models/bge-small-zh-v1.5/`（且注释还声称"不打包进镜像"）——两者矛盾。
    """
    import re
    di_path = os.path.join(ROOT, ".dockerignore")
    pats = [l.strip() for l in open(di_path, encoding="utf-8")
            if l.strip() and not l.startswith("#")]
    src = open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8").read()

    def excluded(path):
        import fnmatch
        for q in pats:
            if fnmatch.fnmatch(path, q) or path.startswith(q.rstrip("/") + "/"):
                return q
        return None

    for m in re.finditer(r"^COPY\s+(\S+)\s+", src, re.M):
        p = m.group(1)
        # 只检查那些确实存在于仓库的路径（不存在的情况由上一个用例覆盖）
        if os.path.exists(os.path.join(ROOT, p)):
            hit = excluded(p)
            assert hit is None, f"COPY {p} 被 .dockerignore 的 {hit!r} 排除，构建会失败"


def test_dockerfile_runs_as_non_root():
    src = open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8").read()
    assert re.search(r"^USER\s+(?!root)\w+", src, re.M), "Dockerfile 未切换到非 root 用户"


def test_docker_compose_no_weak_default_token():
    """不得再提供 changeme 之类的弱默认 token。

    只检查生效的配置行（忽略注释——注释里说明"不再使用 changeme"是正确内容）。
    """
    lines = open(os.path.join(ROOT, "docker-compose.yml"), encoding="utf-8").read().splitlines()
    body = "\n".join(ln for ln in lines if ln.strip() and not ln.strip().startswith("#"))
    for weak in ["changeme", "admin", "password", "123456"]:
        assert weak not in body, f"docker-compose.yml 生效配置含弱默认凭据: {weak}"
    assert "API_AUTH_TOKEN" in body
    # 必须要求显式提供（:? 语法），而不是提供默认值
    assert "API_AUTH_TOKEN:?" in body or "API_AUTH_TOKEN:-?" in body


def test_server_respects_host_env_for_container():
    """main() 必须支持 HOST 环境变量，否则容器端口映射不可达。"""
    import inspect
    from src.ui import gradio_app as G
    src = inspect.getsource(G.main)
    assert 'getenv("HOST"' in src or "getenv('HOST'" in src
    assert "host=host" in src, "uvicorn 仍使用硬编码 host"


def test_container_token_is_required_for_non_loopback(monkeypatch):
    """容器内请求来自网桥（非回环）→ 无 token 必须被拒（fail closed）。"""
    from src.ui.gradio_app import _request_is_local
    assert _request_is_local(_FakeRequest("172.17.0.1", "some-host:8080")) is False
