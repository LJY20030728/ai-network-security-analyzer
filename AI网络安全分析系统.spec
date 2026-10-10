# -*- mode: python ; coding: utf-8 -*-
#
# AI网络安全智能分析系统 —— PyInstaller 规格文件
# ================================================================
# 权威构建方式：`build_exe.bat`（该 .bat 与本体保持一致；本文件由 PyInstaller
# `--clean` 依命令行参数重新生成，请勿只手工维护其中一处而漏掉另一处）。
#
# 【关键约束 1】Qt 绑定必须为 PyQt6
#   本环境同时装有 PyQt5 与 PyQt6，但 PyQt5 的 `QLibraryInfo` 为枚举式且无
#   `.path()`/`.location()`，会导致 PyInstaller 的 PyQt5 hook 取不到 Qt 路径并
#   直接报 "Qt plugin directory ... does not exist!"。故：
#     · excludes 中排除全部 PyQt5 / PyQtWebEngine 模块；
#     · 运行时由 desktop_app.py 在导入前设置 `QT_API=pyqt6`（pywebview 经 qtpy 读取）。
#   若用本文件直接构建，请先 `set QT_API=pyqt6`。
#
# 【关键约束 2】QtWebEngine 是桌面窗口的必需项
#   pywebview 的 qt 后端依赖 QtWebEngine（QtWebEngineProcess.exe、icudtl.dat、
#   qtwebengine_locales）。实测 `collect_all('webview')` 已能触发相应 hook 并完整
#   收集（产物中 PyQt6 目录约 521 MB）。仍显式收集 PyQt6 以增强可复现性，
#   避免依赖 hook 的隐式行为。
# ================================================================
from PyInstaller.utils.hooks import collect_all

datas = [('config', 'config'), ('src', 'src'), ('data/baselines', 'data/baselines'), ('data/chroma_db', 'data/chroma_db'), ('data/knowledge/docs', 'data/knowledge/docs'), ('data/knowledge/attack_types', 'data/knowledge/attack_types'), ('models/bge-small-zh-v1.5', 'models/bge-small-zh-v1.5'), ('models/stacking_meta_learner.joblib', 'models'), ('assets', 'assets')]
binaries = []
hiddenimports = ['uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto', 'uvicorn.protocols', 'uvicorn.protocols.http.auto', 'uvicorn.protocols.http.h11_impl', 'uvicorn.protocols.websockets.auto', 'uvicorn.lifespan.on', 'uvicorn.lifespan.off']
tmp_ret = collect_all('gradio')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('chromadb')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('scapy')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('onnxruntime')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('safehttpx')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('groovy')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('tokenizers')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('webview')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('qtpy')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
# 显式收集 PyQt6（含 Qt6 运行时与插件）与 QtWebEngine 子模块，保证桌面窗口可用
tmp_ret = collect_all('PyQt6')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('PyQt6.QtWebEngineCore')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('PyQt6.QtWebEngineWidgets')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['desktop_app.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['PyQt5', 'PyQt5.QtCore', 'PyQt5.QtWidgets', 'PyQt5.sip', 'PyQtWebEngine', 'PyQtWebEngine.QtWebEngineWidgets', 'pytest', 'pydoc'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AI网络安全分析系统',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets/app_icon.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='AI网络安全分析系统',
)
