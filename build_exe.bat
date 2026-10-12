@echo off
chcp 65001 >nul
title 打包AI网络安全分析系统（PyInstaller）
cd /d "%~dp0"

echo ============================================================
echo   AI网络安全智能分析系统 - PyInstaller 打包
echo   （产出目录模式 dist\AI网络安全分析系统\，不含 .env）
echo ============================================================
echo.

if not exist "venv\Scripts\python.exe" (
    echo 错误：未找到虚拟环境，请先执行 安装依赖.bat
    pause
    exit /b 1
)

rem 清理旧产物
if exist "build" rmdir /s /q "build"
if exist "dist\AI网络安全分析系统" rmdir /s /q "dist\AI网络安全分析系统"

echo [1/1] 开始打包（gradio/chromadb/scapy 体积大，约需 10-30 分钟）...
echo.

rem 固定使用 PyQt6 作为 Qt 绑定（pywebview 经 qtpy 读取 QT_API）。
rem 本环境 PyQt5 绑定不完整：其 QLibraryInfo 为枚举式且无 path()/location()，
rem 会使 PyInstaller 的 PyQt5 hook 取不到 Qt 路径并直接报
rem "Qt plugin directory ... does not exist!"。故排除 PyQt5 相关模块。
set "QT_API=pyqt6"

rem ---- 预构建向量库 data\chroma_db 的条件化打包 ----
rem 背景：该目录被 .gitignore 忽略（66MB 二进制），因此**干净的 CI checkout 里不存在**，
rem 而 --add-data 引用不存在的路径会让 PyInstaller 直接报
rem   ERROR: Unable to find '...\data\chroma_db' when adding binary and data files.
rem 使打包步骤必然失败（实测：CI 首次执行到该步即中断）。
rem
rem 为何可以缺省：应用具备自愈能力 —— RAGEngine._ensure_seeded() 在集合为空时会从
rem 随包分发的 data\knowledge\docs（1.4MB，已入库）自动播种。
rem 代价：运行时重建的块数少于预构建库（内置知识源约 63 块 vs 预构建 1687 块，
rem 后者含 build_knowledge_base.py 导入的 MITRE 外部文档），即**首启动知识量较少**。
rem 故本地与正式发布仍应带上它；CI 仅验证"能否打包成功"。
rem
rem 注：这里用 goto 而非 if(...) 块 —— cmd 会在解析整个括号块时一次性展开
rem %VAR%，块内 set 的值在同块内不可见（实测会得到空参数）。
set "CHROMA_ARG="
if exist "data\chroma_db" goto have_chroma
echo [警告] 未找到 data\chroma_db —— 跳过预构建向量库。
echo         产物首启动将按内置知识源自愈重建，知识量少于预构建库。
echo         正式发布前请先执行: venv\Scripts\python.exe tools\build_knowledge_base.py
goto chroma_done
:have_chroma
set "CHROMA_ARG=--add-data data\chroma_db;data\chroma_db"
:chroma_done

"venv\Scripts\python.exe" -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --onedir ^
    --windowed ^
    --name "AI网络安全分析系统" ^
    --add-data "config;config" ^
    --add-data "src;src" ^
    --add-data "data\baselines;data\baselines" ^
    %CHROMA_ARG% ^
    --add-data "data\knowledge\docs;data\knowledge\docs" ^
    --add-data "data\knowledge\attack_types;data\knowledge\attack_types" ^
    --add-data "models\bge-small-zh-v1.5;models\bge-small-zh-v1.5" ^
    --add-data "models\stacking_meta_learner.joblib;models" ^
    --add-data "assets;assets" ^
    --icon "assets\app_icon.ico" ^
    --hidden-import=uvicorn.logging ^
    --hidden-import=uvicorn.loops ^
    --hidden-import=uvicorn.loops.auto ^
    --hidden-import=uvicorn.protocols ^
    --hidden-import=uvicorn.protocols.http.auto ^
    --hidden-import=uvicorn.protocols.http.h11_impl ^
    --hidden-import=uvicorn.protocols.websockets.auto ^
    --hidden-import=uvicorn.lifespan.on ^
    --hidden-import=uvicorn.lifespan.off ^
    --collect-all gradio ^
    --collect-all chromadb ^
    --collect-all scapy ^
    --collect-all onnxruntime ^
    --collect-all safehttpx ^
    --collect-all groovy ^
    --collect-all tokenizers ^
    --collect-all webview ^
    --collect-all qtpy ^
    --exclude-module PyQt5 ^
    --exclude-module PyQt5.QtCore ^
    --exclude-module PyQt5.QtWidgets ^
    --exclude-module PyQt5.sip ^
    --exclude-module PyQtWebEngine ^
    --exclude-module PyQtWebEngine.QtWebEngineWidgets ^
    --exclude-module pytest ^
    --exclude-module pydoc ^
    desktop_app.py

if errorlevel 1 (
    echo.
    echo 错误：打包失败，请查看上方错误信息
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   打包完成！
echo   产物目录: dist\AI网络安全分析系统\
echo.
echo   下一步：运行 制作安装程序.bat 生成安装包
echo   （注意：产物中不包含 .env，API Key 由用户在安装/首次运行时配置）
echo ============================================================
pause
