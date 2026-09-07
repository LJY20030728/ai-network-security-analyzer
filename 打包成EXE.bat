@echo off
chcp 65001 >nul
title 打包AI网络安全分析系统为EXE
cd /d "%~dp0"

echo ============================================================
echo   AI网络安全智能分析系统 - EXE打包工具
echo ============================================================
echo.

rem 检查虚拟环境
if not exist "venv\Scripts\python.exe" (
    echo 错误：未找到虚拟环境，请先安装依赖
    pause
    exit /b 1
)

rem 安装pyinstaller
echo [1/3] 安装PyInstaller...
"venv\Scripts\python.exe" -m pip install pyinstaller --quiet
if errorlevel 1 (
    echo 错误：PyInstaller安装失败
    pause
    exit /b 1
)

rem 执行打包
echo.
echo [2/3] 开始打包（这可能需要5-15分钟）...
echo.

"venv\Scripts\python.exe" -m PyInstaller ^
    --name "AI网络安全分析系统" ^
    --windowed ^
    --onefile ^
    --add-data ".env;." ^
    --add-data "src;src" ^
    --add-data "config;config" ^
    --hidden-import=uvicorn.logging ^
    --hidden-import=uvicorn.loops ^
    --hidden-import=uvicorn.loops.auto ^
    --hidden-import=uvicorn.protocols ^
    --hidden-import=uvicorn.protocols.http.auto ^
    --hidden-import=uvicorn.protocols.websockets.auto ^
    --hidden-import=gradio ^
    --hidden-import=chromadb ^
    --hidden-import=scapy ^
    --hidden-import=langchain ^
    --collect-all gradio ^
    --collect-all chromadb ^
    --collect-all scapy ^
    desktop_app.py

if errorlevel 1 (
    echo.
    echo 错误：打包失败，请查看上方错误信息
    pause
    exit /b 1
)

rem 完成
echo.
echo [3/3] 打包完成！
echo.
echo EXE文件位置: dist\AI网络安全分析系统.exe
echo.
echo 注意：
echo   1. 首次运行需要将 .env 文件放在 exe 同目录下
echo   2. 确保已安装 WebView2 运行时（Win10/11通常已预装）
echo   3. 实时抓包功能需要管理员权限 + Npcap
echo.
pause
