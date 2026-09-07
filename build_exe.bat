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

"venv\Scripts\python.exe" -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --onedir ^
    --windowed ^
    --name "AI网络安全分析系统" ^
    --add-data "config;config" ^
    --add-data "src;src" ^
    --add-data "data\baselines;data\baselines" ^
    --add-data "models\bge-small-zh-v1.5;models\bge-small-zh-v1.5" ^
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
