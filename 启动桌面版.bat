@echo off
chcp 65001 >nul
title AI网络安全智能分析系统
cd /d "%~dp0"
echo ============================================================
echo   AI网络安全智能分析系统 - 桌面版
echo ============================================================
echo.
echo 正在启动，请稍候...
echo （首次启动可能需要10-30秒）
echo.

rem 使用虚拟环境Python运行桌面应用
if exist "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" desktop_app.py
) else (
    echo 错误：未找到虚拟环境，请先运行 setup.bat 安装依赖
    pause
)

rem 如果程序异常退出，保持窗口显示错误信息
if errorlevel 1 (
    echo.
    echo 程序异常退出，按任意键关闭...
    pause >nul
)
