@echo off
chcp 65001 >nul
title 安装依赖（创建虚拟环境 + pip 安装）
cd /d "%~dp0"

echo ============================================================
echo   AI网络安全智能分析系统 - 依赖安装
echo   仅用于从源码重新打包/运行（普通用户直接用安装包即可）
echo ============================================================
echo.

rem 检测 Python 3.11（PyInstaller 打包需要 3.11）
where py >nul 2>nul
if errorlevel 1 (
    echo 错误：未找到 Python 启动器 py，请先安装 Python 3.11
    echo 下载地址: https://www.python.org/downloads/windows/
    pause
    exit /b 1
)

py -3.11 --version >nul 2>nul
if errorlevel 1 (
    echo 错误：未检测到 Python 3.11，请安装后重试
    pause
    exit /b 1
)

rem 创建虚拟环境（若存在旧环境则跳过）
if not exist "venv\Scripts\python.exe" (
    echo [1/2] 创建虚拟环境 venv ...
    py -3.11 -m venv venv
    if errorlevel 1 (
        echo 错误：创建虚拟环境失败
        pause
        exit /b 1
    )
) else (
    echo [1/2] 已存在虚拟环境 venv，跳过创建
)

echo [2/2] 使用清华镜像安装依赖（约需 5-15 分钟）...
"venv\Scripts\python.exe" -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple
"venv\Scripts\python.exe" -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
if errorlevel 1 (
    echo.
    echo 错误：依赖安装失败，请检查网络后重试
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   依赖安装完成！
echo   下一步：运行 打包成EXE.bat 生成可执行程序
echo ============================================================
pause
