@echo off
chcp 65001 >nul
title 制作安装程序（Inno Setup）
cd /d "%~dp0"

echo ============================================================
echo   AI网络安全智能分析系统 - 生成安装包
echo   前置：已运行 打包成EXE.bat 生成 dist\AI网络安全分析系统\
echo ============================================================
echo.

if not exist "dist\AI网络安全分析系统\AI网络安全分析系统.exe" (
    echo 错误：未找到打包产物，请先运行 打包成EXE.bat
    pause
    exit /b 1
)

rem 自动寻找 ISCC.exe（Inno Setup 编译器）
set "ISCC="
for %%P in (
    "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
    "%ProgramFiles%\Inno Setup 6\ISCC.exe"
    "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe"
) do (
    if not defined ISCC if exist "%%~P" set "ISCC=%%~P"
)

if not defined ISCC (
    echo 错误：未找到 Inno Setup 6，请先安装：
    echo   方式1: winget install JRSoftware.InnoSetup
    echo   方式2: 官网下载 https://jrsoftware.org/isdl.php
    pause
    exit /b 1
)

echo 使用编译器: %ISCC%
echo 开始编译安装包（lzma2 压缩，约需 2-5 分钟）...
echo.

"%ISCC%" "installer.iss"
if errorlevel 1 (
    echo.
    echo 错误：编译失败，请查看上方错误信息
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   安装包生成完成！
echo   位置: installer_output\AI网络安全智能分析系统_Setup_1.3.1.exe
echo   将该文件拷贝到其他电脑即可安装使用
echo ============================================================
pause
