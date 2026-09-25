@echo off
chcp 65001 >nul
title ZZ EDR v14.39.0.0 编译
echo ============================================
echo   ZZ EDR v14.39.0.0  -  一键编译
echo ============================================

where cl >nul 2>&1
if errorlevel 1 (
    echo [!] 未找到 MSVC, 尝试调用 vswhere ...
    for /f "tokens=*" %%p in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath 2^>nul') do (
        if exist "%%p\VC\Auxiliary\Build\vcvars64.bat" (
            call "%%p\VC\Auxiliary\Build\vcvars64.bat"
        )
    )
)

if not exist build mkdir build

set FLAGS=/std:c++17 /utf-8 /O2 /MT /W3 /GS /guard:cf /CETCOMPAT /D_WIN32_WINNT=0x0A00
set FLAGS=%FLAGS% /DVER_MAJOR=14 /DVER_MINOR=39 /DVER_PATCH=0 /DVER_BUILD=0 /D_CRT_SECURE_NO_WARNINGS
set LIBS=user32.lib comctl32.lib gdi32.lib advapi32.lib psapi.lib iphlpapi.lib crypt32.lib shell32.lib shlwapi.lib winmm.lib winhttp.lib wtsapi32.lib comdlg32.lib sechost.lib netapi32.lib

echo [*] 编译 ZZ_EDR.cpp ...
cl %FLAGS% ZZ_EDR.cpp %LIBS% /Fe:ZZ_EDR_v14.39.0.0.exe /Fo:build\ 2>build_errors.txt

if errorlevel 1 (
    echo [!] 编译失败, 详见 build_errors.txt
    type build_errors.txt
    pause
    exit /b 1
)

echo [*] 计算 SHA-256 ...
certutil -hashfile ZZ_EDR_v14.39.0.0.exe SHA256 >sha256.txt 2>nul

echo.
echo ============================================
echo   编译成功: ZZ_EDR_v14.39.0.0.exe
echo   哈希已写入 sha256.txt
echo ============================================
pause
