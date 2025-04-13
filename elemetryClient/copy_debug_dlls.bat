@echo off
setlocal enabledelayedexpansion

REM ====================================================
REM Script to copy Windows SDK debug DLLs to output folder
REM Primarily handling symsrv.dll and dependencies
REM ====================================================

echo Searching for Windows SDK and debug DLLs...

REM Target directory is the location of the EXE
set "TARGET_DIR=%~dp0..\bin\x64\Debug\"

REM Check if target directory exists, create if not
if not exist "%TARGET_DIR%" (
    echo Creating output directory: %TARGET_DIR%
    mkdir "%TARGET_DIR%"
)

REM List of files to copy
set "FILES_TO_COPY=symsrv.dll symstore.dll dbghelp.dll dbgcore.dll"

REM Define common locations for Windows SDK 
set "FOUND_SDK="

REM Try Program Files - Windows Kits 10 x64
if exist "%ProgramFiles(x86)%\Windows Kits\10\Debuggers\x64" (
    set "SDK_DIR=%ProgramFiles(x86)%\Windows Kits\10\Debuggers\x64"
    set "FOUND_SDK=1"
    echo Found Windows SDK in: !SDK_DIR!
    goto copy_files
)

REM Try Program Files - Windows Kits 11 x64
if exist "%ProgramFiles(x86)%\Windows Kits\11\Debuggers\x64" (
    set "SDK_DIR=%ProgramFiles(x86)%\Windows Kits\11\Debuggers\x64"
    set "FOUND_SDK=1"
    echo Found Windows SDK in: !SDK_DIR!
    goto copy_files
)

REM Try normal Program Files - Windows Kits 10 x64
if exist "%ProgramFiles%\Windows Kits\10\Debuggers\x64" (
    set "SDK_DIR=%ProgramFiles%\Windows Kits\10\Debuggers\x64"
    set "FOUND_SDK=1"
    echo Found Windows SDK in: !SDK_DIR!
    goto copy_files
)

REM Try normal Program Files - Windows Kits 11 x64
if exist "%ProgramFiles%\Windows Kits\11\Debuggers\x64" (
    set "SDK_DIR=%ProgramFiles%\Windows Kits\11\Debuggers\x64"
    set "FOUND_SDK=1"
    echo Found Windows SDK in: !SDK_DIR!
    goto copy_files
)

REM Try Visual Studio installation locations
for /d %%V in ("%ProgramFiles(x86)%\Microsoft Visual Studio\*") do (
    for /d %%E in ("%%V\Enterprise" "%%V\Professional" "%%V\Community" "%%V\Preview") do (
        if exist "%%E\Common7\IDE\Extensions\TestPlatform\x64" (
            set "SDK_DIR=%%E\Common7\IDE\Extensions\TestPlatform\x64"
            set "FOUND_SDK=1"
            echo Found SDK tools in Visual Studio: !SDK_DIR!
            goto copy_files
        )
    )
)

REM Try newer Visual Studio 2022 paths
for /d %%V in ("%ProgramFiles%\Microsoft Visual Studio\*") do (
    for /d %%E in ("%%V\Enterprise" "%%V\Professional" "%%V\Community" "%%V\Preview") do (
        if exist "%%E\Common7\IDE\Extensions\TestPlatform\x64" (
            set "SDK_DIR=%%E\Common7\IDE\Extensions\TestPlatform\x64"
            set "FOUND_SDK=1"
            echo Found SDK tools in Visual Studio: !SDK_DIR!
            goto copy_files
        )
    )
)

:copy_files
if not defined FOUND_SDK (
    echo ERROR: Could not find Windows SDK with debugging tools.
    echo Please install Windows SDK or WDK with Debugging Tools for Windows.
    exit /b 1
)

echo Copying debug DLLs from !SDK_DIR! to !TARGET_DIR!
for %%F in (%FILES_TO_COPY%) do (
    if exist "!SDK_DIR!\%%F" (
        echo Copying %%F...
        copy /Y "!SDK_DIR!\%%F" "!TARGET_DIR!" > nul
        if errorlevel 1 (
            echo Failed to copy %%F
        ) else (
            echo Successfully copied %%F
        )
    ) else (
        echo WARNING: %%F not found in SDK directory
    )
)

REM Try copying from System32 as a fallback for dbghelp.dll
if not exist "%TARGET_DIR%\dbghelp.dll" (
    echo Copying dbghelp.dll from System32 as fallback...
    copy /Y "%SystemRoot%\System32\dbghelp.dll" "%TARGET_DIR%" > nul
    if errorlevel 1 (
        echo Failed to copy dbghelp.dll from System32
    ) else (
        echo Successfully copied dbghelp.dll from System32
    )
)

echo.
echo Debugging DLL verification:
for %%F in (%FILES_TO_COPY%) do (
    if exist "%TARGET_DIR%\%%F" (
        echo [✓] %%F found in target directory
    ) else (
        echo [✗] %%F missing from target directory
    )
)

echo.
echo Debug DLL copying process completed.
exit /b 0 