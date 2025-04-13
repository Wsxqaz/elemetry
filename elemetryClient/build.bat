@echo off
setlocal enabledelayedexpansion

REM Set default platform and configuration
set PLATFORM=x64
set CONFIGURATION=Debug

REM Check for arguments
if not "%1"=="" set PLATFORM=%1
if not "%2"=="" set CONFIGURATION=%2

echo Building elemetryClient for %PLATFORM% %CONFIGURATION%

REM Find Visual Studio installation
set FOUND_VS=0
set MSBUILD_PATH=

REM Check for Visual Studio 2022
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    set FOUND_VS=1
    echo Found Visual Studio 2022 Community
    goto build
)

if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    set FOUND_VS=1
    echo Found Visual Studio 2022 Professional
    goto build
)

if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    set FOUND_VS=1
    echo Found Visual Studio 2022 Enterprise
    goto build
)

REM Check for Visual Studio 2019
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
    set FOUND_VS=1
    echo Found Visual Studio 2019 Community
    goto build
)

if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe"
    set FOUND_VS=1
    echo Found Visual Studio 2019 Professional
    goto build
)

if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    set FOUND_VS=1
    echo Found Visual Studio 2019 Enterprise
    goto build
)

REM If we get here, no Visual Studio installation was found
if %FOUND_VS%==0 (
    echo ERROR: Could not find Visual Studio 2019 or 2022 installation.
    exit /b 1
)

:build
echo Using MSBuild: !MSBUILD_PATH!

REM Build the solution
echo Building project...
"!MSBUILD_PATH!" elemetryClient.vcxproj /p:Configuration=%CONFIGURATION% /p:Platform=%PLATFORM% /v:minimal /m

if %ERRORLEVEL% neq 0 (
    echo Build failed with error level %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

echo Build completed successfully.

REM Post-build steps: Copy debug DLLs
echo Running post-build steps...
call copy_debug_dlls.bat

REM Create directory for symbol cache if not exists
set SYMBOL_CACHE=C:\Symbols
if not exist "%SYMBOL_CACHE%" (
    echo Creating symbol cache directory: %SYMBOL_CACHE%
    mkdir "%SYMBOL_CACHE%"
)

echo Done!
exit /b 0 