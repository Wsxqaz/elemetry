@echo off
setlocal enabledelayedexpansion

echo Building elemetryClient...

:: Check for Visual Studio installation
WHERE /Q msbuild
IF ERRORLEVEL 1 (
    echo Visual Studio MSBuild not found in PATH.
    echo Please run this script from a Developer Command Prompt for Visual Studio.
    exit /b 1
)

:: Build for Release x64 by default
set CONFIG=Release
set PLATFORM=x64

:: Parse command line arguments
if not "%1"=="" (
    if /i "%1"=="debug" (
        set CONFIG=Debug
    ) else if /i "%1"=="release" (
        set CONFIG=Release
    )
)

if not "%2"=="" (
    if /i "%2"=="x86" (
        set PLATFORM=Win32
    ) else if /i "%2"=="x64" (
        set PLATFORM=x64
    )
)

echo Building for %CONFIG% configuration on %PLATFORM% platform...

:: Clean previous build
if exist ..\bin\%PLATFORM%\%CONFIG%\ (
    echo Cleaning previous build...
    rmdir /s /q ..\bin\%PLATFORM%\%CONFIG%\
)

:: Create output directories
mkdir ..\bin\%PLATFORM%\%CONFIG%\ 2>nul

:: Build the solution
msbuild ..\elemetryClient.sln /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /m /v:m /nologo

IF ERRORLEVEL 1 (
    echo Build failed!
    exit /b 1
)

echo Build completed successfully!
echo Output is in ..\bin\%PLATFORM%\%CONFIG%\

endlocal
exit /b 0 