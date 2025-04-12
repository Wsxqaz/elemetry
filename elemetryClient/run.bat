@echo off
setlocal enabledelayedexpansion

:: Set default configuration and platform
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

:: Check if the executable exists
set EXECUTABLE=..\bin\%PLATFORM%\%CONFIG%\elemetryClient.exe

if not exist "%EXECUTABLE%" (
    echo.
    echo ERROR: Client executable not found at %EXECUTABLE%
    echo Please run build.bat first.
    echo.
    exit /b 1
)

echo.
echo Running elemetryClient (%CONFIG%/%PLATFORM%)...
echo.

:: Check if running as administrator
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo WARNING: Not running as administrator. The application may fail if it cannot access the driver.
    echo Press any key to try anyway, or Ctrl+C to cancel...
    pause >nul
)

:: Run the client
"%EXECUTABLE%"

echo.
if %ERRORLEVEL% NEQ 0 (
    echo Program exited with code %ERRORLEVEL%
) else (
    echo Program completed successfully
)

endlocal
exit /b 0 