@echo off
echo Signing driver...

REM Check if the driver file exists
if not exist "x64\Debug\elemetryDriver.sys" (
    echo Error: Driver file not found.
    exit /b 1
)

REM Sign the driver
signtool sign /v /s TestCertStore /n TestCert /fd sha256 /tr http://timestamp.digicert.com /td sha256 /d "elemetry Driver" "x64\Debug\elemetryDriver.sys"

if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to sign the driver.
    exit /b 1
)

echo Driver signed successfully.
exit /b 0 