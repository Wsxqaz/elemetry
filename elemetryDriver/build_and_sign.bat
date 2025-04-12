@echo off
echo Building and signing TelemetrySourcerer Driver...

REM Build the driver
msbuild elemetryDriver.vcxproj /p:Configuration=Debug /p:Platform=x64

if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to build the driver.
    exit /b 1
)

REM Check if the driver file exists
if not exist "x64\Debug\elemetryDriver.sys" (
    echo Error: Driver file not found after build.
    exit /b 1
)

REM Sign the driver
echo Signing the driver...
signtool sign /v /s TestCertStore /n TestCert /fd sha256 /tr http://timestamp.digicert.com /td sha256 /d "TelemetrySourcerer Driver" "x64\Debug\elemetryDriver.sys"

if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to sign the driver.
    exit /b 1
)

echo Driver built and signed successfully.
echo The driver is located at: x64\Debug\elemetryDriver.sys
exit /b 0 