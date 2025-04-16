# elemetry Driver

This is a kernel-mode driver for the elemetry project, which is designed to track and enumerate various kernel callbacks.

## Building the Driver

### Prerequisites

- Visual Studio 2019 or later with the Windows Driver Kit (WDK) installed
- Windows SDK 10.0.22621.0 or later
- A test certificate for signing the driver

### Building

1. Open the solution in Visual Studio
2. Select the Debug or Release configuration and x64 platform
3. Build the solution

### Signing the Driver

After building the driver, you need to sign it before it can be loaded into the kernel. There are two ways to do this:

#### Option 1: Using the SignTool in Visual Studio

1. Right-click on the project in Solution Explorer
2. Select "Properties"
3. Navigate to "Configuration Properties" > "Driver Signing"
4. Set "Sign Mode" to "Test Sign"
5. Set "Test Certificate" to your test certificate
6. Build the solution again

#### Option 2: Using the sign_driver.bat script

1. Open a command prompt with administrator privileges
2. Navigate to the project directory
3. Run the `sign_driver.bat` script

```
sign_driver.bat
```

## Loading the Driver

To load the driver for testing:

1. Enable test signing on your system:
   ```
   bcdedit /set testsigning on
   ```
2. Restart your system

### Method 1: Using Service Control Manager (sc)

1. Open a command prompt as Administrator:
   - Right-click on Command Prompt
   - Select "Run as administrator"
   - Click "Yes" when prompted by UAC

2. Create the service:
   ```
   sc create elemetryDriver type= kernel binPath= "<path_to_driver.sys>"
   ```
   Note: You can use any name for the service (e.g., "test"), but make sure to use the same name in all commands. If you use a different name, replace "elemetryDriver" with your chosen name in all commands below.

3. Start the service:
   ```
   sc start elemetryDriver
   ```


## Unloading the Driver

To unload the driver:

```
sc stop elemetryDriver
sc delete elemetryDriver
```

## Troubleshooting

### Signing Issues

If you encounter signing issues, make sure:

1. You have a valid test certificate installed
2. Test signing is enabled on your system
3. You're using the correct certificate name in the signing command

### Loading Issues

If you encounter issues loading the driver:

1. Check the Event Viewer for error messages:
   - Open Event Viewer (eventvwr.msc)
   - Check under Windows Logs > System
   - Look for errors related to driver loading

2. Make sure test signing is enabled:
   ```
   bcdedit
   ```
   Look for "testsigning" in the output. It should be "Yes"

3. Verify that the driver is properly signed:
   ```
   signtool verify /v /d "C:\path\to\elemetryDriver.sys"
   ```

4. Check that you have the necessary permissions:
   - Run Command Prompt as Administrator
   - Verify you're in the Administrators group:
     ```
     net localgroup administrators
     ```

5. If you get "Access is denied" error:
   - Make sure you're running Command Prompt as Administrator
   - Check if Driver Signature Enforcement is disabled:
     ```
     bcdedit /set nointegritychecks on
     ```
   - Restart your system after making any bcdedit changes

