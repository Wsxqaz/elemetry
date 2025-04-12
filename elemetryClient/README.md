# Elemetry Client

A user-mode application to interact with the elemetryDriver kernel driver. This client application sends IOCTLs to trigger module enumeration and view system callbacks registered in the kernel.

## Prerequisites

- Visual Studio 2019 or later
- Windows 10 SDK
- Administrative privileges (to load and interact with the driver)

## Build Instructions

### Using Visual Studio Solution (Recommended)

1. Open `elemetryClient.sln` in Visual Studio
2. Select the desired configuration (Debug/Release) and platform (x64/Win32)
3. Build the solution using `Build > Build Solution` or press F7
4. The output will be in the `bin\$(Platform)\$(Configuration)\` directory

### Using CMake

1. Create a build directory:
   ```
   mkdir build
   cd build
   ```

2. Generate build files:
   ```
   cmake ..
   ```

3. Build the application:
   ```
   cmake --build . --config Release
   ```

## Installing and Loading the Driver

Before running the client, you need to install and load the elemetryDriver:

### Using the Driver Build Scripts

1. Navigate to the `elemetryDriver` directory
2. Run `build_and_sign.bat` to build and sign the driver
3. Install the driver manually or using:
   ```
   sc create elemetryDriver type= kernel binPath= "path\to\elemetryDriver.sys"
   sc start elemetryDriver
   ```

### Manual Driver Installation

1. Build the elemetryDriver project in Visual Studio
2. Open an elevated Command Prompt
3. Use the following commands to install and start the driver:
   ```
   sc create elemetryDriver type= kernel binPath= "full\path\to\elemetryDriver.sys"
   sc start elemetryDriver
   ```
4. To stop and remove the driver:
   ```
   sc stop elemetryDriver
   sc delete elemetryDriver
   ```

## Running the Application

1. Ensure the elemetryDriver is installed and running (see instructions above)
2. Run the client application with administrative privileges:
   - If using Visual Studio: Right-click on the project and select "Run as Administrator" (this is configured in the project settings)
   - If running manually: 
     ```
     RunAs /user:administrator elemetryClient.exe
     ```

## Features

- Retrieves module information from the kernel driver
- Retrieves registered callback information 
- Displays information in a readable format

## Project Structure

- `elemetryClient.cpp` - Main application source code
- `elemetry.h` - Common definitions shared with the driver
- `elemetryClient.vcxproj` - Visual Studio project file
- `elemetryClient.sln` - Visual Studio solution file
- `CMakeLists.txt` - CMake build configuration

## Troubleshooting

If you encounter "Access Denied" errors:
- Make sure you're running as Administrator
- Verify that the elemetryDriver service is running
- Check Windows Event Viewer for driver-related errors

If you encounter "Failed to open device handle. Error code: 2":
- Make sure the driver is loaded and running
- Check that the symbolic link `\\.\elemetry` is created by the driver
- Use `sc query elemetryDriver` to verify the driver's status

## License

This project is licensed under the same terms as the parent project. 