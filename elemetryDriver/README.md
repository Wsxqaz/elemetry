# ElemetryDriver

A Windows kernel-mode driver that uses DbgHelp to automatically enumerate system callbacks.

## Features

- Automatically enumerates various types of system callbacks:
  - Load Image Notify callbacks
  - Create Process Notify callbacks
  - Create Thread Notify callbacks
  - Registry callbacks
  - Object callbacks
  - Minifilter callbacks
- Uses DbgHelp to resolve symbol names and module information
- Provides detailed information about each callback including:
  - Callback type
  - Memory address
  - Symbol name
  - Module name

## Requirements

- Windows 10 x64
- Windows Driver Kit (WDK) 10.0
- Visual Studio 2019 or later
- Debugging Tools for Windows

## Building

1. Open the solution in Visual Studio
2. Select the x64 configuration
3. Build the solution

## Usage

1. Enable test signing on your system:
   ```
   bcdedit /set testsigning on
   ```

2. Install the driver:
   ```
   sc create elemetryDriver type= kernel binPath= "path\to\elemetryDriver.sys"
   sc start elemetryDriver
   ```

3. Check the debug output for callback information

## Notes

- The driver requires administrative privileges to install and run
- Debug output can be viewed using DebugView or WinDbg
- The driver uses DbgHelp for symbol resolution, so PDB files should be available for better symbol information

## License

This project is licensed under the MIT License - see the LICENSE file for details. 