# Elemetry Client Application

The Elemetry Client is a Windows application that communicates with the Elemetry Driver to enumerate kernel modules and callback routines.

## Features

- Enumerate kernel modules loaded in the system
- Enumerate kernel callbacks (Load Image, Process Creation)
- Find and display detailed information about kernel callbacks
- Support for symbol resolution through Microsoft Symbol Server

## Building the Application

### Prerequisites

- Visual Studio 2019 or 2022 with C++ Desktop Development workload
- Windows SDK 10.0.19041.0 or newer
- Windows Driver Kit (optional, for driver development)
- Debugging Tools for Windows (part of the Windows SDK)

### Build Steps

1. Open a Developer Command Prompt for Visual Studio
2. Navigate to the elemetryClient directory
3. Run the build script:

```
build.bat
```

The build script will:
- Find your Visual Studio installation
- Build the application for x64 Debug by default
- Copy necessary debug DLLs like symsrv.dll to the output directory
- Create a symbol cache directory if needed

### Build Configuration

You can specify the platform and configuration as arguments:

```
build.bat [Platform] [Configuration]
```

Example:
```
build.bat x64 Release
```

## Running the Application

After building, run the application using:

```
run.bat
```

Make sure the Elemetry Driver is loaded before running the client application.

## Symbol Loading

The application attempts to use Microsoft Symbol Server to resolve kernel symbols for accurate callback information:

### Symbol Requirements

For proper symbol resolution, the application needs:

1. **Symbol Server DLLs**: 
   - symsrv.dll
   - dbghelp.dll
   - symstore.dll
   - dbgcore.dll

2. **Symbol Cache Directory**:
   - The application uses C:\Symbols as a cache for downloaded symbols
   - This directory is created automatically during build

### Symbol Troubleshooting

If the application can't load symbols:

1. **Check Output Directory**:
   - Verify that symsrv.dll and other debugging DLLs are present in the output directory
   - Run copy_debug_dlls.bat manually if needed

2. **Internet Connection**:
   - Symbol downloading requires internet access to https://msdl.microsoft.com
   - Check corporate firewall settings that might block symbol server access

3. **Manual Symbol Download**:
   - If automatic download fails, you can manually download symbols using symchk:
     ```
     symchk /r C:\Windows\System32\ntoskrnl.exe /s SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols
     ```

4. **Fallback Mechanism**:
   - If symbols can't be loaded, the application will fall back to using hardcoded offsets
   - This provides functionality even without symbols, but may be less accurate

## Troubleshooting

### Common Issues

1. **Error: Failed to open driver handle**
   - Make sure the Elemetry Driver is loaded and running
   - Verify you have Administrator privileges

2. **Error: symsrv.dll load failure**
   - The symbol server DLL couldn't be loaded
   - Run copy_debug_dlls.bat script to fix this issue

3. **Symbol lookup failures**
   - Verify internet connectivity to Microsoft Symbol Server
   - Check that C:\Symbols directory exists and is writable
   - Ensure Windows SDK is properly installed with Debugging Tools

## License

This project is available for educational purposes only.

## Acknowledgements

- Windows Kernel Programming by Pavel Yosifovich
- Windows Internals, 7th Edition 