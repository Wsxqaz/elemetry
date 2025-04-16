# Elemetry Client Application

The Elemetry Client is a Windows application that communicates with the Elemetry Driver to enumerate kernel modules and callback routines.

> NOTE: currently requires ntoskrnl in cwd

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

### Building with Visual Studio

1. **Open Solution**:
   - Open `elemetry.sln` in Visual Studio
   - Select the `elemetryClient` project in Solution Explorer


### Build Verification 

After building:

1. Check output directory contains:
   - elemetryClient.exe
   - symsrv.dll
   - dbghelp.dll
   - Other required DLLs

2. Test basic execution:
   - Run from command prompt as Administrator
   - Should show main menu without errors


Make sure the Elemetry Driver is loaded before running the client application.

## Symbol Loading

The application attempts to use Microsoft Symbol Server to resolve kernel symbols for accurate callback information:

### Symbol Requirements

For proper symbol resolution, the application needs:

1. **Symbol Server DLLs**: 
   - symsrv.dll
   - dbghelp.dll
   - dbgcore.dll

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
   - Ensure Windows SDK is properly installed with Debugging Tools

## Acknowledgements

- Windows Kernel Programming by Pavel Yosifovich
- Windows Internals, 7th Edition 