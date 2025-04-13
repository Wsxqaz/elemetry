#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <unordered_map>
#include <fstream>
#include <filesystem>
#include <DbgHelp.h>
#include <Psapi.h>  // For EnumProcessModules, GetModuleInformation

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")  // Link against psapi.lib

#include "elemetry.h"

// Constants for kernel addresses, offsets, and sizes
#define MAX_MODULES 512
#define MAX_PATH_LENGTH 260
#define MAX_CALLBACKS_SHARED 256
#define MAX_CALLBACK_INFO_LENGTH 4096

// Helper function to convert wstring to string
std::string wstring_to_string(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Constants
const char* DRIVER_NAME = "\\\\.\\Elemetry"; // NT device path for our driver
const char* DEFAULT_SYMBOL_PATH = "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols";
const ULONG MAX_CALLBACKS_SHARED = 64; // Maximum number of callbacks to retrieve

// Primary symbol names for callback tables
const char* SYMBOL_LOAD_IMAGE_CALLBACKS = "PspLoadImageNotifyRoutine";
const char* SYMBOL_PROCESS_CALLBACKS = "PspCreateProcessNotifyRoutine";
const char* SYMBOL_THREAD_CALLBACKS = "PspCreateThreadNotifyRoutine";
const char* SYMBOL_REGISTRY_CALLBACKS = "CmCallbackListHead";

// Alternative symbol names for different Windows versions
const char* ALT_LOAD_IMAGE_CALLBACKS[] = {
    "PspLoadImageNotifyRoutine",
    "PspLoadImageNotifyRoutineCount",  // Some versions use this
    "PspLoadImageNotifyList"           // Some versions use this
};
const int ALT_LOAD_IMAGE_COUNT = 3;

const char* ALT_PROCESS_CALLBACKS[] = {
    "PspCreateProcessNotifyRoutine",
    "PspCreateProcessNotifyRoutineCount", // Some versions use this
    "PspCreateProcessNotifyRoutineEx"     // Some versions use this
};
const int ALT_PROCESS_COUNT = 3;

// Global variables for symbol enumeration callback
PVOID g_LocalSymbolAddr = NULL;
const char* g_TargetSymbol = NULL;

// Global variables for symbol enumeration to file
FILE* g_SymbolDumpFile = NULL;

// Callback for symbol enumeration when dumping to a file
BOOL CALLBACK SymEnumCallbackForDump(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) {
    if (g_SymbolDumpFile && pSymInfo) {
        // Format: SymbolName | Address | Size | Flags
        fprintf(g_SymbolDumpFile, "%-60s | 0x%016llX | %8lu | 0x%08X\n", 
            pSymInfo->Name, 
            pSymInfo->Address, 
            pSymInfo->Size, 
            pSymInfo->Flags);
    }
    return TRUE; // Continue enumeration
}

// Windows version-specific callback table addresses (offsets from ntoskrnl.exe base)
struct WinVersionCallbacks {
    DWORD BuildNumber;             // Windows build number
    ULONG_PTR LoadImageOffset;     // Offset of PspLoadImageNotifyRoutine from kernel base
    ULONG_PTR ProcessCreateOffset; // Offset of PspCreateProcessNotifyRoutine from kernel base
    const char* Description;       // Description of Windows version
};

// Known offsets for different Windows versions
// These values need to be updated for each new Windows version
const WinVersionCallbacks KnownCallbackOffsets[] = {
    // Windows 10 21H2 (Build 19044)
    { 19044, 0x359990, 0x359950, "Windows 10 21H2" },
    // Windows 10 22H2 (Build 19045)
    { 19045, 0x359990, 0x359950, "Windows 10 22H2" },
    // Windows 11 21H2 (Build 22000)
    { 22000, 0x3ADA50, 0x3ADA10, "Windows 11 21H2" },
    // Windows 11 22H2 (Build 22621)
    { 22621, 0x3B4710, 0x3B46D0, "Windows 11 22H2" },
    // Add more as needed for different Windows versions
};
const int KnownCallbackOffsetCount = sizeof(KnownCallbackOffsets) / sizeof(WinVersionCallbacks);

// Forward Declarations
bool GetWindowsVersion(DWORD& buildNumber);
bool GetCallbackAddressByWindowsVersion(PVOID kernelBase, CALLBACK_TABLE_TYPE callbackType, PVOID& callbackAddress);
bool DumpModuleSymbolsToFile(HANDLE deviceHandle, const wchar_t* moduleName, const char* outputFilename);
bool TestSymbolLookup(HANDLE deviceHandle);
bool LoadKernelModuleSymbols(HANDLE deviceHandle);
bool DumpAllSymbolsToFile(HANDLE deviceHandle);

// Callback function for SymEnumSymbols
BOOL CALLBACK SymEnumCallback(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) {
    if (strcmp(pSymInfo->Name, g_TargetSymbol) == 0) {
        g_LocalSymbolAddr = (PVOID)pSymInfo->Address;
        return FALSE; // Stop enumeration, we found it
    }
    return TRUE; // Continue enumeration
}

// Function to open a handle to the driver device
HANDLE OpenDriverHandle() {
    HANDLE deviceHandle = CreateFileA(
        DRIVER_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (deviceHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device handle. Error code: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    return deviceHandle;
}

// Function to print module information
void PrintModuleInfo(const MODULE_INFO& moduleInfo) {
    std::wcout << L"Module: " << moduleInfo.Path << std::endl;
    std::cout << "  Base Address: 0x" << std::hex << moduleInfo.BaseAddress << std::dec << std::endl;
    std::cout << "  Size: " << moduleInfo.Size << " bytes" << std::endl;
    std::cout << "  Flags: 0x" << std::hex << moduleInfo.Flags << std::dec << std::endl;
    std::cout << std::endl;
}

// Function to get callback type as string
std::string GetCallbackTypeString(CALLBACK_TYPE type) {
    switch (type) {
    case CALLBACK_TYPE::Unknown: return "Unknown";
    case CALLBACK_TYPE::PsLoadImage: return "PsLoadImage";
    case CALLBACK_TYPE::PsProcessCreation: return "PsProcessCreation";
    case CALLBACK_TYPE::PsThreadCreation: return "PsThreadCreation";
    case CALLBACK_TYPE::CmRegistry: return "CmRegistry";
    case CALLBACK_TYPE::ObProcessHandlePre: return "ObProcessHandlePre";
    case CALLBACK_TYPE::ObProcessHandlePost: return "ObProcessHandlePost";
    case CALLBACK_TYPE::ObThreadHandlePre: return "ObThreadHandlePre";
    case CALLBACK_TYPE::ObThreadHandlePost: return "ObThreadHandlePost";
    default: return "Unknown";
    }
}

// Function to print callback information
void PrintCallbackInfo(const CALLBACK_INFO_SHARED& callbackInfo) {
    std::cout << "Callback: " << callbackInfo.CallbackName << std::endl;
    std::cout << "  Type: " << GetCallbackTypeString(callbackInfo.Type) << std::endl;
    std::cout << "  Address: 0x" << std::hex << callbackInfo.Address << std::dec << std::endl;
    std::cout << "  Module: " << callbackInfo.ModuleName << std::endl;
    std::cout << "  Context: 0x" << std::hex << callbackInfo.Context << std::dec << std::endl;
    std::cout << std::endl;
}

// Function to write callback information to a file
void WriteCallbackToFile(std::ofstream& outFile, const CALLBACK_INFO_SHARED& callbackInfo) {
    outFile << "Callback: " << callbackInfo.CallbackName << std::endl;
    outFile << "  Type: " << GetCallbackTypeString(callbackInfo.Type) << std::endl;
    outFile << "  Address: 0x" << std::hex << callbackInfo.Address << std::dec << std::endl;
    outFile << "  Module: " << callbackInfo.ModuleName << std::endl;
    outFile << "  Context: 0x" << std::hex << callbackInfo.Context << std::dec << std::endl;
    outFile << std::endl;
}

// Function to get and display modules from the driver
bool GetDriverModules() {
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Allocate buffer for module information
    const DWORD bufferSize = sizeof(MODULE_INFO) * MAX_MODULES;
    std::vector<BYTE> buffer(bufferSize, 0);
    PMODULE_INFO moduleInfos = reinterpret_cast<PMODULE_INFO>(buffer.data());

    // Send IOCTL to get module information
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_GET_MODULES,
        moduleInfos, bufferSize,
        moduleInfos, bufferSize,
        &bytesReturned,
        nullptr
    );

    if (!success) {
        std::cerr << "DeviceIoControl failed. Error code: " << GetLastError() << std::endl;
        CloseHandle(deviceHandle);
        return false;
    }

    // Calculate number of modules returned
    DWORD moduleCount = bytesReturned / sizeof(MODULE_INFO);
    std::cout << "Retrieved " << moduleCount << " modules:" << std::endl << std::endl;

    // Print module information
    for (DWORD i = 0; i < moduleCount; i++) {
        PrintModuleInfo(moduleInfos[i]);
    }

    CloseHandle(deviceHandle);
    return true;
}

// Function to get and display callbacks from the driver
bool GetDriverCallbacks() {
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    // First call: Determine required buffer size with a small buffer
    // Use a small non-zero buffer for the first call, because zero-sized 
    // buffers don't always return the proper required size
    DWORD bytesReturned = 0;
    DWORD requiredSize = 0;
    char dummyBuffer[4] = {0};
    
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_GET_CALLBACKS,
        nullptr, 0,          // Empty input buffer
        dummyBuffer, sizeof(dummyBuffer),  // Small output buffer
        &bytesReturned,      // Will receive required size
        nullptr
    );
    
    // We expect this to fail with ERROR_MORE_DATA
    if (!success) {
        DWORD errorCode = GetLastError();
        if (errorCode != ERROR_MORE_DATA && errorCode != ERROR_INSUFFICIENT_BUFFER) {
            std::cerr << "DeviceIoControl failed unexpectedly. Error code: " << errorCode << std::endl;
            CloseHandle(deviceHandle);
            return false;
        }
        
        // Get required size - on Windows 10+, it's in bytesReturned
        if (bytesReturned > 0) {
            requiredSize = bytesReturned;
        } else {
            // Hard-code to 2MB if we didn't get a valid size back
            requiredSize = 2 * 1024 * 1024; // 2MB should be enough
        }
        
        std::cout << "Required buffer size for callbacks: " << requiredSize << " bytes" << std::endl;
    } else {
        // Should not succeed with small buffer
        std::cerr << "DeviceIoControl unexpectedly succeeded with small buffer." << std::endl;
        CloseHandle(deviceHandle);
        return false;
    }
    
    // Allocate buffer of required size (plus a safety margin)
    // Make sure we're not trying to allocate anything ridiculous
    if (requiredSize > 20 * 1024 * 1024) { // Cap at 20MB
        std::cerr << "Required buffer size is suspiciously large: " << requiredSize << " bytes" << std::endl;
        CloseHandle(deviceHandle);
        return false;
    }
    
    std::cout << "Allocating " << requiredSize << " bytes for callback data..." << std::endl;
    std::vector<BYTE> buffer(requiredSize, 0);
    PCALLBACK_INFO_SHARED callbackInfos = reinterpret_cast<PCALLBACK_INFO_SHARED>(buffer.data());
    
    // Second call: Get actual data with proper buffer size
    success = DeviceIoControl(
        deviceHandle,
        IOCTL_GET_CALLBACKS,
        nullptr, 0,                    // No input
        callbackInfos, static_cast<DWORD>(buffer.size()),  // Proper sized output buffer with explicit cast
        &bytesReturned,
        nullptr
    );
    
    if (!success) {
        std::cerr << "DeviceIoControl failed on second call. Error code: " << GetLastError() << std::endl;
        CloseHandle(deviceHandle);
        return false;
    }
    
    // Calculate number of callbacks returned
    DWORD callbackCount = bytesReturned / sizeof(CALLBACK_INFO_SHARED);
    std::cout << "Retrieved " << callbackCount << " callbacks from " << bytesReturned << " bytes." << std::endl << std::endl;
    
    // Create a file name with timestamp
    std::string fileBaseName = "elemetry_exports_";
    SYSTEMTIME st;
    GetLocalTime(&st);
    char timeStr[100];
    sprintf_s(timeStr, sizeof(timeStr), "%04d%02d%02d_%02d%02d%02d", 
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    fileBaseName += timeStr;
    fileBaseName += ".txt";
    
    // Set the path to Administrator's desktop
    std::string filePath = "C:\\Users\\Administrator\\Desktop\\";
    std::string fileName = filePath + fileBaseName;
    
    // Open output file
    std::ofstream outFile(fileName);
    if (!outFile.is_open()) {
        std::cerr << "Failed to open output file: " << fileName << std::endl;
        std::cerr << "Make sure the directory exists and you have write permissions." << std::endl;
        CloseHandle(deviceHandle);
        return false;
    }
    
    std::cout << "Writing " << callbackCount << " callbacks to file: " << fileName << std::endl;
    
    // Write header information to file
    outFile << "Elemetry Export Enumeration Results" << std::endl;
    outFile << "==================================" << std::endl;
    outFile << "Total exports found: " << callbackCount << std::endl;
    outFile << "Date/Time: " << timeStr << std::endl << std::endl;
    
    // Write callbacks to file and display a progress meter
    std::cout << "Progress: ";
    const int progressUpdateInterval = callbackCount / 50; // Update progress bar approximately 50 times
    for (DWORD i = 0; i < callbackCount; i++) {
        WriteCallbackToFile(outFile, callbackInfos[i]);
        
        // Show progress every N callbacks
        if (progressUpdateInterval > 0 && i % progressUpdateInterval == 0) {
            std::cout << ".";
            std::cout.flush();
        }
    }
    std::cout << " Done!" << std::endl;
    
    // Print just a small sample to console (first 5)
    std::cout << "Sample of first 5 callbacks:" << std::endl << std::endl;
    for (DWORD i = 0; i < min(5UL, callbackCount); i++) {
        PrintCallbackInfo(callbackInfos[i]);
    }
    
    // Add summary of module sources to both console and file
    std::cout << "\nCallback/Export Source Summary:" << std::endl;
    std::cout << "-----------------------------" << std::endl;
    
    outFile << "\nCallback/Export Source Summary:" << std::endl;
    outFile << "-----------------------------" << std::endl;
    
    std::unordered_map<std::string, int> moduleCounts;
    for (DWORD i = 0; i < callbackCount; i++) {
        std::string moduleName = callbackInfos[i].ModuleName;
        moduleCounts[moduleName]++;
    }
    
    for (const auto& pair : moduleCounts) {
        std::cout << pair.first << ": " << pair.second << " exports" << std::endl;
        outFile << pair.first << ": " << pair.second << " exports" << std::endl;
    }
    
    // Close the file
    outFile.close();
    std::cout << "Results successfully written to " << fileName << std::endl;
    
    CloseHandle(deviceHandle);
    return true;
}

// Function to print callback information with module lookup using symbols
void PrintSymbolCallbackInfo(const CALLBACK_INFO_SHARED& callbackInfo, HANDLE hProcess) {
    std::cout << "Callback: " << callbackInfo.CallbackName << std::endl;
    std::cout << "  Type: " << GetCallbackTypeString(callbackInfo.Type) << std::endl;
    std::cout << "  Address: 0x" << std::hex << callbackInfo.Address << std::dec << std::endl;
    
    // Try to get more info from symbols
    if (hProcess != NULL) {
        char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)symbolBuffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
        
        DWORD64 displacement = 0;
        if (SymFromAddr(hProcess, (DWORD64)callbackInfo.Address, &displacement, pSymbol)) {
            std::cout << "  Symbol: " << pSymbol->Name << std::endl;
            if (displacement > 0) {
                std::cout << "  Displacement: +" << std::hex << displacement << std::dec << std::endl;
            }
            
            // Try to get module information
            IMAGEHLP_MODULE64 moduleInfo = { 0 };
            moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
            if (SymGetModuleInfo64(hProcess, (DWORD64)callbackInfo.Address, &moduleInfo)) {
                std::cout << "  Module: " << moduleInfo.ImageName << std::endl;
                std::cout << "  Module Base: 0x" << std::hex << moduleInfo.BaseOfImage << std::dec << std::endl;
            }
        }
    }
    
    std::cout << "  Module: " << callbackInfo.ModuleName << std::endl;
    std::cout << "  Context: 0x" << std::hex << callbackInfo.Context << std::dec << std::endl;
    std::cout << std::endl;
}

// Function to read kernel memory
bool ReadKernelMemory(HANDLE deviceHandle, PVOID kernelAddress, PVOID buffer, SIZE_T size, SIZE_T* bytesRead) {
    if (deviceHandle == INVALID_HANDLE_VALUE || !kernelAddress || !buffer || size == 0) {
        return false;
    }
    
    KERNEL_READ_REQUEST request = { 0 };
    request.Address = kernelAddress;
    request.Buffer = buffer;
    request.Size = size;
    
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_READ_KERNEL_MEMORY,
        &request, sizeof(request),
        &request, sizeof(request),
        &bytesReturned,
        nullptr
    );
    
    if (!success) {
        std::cerr << "ReadKernelMemory failed. Error code: " << GetLastError() << std::endl;
        return false;
    }
    
    if (bytesRead) {
        *bytesRead = request.BytesRead;
    }
    
    return true;
}

// Function to get Windows version information
bool GetWindowsVersion(DWORD& buildNumber) {
    NTSTATUS(WINAPI *RtlGetVersion)(PRTL_OSVERSIONINFOW);
    RTL_OSVERSIONINFOW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    
    // Get RtlGetVersion dynamically as it's always available
    *(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (RtlGetVersion == nullptr) {
        std::cerr << "Failed to get RtlGetVersion function. Error: " << GetLastError() << std::endl;
        return false;
    }
    
    if (RtlGetVersion(&osvi) != 0) { // STATUS_SUCCESS is 0
        std::cerr << "RtlGetVersion failed" << std::endl;
        return false;
    }
    
    buildNumber = osvi.dwBuildNumber;
    std::cout << "Windows Version: " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion
              << " (Build " << osvi.dwBuildNumber << ")" << std::endl;
    
    return true; // Added missing return on success
}

// Function to find callback table addresses based on Windows version
bool GetCallbackAddressByWindowsVersion(PVOID kernelBase, CALLBACK_TABLE_TYPE callbackType, PVOID& callbackAddress) {
    DWORD buildNumber = 0;
    if (!GetWindowsVersion(buildNumber)) {
        return false;
    }
    
    // Find matching version in our known offsets table
    int matchIdx = -1;
    for (int i = 0; i < KnownCallbackOffsetCount; i++) {
        if (KnownCallbackOffsets[i].BuildNumber == buildNumber) {
            matchIdx = i;
            break;
        }
    }
    
    if (matchIdx == -1) {
        std::cerr << "No known callback offsets for Windows build " << buildNumber << std::endl;
        return false;
    }
    
    // Calculate address based on kernel base and appropriate offset
    ULONG_PTR offset = 0;
    switch (callbackType) {
        case CallbackTableLoadImage:
            offset = KnownCallbackOffsets[matchIdx].LoadImageOffset;
            break;
        case CallbackTableCreateProcess:
            offset = KnownCallbackOffsets[matchIdx].ProcessCreateOffset;
            break;
        default:
            std::cerr << "Unsupported callback type for hardcoded addresses" << std::endl;
            return false;
    }
    
    callbackAddress = (PVOID)((ULONG_PTR)kernelBase + offset);
    std::cout << "Using hardcoded address for " << KnownCallbackOffsets[matchIdx].Description
              << " at offset 0x" << std::hex << offset << std::dec
              << " (full address: 0x" << std::hex << callbackAddress << std::dec << ")" << std::endl;
    
    return true; // Added missing return on success
}

// Function to enumerate callbacks using the DbgHelp symbols approach
bool EnumerateCallbacksWithSymbols(HANDLE deviceHandle, CALLBACK_TABLE_TYPE callbackType, const char* symbolName, const wchar_t* moduleName = L"ntoskrnl.exe") {
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Initialize DbgHelp and symbols
    HANDLE hProcess = GetCurrentProcess();
    
    // Configure symbol options for better results
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG | SYMOPT_LOAD_LINES | 
                  SYMOPT_OMAP_FIND_NEAREST | SYMOPT_AUTO_PUBLICS | SYMOPT_NO_PROMPTS);
    
    // Try to initialize symbols
    if (!SymInitialize(hProcess, DEFAULT_SYMBOL_PATH, FALSE)) {
        DWORD error = GetLastError();
        std::cerr << "Failed to initialize symbols. Error code: " << error << std::endl;
        
        // Try again with a NULL path to use the default search path
        if (!SymInitialize(hProcess, NULL, FALSE)) {
            std::cerr << "Failed to initialize symbols with default path. Error code: " << GetLastError() << std::endl;
            return false;
        }
        std::cout << "Initialized symbols with default path after initial failure." << std::endl;
    }
    
    // Get requested module base address from our modules list
    const DWORD bufferSize = sizeof(MODULE_INFO) * MAX_MODULES;
    std::vector<BYTE> moduleBuffer(bufferSize, 0);
    PMODULE_INFO moduleInfos = reinterpret_cast<PMODULE_INFO>(moduleBuffer.data());

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_GET_MODULES,
        moduleInfos, bufferSize,
        moduleInfos, bufferSize,
        &bytesReturned,
        nullptr
    );
    
    if (!success) {
        std::cerr << "Failed to get modules. Error code: " << GetLastError() << std::endl;
        SymCleanup(hProcess);
        return false;
    }
    
    // Find the requested module
    DWORD moduleCount = bytesReturned / sizeof(MODULE_INFO);
    bool moduleFound = false;
    PVOID moduleBase = NULL;
    std::wstring moduleFileName;
    
    // Extract just the filename for comparison if a full path was provided
    size_t lastSlash = std::wstring(moduleName).find_last_of(L"/\\");
    if (lastSlash != std::wstring::npos) {
        moduleFileName = std::wstring(moduleName).substr(lastSlash + 1);
    } else {
        moduleFileName = moduleName;
    }
    
    // Convert requested module name to lowercase for case-insensitive comparison
    std::wstring moduleNameLower = moduleFileName;
    std::transform(moduleNameLower.begin(), moduleNameLower.end(), moduleNameLower.begin(), ::towlower);
    
    for (DWORD i = 0; i < moduleCount; i++) {
        // Convert to lowercase for case-insensitive comparison
        std::wstring modulePath = moduleInfos[i].Path;
        std::transform(modulePath.begin(), modulePath.end(), modulePath.begin(), ::towlower);
        
        // Check if the module path contains our requested module name
        if (modulePath.find(moduleNameLower) != std::wstring::npos) {
            moduleBase = moduleInfos[i].BaseAddress;
            moduleFound = true;
            std::cout << "Found module " << wstring_to_string(moduleFileName) << " at address: 0x" 
                      << std::hex << moduleBase << std::dec << std::endl;
            break;
        }
    }
    
    if (!moduleFound || !moduleBase) {
        std::cerr << "Failed to find module base address for: " << wstring_to_string(moduleFileName) << std::endl;
        SymCleanup(hProcess);
        return false;
    }
    
    // Convert the module filename to char for SymLoadModuleEx
    char ansiModuleName[MAX_PATH] = {0};
    WideCharToMultiByte(CP_ACP, 0, moduleFileName.c_str(), -1, ansiModuleName, MAX_PATH, NULL, NULL);
    
    // Load module symbols
    std::cout << "Loading symbols for " << ansiModuleName << "..." << std::endl;
    DWORD64 baseAddr = SymLoadModuleEx(hProcess, NULL, ansiModuleName, NULL, (DWORD64)moduleBase, 0, NULL, 0);
    if (baseAddr == 0) {
        DWORD error = GetLastError();
        
        // ERROR_SUCCESS (0) means the module was already loaded, which is fine
        if (error != ERROR_SUCCESS) {
            std::cerr << "Failed to load " << ansiModuleName << " symbols. Error code: " << error << std::endl;
            
            // Try with System32 directory path for standard system modules
            char systemDir[MAX_PATH] = {0};
            if (GetSystemDirectoryA(systemDir, MAX_PATH)) {
                std::string fullPath = std::string(systemDir) + "\\" + ansiModuleName;
                std::cout << "Trying with system path: " << fullPath << std::endl;
                baseAddr = SymLoadModuleEx(hProcess, NULL, fullPath.c_str(), ansiModuleName, (DWORD64)moduleBase, 0, NULL, 0);
                
                if (baseAddr == 0 && GetLastError() != ERROR_SUCCESS) {
                    // Try copy to local directory as last resort
                    if (CopyFileA(fullPath.c_str(), ansiModuleName, FALSE) || GetLastError() == ERROR_FILE_EXISTS) {
                        std::cout << "Copied module file to current directory, trying local path..." << std::endl;
                        baseAddr = SymLoadModuleEx(hProcess, NULL, ansiModuleName, NULL, (DWORD64)moduleBase, 0, NULL, 0);
                    }
                }
            }
            
            // If still failed, try with explicit module size
            if (baseAddr == 0 && GetLastError() != ERROR_SUCCESS) {
                MODULEINFO modInfo = {0};
                HMODULE hMods[1024];
                DWORD cbNeeded;
                if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
                    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                        char modName[MAX_PATH];
                        if (GetModuleFileNameExA(GetCurrentProcess(), hMods[i], modName, sizeof(modName))) {
                            if (GetModuleInformation(GetCurrentProcess(), hMods[i], &modInfo, sizeof(modInfo))) {
                                std::cout << "Trying to load symbol with explicit module size: " << modInfo.SizeOfImage << std::endl;
                                baseAddr = SymLoadModuleEx(hProcess, NULL, ansiModuleName, NULL, (DWORD64)moduleBase, modInfo.SizeOfImage, NULL, 0);
                                if (baseAddr != 0) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            
            if (baseAddr == 0 && GetLastError() != ERROR_SUCCESS) {
                std::cerr << "All attempts to load symbols for " << ansiModuleName << " failed." << std::endl;
                SymCleanup(hProcess);
                return false;
            }
        }
    }
    
    std::cout << ansiModuleName << " symbols loaded successfully." << std::endl;
    
    // Get the callback table address from symbols
    SYMBOL_INFO_PACKAGE symbolPackage = { 0 };
    symbolPackage.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolPackage.si.MaxNameLen = MAX_SYM_NAME;
    
    if (!SymFromName(hProcess, symbolName, &symbolPackage.si)) {
        DWORD error = GetLastError();
        std::cerr << "Failed to find symbol: " << symbolName << " in module " << ansiModuleName 
                  << ". Error code: " << error << std::endl;
        
        bool symbolFound = false;
        // Try getting the symbol another way for PDB files (enumeration)
        if (error == ERROR_NOT_FOUND || error == ERROR_MOD_NOT_FOUND) {
            std::cout << "Attempting to find symbol using enumeration..." << std::endl;
            
            // Initialize global variables for the callback
            g_LocalSymbolAddr = NULL;
            g_TargetSymbol = symbolName;
            
            // Enumerate all symbols looking for our target
            // Use baseAddr from SymLoadModuleEx
            if (SymEnumSymbols(hProcess, baseAddr, NULL, SymEnumCallback, NULL)) { 
                // Callback handles success/failure
            } else {
                 DWORD enumError = GetLastError();
                 // ERROR_SUCCESS means callback stopped enumeration (found or error in callback)
                 // ERROR_INVALID_ADDRESS might happen if baseAddr is bad
                 if (enumError != ERROR_SUCCESS && g_LocalSymbolAddr == NULL) {
                    std::cerr << "SymEnumSymbols failed. Error: " << enumError << std::endl;
                 }
            }

            if (g_LocalSymbolAddr != NULL) {
                std::cout << "Found symbol through enumeration: " << symbolName << " at 0x" << std::hex << g_LocalSymbolAddr << std::dec << std::endl;
                symbolPackage.si.Address = (ULONG64)g_LocalSymbolAddr;
                symbolFound = true;
            }
        }
        
        // If symbol lookup (direct and enumeration) failed, try hardcoded address
        // But only for ntoskrnl.exe since we only have hardcoded offsets for it
        if (!symbolFound && _wcsicmp(moduleName, L"ntoskrnl.exe") == 0) {
            std::cout << "Symbol lookup failed, attempting fallback using hardcoded offsets for ntoskrnl.exe..." << std::endl;
            PVOID hardcodedAddress = NULL;
            if (GetCallbackAddressByWindowsVersion(moduleBase, callbackType, hardcodedAddress)) {
                 symbolPackage.si.Address = (ULONG64)hardcodedAddress;
                 symbolFound = true;
                 std::cout << "Using hardcoded address: 0x" << std::hex << hardcodedAddress << std::dec << std::endl;
            } else {
                 std::cerr << "Failed to get hardcoded address for this Windows version." << std::endl;
            }
        }
        
        // If symbol lookup failed and no hardcoded address, we fail
        if (!symbolFound) { 
             SymCleanup(hProcess);
             return false;
        }

    } // End of if (!SymFromName(...))
    
    PVOID callbackTableAddress = (PVOID)symbolPackage.si.Address;
    // Make sure address is not null before proceeding
    if (!callbackTableAddress) {
        std::cerr << "Callback table address is NULL after lookup attempts." << std::endl;
        SymCleanup(hProcess);
        return false;
    }
    
    std::cout << "Using callback table address: 0x" << std::hex << callbackTableAddress << std::dec << std::endl;
    
    // Calculate required size for the request
    const ULONG maxCallbacks = 64; // Reasonable limit for kernel callbacks
    ULONG requestSize = sizeof(CALLBACK_ENUM_REQUEST) + (maxCallbacks - 1) * sizeof(CALLBACK_INFO_SHARED);
    
    // Allocate request buffer
    std::vector<BYTE> requestBuffer(requestSize, 0);
    PCALLBACK_ENUM_REQUEST request = reinterpret_cast<PCALLBACK_ENUM_REQUEST>(requestBuffer.data());
    
    // Initialize request
    request->Type = callbackType;
    request->TableAddress = callbackTableAddress;
    request->MaxCallbacks = maxCallbacks;
    
    // Send request to driver
    bytesReturned = 0;
    success = DeviceIoControl(
        deviceHandle,
        IOCTL_ENUM_CALLBACKS,
        request, requestSize,
        request, requestSize,
        &bytesReturned,
        nullptr
    );
    
    if (!success) {
        std::cerr << "Failed to enumerate callbacks via IOCTL. Error code: " << GetLastError() << std::endl;
        SymCleanup(hProcess);
        return false;
    }
    
    // Display results
    std::cout << "Retrieved " << request->FoundCallbacks << " callbacks from address 0x" 
              << std::hex << callbackTableAddress << std::dec << std::endl << std::endl;
    
    // Print callback information
    for (ULONG i = 0; i < request->FoundCallbacks; i++) {
        PrintSymbolCallbackInfo(request->Callbacks[i], hProcess);
    }
    
    SymCleanup(hProcess);
    return true;
}

// Function for testing symbol lookup
bool TestSymbolLookup(HANDLE deviceHandle) {
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    HANDLE hProcess = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG);

    if (!SymInitialize(hProcess, DEFAULT_SYMBOL_PATH, FALSE)) {
        std::cerr << "Failed to initialize symbols. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Get list of modules
    const DWORD bufferSize = sizeof(MODULE_INFO) * MAX_MODULES;
    std::vector<BYTE> buffer(bufferSize, 0);
    PMODULE_INFO moduleInfos = reinterpret_cast<PMODULE_INFO>(buffer.data());

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_GET_MODULES,
        NULL, 0,
        moduleInfos, bufferSize,
        &bytesReturned,
        NULL
    );

    if (!success) {
        std::cerr << "Failed to get modules. Error code: " << GetLastError() << std::endl;
        SymCleanup(hProcess);
        return false;
    }

    DWORD moduleCount = bytesReturned / sizeof(MODULE_INFO);
    PVOID ntosAddr = NULL;

    // Find ntoskrnl.exe
    for (DWORD i = 0; i < moduleCount; i++) {
        std::wstring path = moduleInfos[i].Path;
        std::transform(path.begin(), path.end(), path.begin(), ::towlower);

        if (path.find(L"ntoskrnl.exe") != std::wstring::npos || 
            path.find(L"ntkrnlmp.exe") != std::wstring::npos ||
            path.find(L"ntkrnlpa.exe") != std::wstring::npos) {
            ntosAddr = moduleInfos[i].BaseAddress;
            std::wcout << L"Found ntoskrnl at: 0x" << std::hex << ntosAddr << std::dec << std::endl;
            break;
        }
    }

    if (!ntosAddr) {
        std::cerr << "Failed to find ntoskrnl.exe module" << std::endl;
        SymCleanup(hProcess);
        return false;
    }

    // Load ntoskrnl symbols
    DWORD64 baseAddr = SymLoadModuleEx(hProcess, NULL, "ntoskrnl.exe", NULL, (DWORD64)ntosAddr, 0, NULL, 0);
    if (baseAddr == 0 && GetLastError() != ERROR_SUCCESS) {
        DWORD error = GetLastError();
        std::cerr << "Failed to load symbols for ntoskrnl.exe. Error code: " << error << std::endl;
        
        if (error == ERROR_MOD_NOT_FOUND) {
            std::cerr << "symsrv.dll load failure or symbols not found. Check symbol path." << std::endl;
        }
        
        SymCleanup(hProcess);
        return false;
    }

    std::cout << "Successfully loaded symbols at base: 0x" << std::hex << baseAddr << std::dec << std::endl;

    // Test looking up common symbols to verify symbol loading is working
    SYMBOL_INFO_PACKAGE symbolInfo = { 0 };
    symbolInfo.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo.si.MaxNameLen = MAX_SYM_NAME;

    // Try to find ExAllocatePool2 (available in Windows 10 20H1+)
    if (SymFromName(hProcess, "ExAllocatePool2", &symbolInfo.si)) {
        std::cout << "SUCCESS: Found ExAllocatePool2 at 0x" << std::hex << symbolInfo.si.Address << std::dec << std::endl;
    } else {
        std::cout << "ExAllocatePool2 not found, trying ExAllocatePoolWithTag..." << std::endl;
        // Try ExAllocatePoolWithTag (available in older Windows versions)
        if (SymFromName(hProcess, "ExAllocatePoolWithTag", &symbolInfo.si)) {
            std::cout << "SUCCESS: Found ExAllocatePoolWithTag at 0x" << std::hex << symbolInfo.si.Address << std::dec << std::endl;
        } else {
            std::cerr << "Failed to find either ExAllocatePool2 or ExAllocatePoolWithTag. Error: " << GetLastError() << std::endl;
            SymCleanup(hProcess);
            return false;
        }
    }

    // Try to find callback-related symbols
    bool foundCallbackSymbol = false;
    const char* callbackSymbols[] = {
        SYMBOL_LOAD_IMAGE_CALLBACKS,
        SYMBOL_PROCESS_CALLBACKS,
        SYMBOL_THREAD_CALLBACKS,
        SYMBOL_REGISTRY_CALLBACKS
    };

    for (const char* symbol : callbackSymbols) {
        if (SymFromName(hProcess, symbol, &symbolInfo.si)) {
            std::cout << "SUCCESS: Found " << symbol << " at 0x" << std::hex << symbolInfo.si.Address << std::dec << std::endl;
            foundCallbackSymbol = true;
            break;
        }
    }

    if (!foundCallbackSymbol) {
        std::cerr << "WARNING: Failed to find any callback symbols. Symbols might not be complete." << std::endl;
    }

    SymCleanup(hProcess);
    return true;
}

// Function to load symbols for critical kernel modules
bool LoadKernelModuleSymbols(HANDLE deviceHandle) {
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Initialize symbols
    HANDLE hProcess = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG);

    if (!SymInitialize(hProcess, DEFAULT_SYMBOL_PATH, FALSE)) {
        std::cerr << "Failed to initialize symbols. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Get list of modules
    const DWORD bufferSize = sizeof(MODULE_INFO) * MAX_MODULES;
    std::vector<BYTE> buffer(bufferSize, 0);
    PMODULE_INFO moduleInfos = reinterpret_cast<PMODULE_INFO>(buffer.data());

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_GET_MODULES,
        NULL, 0,
        moduleInfos, bufferSize,
        &bytesReturned,
        NULL
    );

    if (!success) {
        std::cerr << "Failed to get modules. Error code: " << GetLastError() << std::endl;
        SymCleanup(hProcess);
        return false;
    }

    DWORD moduleCount = bytesReturned / sizeof(MODULE_INFO);
    std::cout << "Found " << moduleCount << " kernel modules" << std::endl;

    // Define important kernel modules to load symbols for
    std::vector<std::wstring> importantModules = {
        L"ntoskrnl.exe", L"ntkrnlmp.exe", L"ntkrnlpa.exe", // Windows kernel variations
        L"hal.dll",                                        // Hardware Abstraction Layer
        L"win32k.sys",                                     // Win32 subsystem
        L"ndis.sys",                                       // Network Driver Interface
        L"tcpip.sys"                                       // TCP/IP stack
    };

    int modulesLoaded = 0;

    for (DWORD i = 0; i < moduleCount; i++) {
        std::wstring path = moduleInfos[i].Path;
        std::wstring lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

        // Check if this is an important module
        bool isImportant = false;
        for (const auto& module : importantModules) {
            if (lowerPath.find(module) != std::wstring::npos) {
                isImportant = true;
                break;
            }
        }

        if (isImportant) {
            // Extract filename from path
            std::wstring fileName = path;
            size_t lastSlash = fileName.find_last_of(L"/\\");
            if (lastSlash != std::wstring::npos) {
                fileName = fileName.substr(lastSlash + 1);
            }

            char ansiFileName[MAX_PATH] = {0};
            WideCharToMultiByte(CP_ACP, 0, fileName.c_str(), -1, ansiFileName, MAX_PATH, NULL, NULL);

            std::cout << "Loading symbols for " << ansiFileName << " at 0x" 
                     << std::hex << moduleInfos[i].BaseAddress << std::dec << "..." << std::endl;

            DWORD64 baseAddr = SymLoadModuleEx(
                hProcess, 
                NULL, 
                ansiFileName, 
                NULL, 
                (DWORD64)moduleInfos[i].BaseAddress, 
                moduleInfos[i].Size, 
                NULL, 
                0
            );

            if (baseAddr == 0 && GetLastError() != ERROR_SUCCESS) {
                DWORD error = GetLastError();
                std::cerr << "  Failed to load symbols. Error code: " << error << std::endl;
            } else {
                std::cout << "  Symbols loaded successfully." << std::endl;
                modulesLoaded++;
            }
        }
    }

    std::cout << "Loaded symbols for " << modulesLoaded << " important kernel modules." << std::endl;

    // Test if symbols are working by looking up some well-known functions
    SYMBOL_INFO_PACKAGE symbolInfo = { 0 };
    symbolInfo.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo.si.MaxNameLen = MAX_SYM_NAME;

    if (SymFromName(hProcess, "ExAllocatePool2", &symbolInfo.si) || 
        SymFromName(hProcess, "ExAllocatePoolWithTag", &symbolInfo.si)) {
        std::cout << "Symbol lookup test successful." << std::endl;
    } else {
        std::cerr << "WARNING: Symbol lookup test failed. Symbols might not be working correctly." << std::endl;
    }

    // Keep symbols initialized for future use
    return modulesLoaded > 0;
}

// Function to let the user select a module and dump its symbols to a file
void DumpAllSymbolsToFile(HANDLE deviceHandle) {
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "Invalid device handle." << std::endl;
        return;
    }

    // Get list of modules
    const DWORD bufferSize = sizeof(MODULE_INFO) * MAX_MODULES;
    std::vector<BYTE> buffer(bufferSize, 0);
    PMODULE_INFO moduleInfos = reinterpret_cast<PMODULE_INFO>(buffer.data());

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_GET_MODULES,
        NULL, 0,
        moduleInfos, bufferSize,
        &bytesReturned,
        NULL
    );

    if (!success) {
        std::cerr << "Failed to get modules. Error code: " << GetLastError() << std::endl;
        return;
    }

    DWORD moduleCount = bytesReturned / sizeof(MODULE_INFO);

    if (moduleCount == 0) {
        std::cerr << "No modules found." << std::endl;
        return;
    }

    std::cout << "\n=== Available Kernel Modules ===\n" << std::endl;
    for (DWORD i = 0; i < moduleCount; i++) {
        std::wcout << i << ": " << moduleInfos[i].Path << std::endl;
    }

    // Ask the user to select a module
    DWORD selection = 0;
    do {
        std::cout << "\nEnter module number to dump symbols (0-" << moduleCount - 1 << "), or -1 to cancel: ";
        std::cin >> selection;
        
        if (selection == -1) {
            std::cout << "Symbol dump canceled." << std::endl;
            return;
        }
    } while (selection >= moduleCount);

    // Create the SymbolDumps directory if it doesn't exist
    CreateDirectoryA("SymbolDumps", NULL);

    // Extract module filename for the output file name
    std::wstring fileName = moduleInfos[selection].Path;
    size_t lastSlash = fileName.find_last_of(L"/\\");
    if (lastSlash != std::wstring::npos) {
        fileName = fileName.substr(lastSlash + 1);
    }

    char ansiFileName[MAX_PATH] = {0};
    WideCharToMultiByte(CP_ACP, 0, fileName.c_str(), -1, ansiFileName, MAX_PATH, NULL, NULL);

    std::string outputFilePath = "SymbolDumps\\";
    outputFilePath += ansiFileName;
    outputFilePath += ".txt";

    std::cout << "Dumping symbols for " << ansiFileName << " to " << outputFilePath << "..." << std::endl;

    if (DumpModuleSymbolsToFile(deviceHandle, moduleInfos[selection].Path, outputFilePath.c_str())) {
        std::cout << "Symbol dump completed successfully. Output saved to " << outputFilePath << std::endl;
    } else {
        std::cerr << "Symbol dump failed." << std::endl;
    }
}

// Helper function to dump symbols for a specific module
bool DumpModuleSymbolsToFile(HANDLE deviceHandle, const wchar_t* moduleName, const char* outputFilename) {
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Initialize symbols
    HANDLE hProcess = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG);
    
    if (!SymInitialize(hProcess, DEFAULT_SYMBOL_PATH, FALSE)) {
        std::cerr << "Failed to initialize symbols. Error code: " << GetLastError() << std::endl;
        return false;
    }
    
    // Get list of modules
    const DWORD bufferSize = sizeof(MODULE_INFO) * MAX_MODULES;
    std::vector<BYTE> buffer(bufferSize, 0);
    PMODULE_INFO moduleInfos = reinterpret_cast<PMODULE_INFO>(buffer.data());

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_GET_MODULES,
        moduleInfos, bufferSize,
        moduleInfos, bufferSize,
        &bytesReturned,
        nullptr
    );
    
    if (!success) {
        std::cerr << "Failed to get modules. Error code: " << GetLastError() << std::endl;
        SymCleanup(hProcess);
        return false;
    }
    
    DWORD moduleCount = bytesReturned / sizeof(MODULE_INFO);
    
    // Find the module
    bool moduleFound = false;
    PVOID moduleBase = NULL;
    DWORD64 moduleSize = 0;
    
    for (DWORD i = 0; i < moduleCount; i++) {
        std::wstring modulePath = moduleInfos[i].Path;
        std::transform(modulePath.begin(), modulePath.end(), modulePath.begin(), ::towlower);
        
        std::wstring nameToFind = moduleName;
        std::transform(nameToFind.begin(), nameToFind.end(), nameToFind.begin(), ::towlower);
        
        if (modulePath.find(nameToFind) != std::wstring::npos) {
            moduleBase = moduleInfos[i].BaseAddress;
            moduleSize = moduleInfos[i].Size;
            moduleFound = true;
            std::wcout << L"Found module " << moduleName << L" at address: 0x" << std::hex << moduleBase 
                       << std::dec << L" with size: " << moduleSize << std::endl;
            break;
        }
    }
    
    if (!moduleFound || !moduleBase) {
        std::wcerr << L"Failed to find module: " << moduleName << std::endl;
        SymCleanup(hProcess);
        return false;
    }
    
    // Extract just the filename for symbol loading
    std::wstring fileName = std::wstring(moduleName);
    size_t lastSlash = fileName.find_last_of(L"/\\");
    if (lastSlash != std::wstring::npos) {
        fileName = fileName.substr(lastSlash + 1);
    }
    
    char ansiModuleName[MAX_PATH] = {0};
    WideCharToMultiByte(CP_ACP, 0, fileName.c_str(), -1, ansiModuleName, MAX_PATH, NULL, NULL);
    
    // Load module symbols
    std::cout << "Loading symbols for " << ansiModuleName << "..." << std::endl;
    DWORD64 baseAddr = SymLoadModuleEx(hProcess, NULL, ansiModuleName, NULL, (DWORD64)moduleBase, moduleSize, NULL, 0);
    
    if (baseAddr == 0 && GetLastError() != ERROR_SUCCESS) {
        DWORD error = GetLastError();
        std::cerr << "Failed to load symbols for " << ansiModuleName << ". Error code: " << error << std::endl;
        SymCleanup(hProcess);
        return false;
    }
    
    std::cout << "Successfully loaded symbols at base: 0x" << std::hex << baseAddr << std::dec << std::endl;
    
    // Open the output file
    std::ofstream outputFile(outputFilename);
    if (!outputFile.is_open()) {
        std::cerr << "Failed to create output file: " << outputFilename << std::endl;
        SymCleanup(hProcess);
        return false;
    }
    
    // Write header to the file
    time_t now = time(0);
    outputFile << "===== Symbol Dump for " << ansiModuleName << " =====" << std::endl;
    outputFile << "Timestamp: " << ctime(&now) << std::endl;
    outputFile << "Module Base: 0x" << std::hex << moduleBase << std::dec << std::endl;
    outputFile << "Module Size: " << moduleSize << " bytes" << std::endl;
    outputFile << std::endl;
    
    // Enumerate symbols
    struct SYMBOL_CONTEXT {
        std::ofstream* file;
        int count;
    };
    
    SYMBOL_CONTEXT context = { &outputFile, 0 };
    
    auto enumSymbolsCallback = [](PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) -> BOOL {
        SYMBOL_CONTEXT* ctx = static_cast<SYMBOL_CONTEXT*>(UserContext);
        std::ofstream& file = *ctx->file;
        
        // Write symbol info to file
        file << std::hex << "0x" << pSymInfo->Address << std::dec;
        file << " | " << pSymInfo->Size << " bytes | ";
        file << pSymInfo->Name << std::endl;
        
        ctx->count++;
        return TRUE;
    };
    
    std::cout << "Enumerating symbols... " << std::endl;
    if (!SymEnumSymbols(hProcess, baseAddr, "*", enumSymbolsCallback, &context)) {
        DWORD error = GetLastError();
        std::cerr << "Error enumerating symbols: " << error << std::endl;
        outputFile << "ERROR: Failed to enumerate symbols. Error code: " << error << std::endl;
    }
    
    std::cout << "Found " << context.count << " symbols." << std::endl;
    outputFile << "\nTotal symbols found: " << context.count << std::endl;
    outputFile << "===== End of Symbol Dump =====" << std::endl;
    
    outputFile.close();
    SymCleanup(hProcess);
    
    return context.count > 0;
}

int main() {
    std::cout << "Elemetry Client - Driver Module and Callback Enumerator" << std::endl;
    std::cout << "========================================================" << std::endl << std::endl;

    // Open a handle to the driver
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open driver handle." << std::endl;
        return 1;
    }

    // Test if symbol handling works with the new SDK configuration
    std::cout << "Testing symbol lookup with new SDK configuration..." << std::endl;
    bool symbolsWorking = TestSymbolLookup(deviceHandle);
    std::cout << "Symbol test result: " << (symbolsWorking ? "SUCCESS" : "FAILURE") << std::endl << std::endl;

    // Load symbols for other kernel modules
    std::cout << "\n===========================================" << std::endl;
    std::cout << "Loading symbols for other kernel modules..." << std::endl;
    std::cout << "===========================================" << std::endl;
    LoadKernelModuleSymbols(deviceHandle);

    // Menu loop for different operations
    bool running = true;
    while (running) {
        std::cout << std::endl;
        std::cout << "Available operations:" << std::endl;
        std::cout << "1. Enumerate kernel modules" << std::endl;
        std::cout << "2. Enumerate kernel callbacks" << std::endl;
        std::cout << "3. Dump all kernel symbols to file" << std::endl;
        std::cout << "0. Exit" << std::endl;
        std::cout << std::endl;
        std::cout << "Select an operation (0-3): ";
        
        int choice = 0;
        std::cin >> choice;
        
        switch (choice) {
            case 0:
                running = false;
                break;
                
            case 1:
                std::cout << std::endl << "Enumerating kernel modules..." << std::endl;
                GetDriverModules();
                break;
                
            case 2:
                std::cout << std::endl << "Enumerating kernel callbacks..." << std::endl;
                GetDriverCallbacks();
                break;
                
            case 3:
                std::cout << std::endl << "Dumping kernel symbols to file..." << std::endl;
                DumpAllSymbolsToFile(deviceHandle);
                break;
                
            default:
                std::cout << "Invalid option. Please try again." << std::endl;
                break;
        }
    }

    CloseHandle(deviceHandle);
    std::cout << "Operation completed successfully." << std::endl;
    return 0;
} 