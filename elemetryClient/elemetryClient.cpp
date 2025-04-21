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
#define CLIENT_MAX_MODULES 512  // Renamed to avoid conflict
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
const char* DEFAULT_SYMBOL_PATH = "srv*C:\\Windows\\System32*https://msdl.microsoft.com/download/symbols";
const char* SYSTEM32_PATH = "C:\\Windows\\System32\\";  // Path to system32 directory

// Primary symbol names for callback tables
const char* SYMBOL_LOAD_IMAGE_CALLBACKS = "PspLoadImageNotifyRoutine";
const char* SYMBOL_PROCESS_CALLBACKS = "PspCreateProcessNotifyRoutine";
const char* SYMBOL_THREAD_CALLBACKS = "PspCreateThreadNotifyRoutine";
const char* SYMBOL_REGISTRY_CALLBACKS = "CmCallbackListHead";

// Alternative registry callback symbol names for different Windows versions
const char* ALT_REGISTRY_CALLBACKS[] = {
    "CmCallbackListHead",           // Standard symbol
    "CallbackListHead",             // Alternative name
    "CmpCallbackListHead",          // Another variant
    "CmRegistryCallbackList",       // Another possible name
    "CallbackListHeadEx",           // Windows 10+ variant
    "CmpCallbackListLock",          // Often used in recent Windows versions
    "CmpRegistryCallbacks",         // Another name in newer builds
    "_CmCallbackListHead"           // Sometimes prefixed with an underscore
};
const int ALT_REGISTRY_COUNT = 8;

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


// Forward Declarations
bool TestSymbolLookup(HANDLE deviceHandle);
bool LoadKernelModuleSymbols(HANDLE deviceHandle);

// Callback function for SymEnumSymbols
BOOL CALLBACK SymEnumCallback(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) {
    if (strcmp(pSymInfo->Name, g_TargetSymbol) == 0) {
        g_LocalSymbolAddr = (PVOID)pSymInfo->Address;
        return FALSE; // Stop enumeration, we found it
    }
    return TRUE; // Continue enumeration
}

// Function to check if a file exists
bool FileExists(const std::string& filePath) {
    return std::filesystem::exists(filePath);
}

// Function to get the path to ntoskrnl.exe
std::string GetNtoskrnlPath() {
    // First, check current directory
    if (FileExists("ntoskrnl.exe")) {
        return "ntoskrnl.exe";
    }

    // Then check System32
    std::string system32Path = SYSTEM32_PATH;
    std::string ntoskrnlSystem32 = system32Path + "ntoskrnl.exe";
    if (FileExists(ntoskrnlSystem32)) {
        return ntoskrnlSystem32;
    }

    // Try other possible kernel names in System32
    std::string ntkrnlmpSystem32 = system32Path + "ntkrnlmp.exe";
    if (FileExists(ntkrnlmpSystem32)) {
        return ntkrnlmpSystem32;
    }

    std::string ntkrnlpaSystem32 = system32Path + "ntkrnlpa.exe";
    if (FileExists(ntkrnlpaSystem32)) {
        return ntkrnlpaSystem32;
    }

    // Not found
    return "";
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

// Function to get minifilter callback type as string
// Updated to accept CALLBACK_TYPE instead of MINIFILTER_CALLBACK_TYPE
std::string GetMinifilterCallbackTypeString(CALLBACK_TYPE type) {
    switch (type) {
        // Map CALLBACK_TYPE values to descriptive strings
    case CALLBACK_TYPE::Unknown: return "Unknown";
    case CALLBACK_TYPE::FsPreCreate: return "PreCreate";
    case CALLBACK_TYPE::FsPostCreate: return "PostCreate";
    case CALLBACK_TYPE::FsPreClose: return "PreClose";
    case CALLBACK_TYPE::FsPostClose: return "PostClose";
    case CALLBACK_TYPE::FsPreRead: return "PreRead";
    case CALLBACK_TYPE::FsPostRead: return "PostRead";
    case CALLBACK_TYPE::FsPreWrite: return "PreWrite";
    case CALLBACK_TYPE::FsPostWrite: return "PostWrite";
    case CALLBACK_TYPE::FsPreQueryInfo: return "PreQueryInformation";
    case CALLBACK_TYPE::FsPostQueryInfo: return "PostQueryInformation";
    case CALLBACK_TYPE::FsPreSetInfo: return "PreSetInformation";
    case CALLBACK_TYPE::FsPostSetInfo: return "PostSetInformation";
    case CALLBACK_TYPE::FsPreDirCtrl: return "PreDirectoryControl";
    case CALLBACK_TYPE::FsPostDirCtrl: return "PostDirectoryControl";
    case CALLBACK_TYPE::FsPreFsCtrl: return "PreFileSystemControl";
    case CALLBACK_TYPE::FsPostFsCtrl: return "PostFileSystemControl";
    // Add cases for other CALLBACK_TYPE members if needed
    case CALLBACK_TYPE::PsLoadImage: return "PsLoadImage";
    case CALLBACK_TYPE::PsProcessCreation: return "PsProcessCreation";
    case CALLBACK_TYPE::PsThreadCreation: return "PsThreadCreation";
    case CALLBACK_TYPE::CmRegistry: return "CmRegistry";
    case CALLBACK_TYPE::ObProcessHandlePre: return "ObProcessHandlePre";
    case CALLBACK_TYPE::ObProcessHandlePost: return "ObProcessHandlePost";
    case CALLBACK_TYPE::ObThreadHandlePre: return "ObThreadHandlePre";
    case CALLBACK_TYPE::ObThreadHandlePost: return "ObThreadHandlePost";
    default: return "Other/Unknown"; // Default case for unmapped types
    }
}

// Function to print callback information
void PrintCallbackInfo(const CALLBACK_INFO_SHARED& callbackInfo) {
    std::cout << "Callback: " << callbackInfo.CallbackName << std::endl;
    std::cout << "  Type: " << GetMinifilterCallbackTypeString(callbackInfo.Type) << std::endl;
    std::cout << "  Address: 0x" << std::hex << callbackInfo.Address << std::dec << std::endl;
    std::cout << "  Module: " << callbackInfo.ModuleName << std::endl;
    std::cout << std::endl;
}

// Function to write callback information to a file
void WriteCallbackToFile(std::ofstream& outFile, const CALLBACK_INFO_SHARED& callbackInfo) {
    outFile << "Callback: " << callbackInfo.CallbackName << std::endl;
    outFile << "  Type: " << GetMinifilterCallbackTypeString(callbackInfo.Type) << std::endl;
    outFile << "  Address: 0x" << std::hex << callbackInfo.Address << std::dec << std::endl;
    outFile << "  Module: " << callbackInfo.ModuleName << std::endl;
    outFile << std::endl;
}

// Function to get and display modules from the driver
bool GetDriverModules() {
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Allocate buffer for module information
    const DWORD bufferSize = sizeof(MODULE_INFO) * CLIENT_MAX_MODULES;
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
    const DWORD bufferSize = sizeof(MODULE_INFO) * CLIENT_MAX_MODULES;
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

    // Get path to ntoskrnl.exe
    std::string ntoskrnlPath = GetNtoskrnlPath();
    if (ntoskrnlPath.empty()) {
        std::cerr << "Warning: Could not find ntoskrnl.exe in current directory or System32. Using default name." << std::endl;
        ntoskrnlPath = "ntoskrnl.exe";
    } else {
        std::cout << "Using ntoskrnl.exe from: " << ntoskrnlPath << std::endl;
    }

    // Load ntoskrnl symbols
    DWORD64 baseAddr = SymLoadModuleEx(hProcess, NULL, ntoskrnlPath.c_str(), NULL, (DWORD64)ntosAddr, 0, NULL, 0);
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
    const DWORD bufferSize = sizeof(MODULE_INFO) * CLIENT_MAX_MODULES;
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

    // For ntoskrnl.exe, use our special function to find it in System32 if needed
    std::string ntoskrnlPath = GetNtoskrnlPath();
    if (!ntoskrnlPath.empty()) {
        std::cout << "Using ntoskrnl.exe from: " << ntoskrnlPath << std::endl;
    }

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

            // Use the full path for ntoskrnl if we found it earlier
            const char* symbolFilePath = ansiFileName;
            std::string fullPath;

            if ((lowerPath.find(L"ntoskrnl.exe") != std::wstring::npos ||
                 lowerPath.find(L"ntkrnlmp.exe") != std::wstring::npos ||
                 lowerPath.find(L"ntkrnlpa.exe") != std::wstring::npos) &&
                !ntoskrnlPath.empty()) {
                symbolFilePath = ntoskrnlPath.c_str();
            } else if (lowerPath.find(L"hal.dll") != std::wstring::npos) {
                // Also check System32 for HAL.dll
                fullPath = std::string(SYSTEM32_PATH) + "hal.dll";
                if (FileExists(fullPath)) {
                    symbolFilePath = fullPath.c_str();
                }
            }

            DWORD64 baseAddr = SymLoadModuleEx(
                hProcess,
                NULL,
                symbolFilePath,
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

// Function to enumerate callbacks with symbol lookup
bool EnumerateCallbacksWithSymbolTable(HANDLE deviceHandle, CALLBACK_TABLE_TYPE tableType, const char* symbolName) {
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "Invalid device handle." << std::endl;
        return false;
    }

    // Initialize symbols
    HANDLE hProcess = GetCurrentProcess();

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG);

    if (!SymInitialize(hProcess, DEFAULT_SYMBOL_PATH, FALSE)) {
        std::cerr << "Failed to initialize symbols. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Get ntoskrnl.exe base address
    const DWORD bufferSize = sizeof(MODULE_INFO) * CLIENT_MAX_MODULES;
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

    // Get path to ntoskrnl.exe
    std::string ntoskrnlPath = GetNtoskrnlPath();
    if (ntoskrnlPath.empty()) {
        std::cerr << "Warning: Could not find ntoskrnl.exe in current directory or System32. Using default name." << std::endl;
        ntoskrnlPath = "ntoskrnl.exe";
    } else {
        std::cout << "Using ntoskrnl.exe from: " << ntoskrnlPath << std::endl;
    }

    // Load ntoskrnl symbols
    DWORD64 baseAddr = SymLoadModuleEx(hProcess, NULL, ntoskrnlPath.c_str(), NULL, (DWORD64)ntosAddr, 0, NULL, 0);
    if (baseAddr == 0 && GetLastError() != ERROR_SUCCESS) {
        std::cerr << "Failed to load symbols for ntoskrnl.exe. Error code: " << GetLastError() << std::endl;
        SymCleanup(hProcess);
        return false;
    }

    // Look up the callback table symbol
    SYMBOL_INFO_PACKAGE symbolInfo = { 0 };
    symbolInfo.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo.si.MaxNameLen = MAX_SYM_NAME;

    if (!SymFromName(hProcess, symbolName, &symbolInfo.si)) {
        std::cerr << "Failed to find symbol: " << symbolName << ". Error code: " << GetLastError() << std::endl;
        SymCleanup(hProcess);
        return false;
    }

    std::cout << "Found symbol " << symbolName << " at address: 0x"
              << std::hex << symbolInfo.si.Address << std::dec << std::endl;

    // Prepare the request to enumerate callbacks
    PVOID callbackTable = (PVOID)symbolInfo.si.Address;

    // Calculate required size for the request
    const ULONG maxCallbacks = 64; // Reasonable limit for kernel callbacks
    ULONG requestSize = sizeof(CALLBACK_ENUM_REQUEST) + (maxCallbacks - 1) * sizeof(CALLBACK_INFO_SHARED);

    // Allocate request buffer
    std::vector<BYTE> requestBuffer(requestSize, 0);
    PCALLBACK_ENUM_REQUEST request = reinterpret_cast<PCALLBACK_ENUM_REQUEST>(requestBuffer.data());

    // Initialize request
    request->Type = tableType;
    request->TableAddress = callbackTable;
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
        std::cerr << "Failed to enumerate callbacks. Error code: " << GetLastError() << std::endl;
        SymCleanup(hProcess);
        return false;
    }

    // Display results
    std::cout << "Retrieved " << request->FoundCallbacks << " callbacks from "
              << symbolName << " at address 0x" << std::hex << callbackTable << std::dec << std::endl;

    // Determine callback type string for display
    std::string callbackTypeStr;
    switch (tableType) {
        case CallbackTableLoadImage:
            callbackTypeStr = "Load Image";
            break;
        case CallbackTableCreateProcess:
            callbackTypeStr = "Process Creation";
            break;
        case CallbackTableCreateThread:
            callbackTypeStr = "Thread Creation";
            break;
        case CallbackTableRegistry:
            callbackTypeStr = "Registry";
            break;
        default:
            callbackTypeStr = "Unknown";
            break;
    }

    std::cout << std::endl << "==== " << callbackTypeStr << " Callbacks ====" << std::endl << std::endl;

    // Print callback information
    for (ULONG i = 0; i < request->FoundCallbacks; i++) {
        PCALLBACK_INFO_SHARED info = &request->Callbacks[i];

        std::cout << "[" << i << "] Callback in " << info->ModuleName << std::endl;
        std::cout << "    Name: " << info->CallbackName << std::endl;
        std::cout << "    Address: 0x" << std::hex << info->Address << std::dec << std::endl;

        // Try to get symbol information if possible
        char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)symbolBuffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (SymFromAddr(hProcess, (DWORD64)info->Address, &displacement, pSymbol)) {
            std::cout << "    Symbol: " << pSymbol->Name;
            if (displacement > 0) {
                std::cout << " + 0x" << std::hex << displacement << std::dec;
            }
            std::cout << std::endl;
        }

        std::cout << std::endl;
    }

    SymCleanup(hProcess);
    return true;
}

// Function to try multiple registry callback symbol names
bool TryEnumerateRegistryCallbacks(HANDLE deviceHandle) {
    std::cout << std::endl << "Enumerating registry callbacks..." << std::endl;

    // Try each symbol name in the ALT_REGISTRY_CALLBACKS array
    for (int i = 0; i < ALT_REGISTRY_COUNT; i++) {
        std::cout << "Trying symbol: " << ALT_REGISTRY_CALLBACKS[i] << std::endl;
        if (EnumerateCallbacksWithSymbolTable(deviceHandle, CallbackTableRegistry, ALT_REGISTRY_CALLBACKS[i])) {
            std::cout << "Successfully enumerated registry callbacks using symbol: " << ALT_REGISTRY_CALLBACKS[i] << std::endl;
            return true;
        }
        std::cout << "Failed with symbol: " << ALT_REGISTRY_CALLBACKS[i] << std::endl;
    }

    std::cout << "All registry callback enumeration methods failed." << std::endl;
    std::cout << "Please ensure symbols are properly configured and try again." << std::endl;
    return false;
}

// Function to get and display minifilter callbacks from the driver
bool GetDriverMinifilterCallbacks() {
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Calculate buffer size for the request
    const DWORD maxCallbacks = MAX_CALLBACKS_SHARED;
    const DWORD requestSize = FIELD_OFFSET(CALLBACK_ENUM_REQUEST, Callbacks) +
                              (maxCallbacks * sizeof(CALLBACK_INFO_SHARED));

    // Allocate buffer
    std::vector<BYTE> buffer(requestSize, 0);
    PCALLBACK_ENUM_REQUEST request = reinterpret_cast<PCALLBACK_ENUM_REQUEST>(buffer.data());

    // Set up request
    request->Type = CallbackTableFilesystem;
    request->TableAddress = nullptr; // Not needed for minifilters
    request->MaxCallbacks = maxCallbacks;
    request->FoundCallbacks = 0;

    // Set up request structure for input
    CALLBACK_ENUM_REQUEST inputRequest = { 0 };
    inputRequest.Type = CallbackTableFilesystem;
    inputRequest.TableAddress = nullptr; // Not needed for minifilters
    inputRequest.MaxCallbacks = maxCallbacks;

    // Allocate buffer for output
    DWORD outputBufferSize = sizeof(CALLBACK_ENUM_REQUEST) + (maxCallbacks * sizeof(CALLBACK_INFO_SHARED));
    std::vector<BYTE> outputBuffer(outputBufferSize, 0);
    PCALLBACK_ENUM_REQUEST response = reinterpret_cast<PCALLBACK_ENUM_REQUEST>(outputBuffer.data());

    // Send IOCTL to get minifilter callbacks
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_ENUM_CALLBACKS,
        &inputRequest, sizeof(inputRequest), // Input buffer (fixed size)
        response, outputBufferSize,          // Output buffer
        &bytesReturned,
        nullptr
    );

    if (!success) {
        std::cerr << "DeviceIoControl failed. Error code: " << GetLastError() << std::endl;
        CloseHandle(deviceHandle);
        return false;
    }

    // Check how many callbacks were actually returned by the driver
    if (bytesReturned < FIELD_OFFSET(CALLBACK_ENUM_REQUEST, Callbacks)) {
        std::cerr << "DeviceIoControl returned insufficient data size: " << bytesReturned << std::endl;
        CloseHandle(deviceHandle);
        return false;
    }
    DWORD foundCallbacks = response->FoundCallbacks; // Get count from response struct

    // Print results
    std::cout << "Retrieved " << foundCallbacks << " minifilter callbacks:" << std::endl << std::endl;
    for (DWORD i = 0; i < foundCallbacks; i++) {
        PrintCallbackInfo(response->Callbacks[i]);
    }

    // Create a file name with timestamp for exporting
    std::string fileBaseName = "elemetry_minifilter_";
    SYSTEMTIME st;
    GetLocalTime(&st);
    char timeStr[100];
    sprintf_s(timeStr, sizeof(timeStr), "%04d%02d%02d_%02d%02d%02d",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    fileBaseName += timeStr;
    fileBaseName += ".txt";

    // Set the path to current directory
    std::string fileName = fileBaseName;

    // Open output file
    std::ofstream outFile(fileName);
    if (outFile.is_open()) {
        // Write header
        outFile << "Elemetry Minifilter Callback Enumeration Results" << std::endl;
        outFile << "=============================================" << std::endl;
        outFile << "Total minifilter callbacks found: " << foundCallbacks << std::endl;
        outFile << "Date/Time: " << timeStr << std::endl << std::endl;

        // Write callback details
        for (DWORD i = 0; i < foundCallbacks; i++) {
            WriteCallbackToFile(outFile, response->Callbacks[i]);
        }

        // Add summary of module sources
        outFile << "\nCallback Source Summary:" << std::endl;
        outFile << "----------------------" << std::endl;

        std::unordered_map<std::string, int> moduleCounts;
        for (DWORD i = 0; i < foundCallbacks; i++) {
            std::string moduleName = response->Callbacks[i].ModuleName;
            moduleCounts[moduleName]++;
        }

        for (const auto& pair : moduleCounts) {
            outFile << pair.first << ": " << pair.second << " callbacks" << std::endl;
        }

        std::cout << "Results successfully written to " << fileName << std::endl;
        outFile.close();
    }

    CloseHandle(deviceHandle);
    return true;
}

// Main function - update with additional menu options
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
    while (true) {
        std::cout << std::endl;
        std::cout << "Available operations:" << std::endl;
        std::cout << "1. Enumerate kernel modules" << std::endl;
        std::cout << "2. Enumerate load image callbacks (PspLoadImageNotifyRoutine)" << std::endl;
        std::cout << "3. Enumerate process creation callbacks (PspCreateProcessNotifyRoutine)" << std::endl;
        std::cout << "4. Enumerate thread creation callbacks (PspCreateThreadNotifyRoutine)" << std::endl;
        std::cout << "5. Enumerate registry callbacks (CmCallbackListHead)" << std::endl;
        std::cout << "6. Enumerate minifilter callbacks" << std::endl;
        std::cout << "0. Exit" << std::endl;
        std::cout << std::endl;
        std::cout << "Select an operation (0-6): ";

        int choice;
        std::cin >> choice;

        if (choice == 0) {
            break;
        }

        switch (choice) {
            case 1:
                std::cout << std::endl << "Enumerating kernel modules..." << std::endl;
                GetDriverModules();
                break;

            case 2:
                std::cout << std::endl << "Enumerating load image callbacks..." << std::endl;
                EnumerateCallbacksWithSymbolTable(deviceHandle, CallbackTableLoadImage, SYMBOL_LOAD_IMAGE_CALLBACKS);
                break;

            case 3:
                std::cout << std::endl << "Enumerating process creation callbacks..." << std::endl;
                EnumerateCallbacksWithSymbolTable(deviceHandle, CallbackTableCreateProcess, SYMBOL_PROCESS_CALLBACKS);
                break;

            case 4:
                std::cout << std::endl << "Enumerating thread creation callbacks..." << std::endl;
                EnumerateCallbacksWithSymbolTable(deviceHandle, CallbackTableCreateThread, SYMBOL_THREAD_CALLBACKS);
                break;

            case 5:
                // Use our new function that tries multiple symbol names
                TryEnumerateRegistryCallbacks(deviceHandle);
                break;

            case 6:
                std::cout << std::endl << "Enumerating minifilter callbacks..." << std::endl;
                GetDriverMinifilterCallbacks();
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
