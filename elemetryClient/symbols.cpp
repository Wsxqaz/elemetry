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
#include "symbols.h"
#include "utils.h"

const char* DEFAULT_SYMBOL_PATH = "srv*C:\\Windows\\System32*https://msdl.microsoft.com/download/symbols";

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

size_t LookupSymbol(HANDLE deviceHandle, const char* symbolName, DWORD64& address) {
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
        return -1;
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
        return -1;
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
        return -1;
    }

    // Look up the callback table symbol
    SYMBOL_INFO_PACKAGE symbolInfo = { 0 };
    symbolInfo.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo.si.MaxNameLen = MAX_SYM_NAME;

    if (!SymFromName(hProcess, symbolName, &symbolInfo.si)) {
        std::cerr << "Failed to find symbol: " << symbolName << ". Error code: " << GetLastError() << std::endl;
        SymCleanup(hProcess);
        return -1;
    }

    std::cout << "Found symbol " << symbolName << " at address: 0x"
              << std::hex << symbolInfo.si.Address << std::dec << std::endl;

    // write symbol address to output parameter
    address = symbolInfo.si.Address;

    return symbolInfo.si.Address;
}

