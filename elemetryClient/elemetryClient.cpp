#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <unordered_map>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <mutex>  // Add mutex header
#include <DbgHelp.h>
#include <Psapi.h>  // For EnumProcessModules, GetModuleInformation
#include <commctrl.h>
#include <stdio.h>
#include <strsafe.h>
#include <dbghelp.h>
#include <TlHelp32.h>
#include "SharedDefs.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")  // Link against psapi.lib

// Windows UI headers
#include <tchar.h>
#include <windowsx.h>

// Global variables
HINSTANCE g_hInst;

// Window handles structure
struct WINDOW_HANDLES {
    HWND Main;
    HWND StatusBar;
    HWND TabControl;

    // Modules Tab
    HWND ModulesPage;
    HWND ModulesRefreshButton;
    HWND ModulesCountLabel;
    HWND ModulesListView;
    HMENU ModulesContextMenu;

    // Process Callbacks Tab
    HWND ProcessCallbacksPage;
    HWND ProcessCallbacksRefreshButton;
    HWND ProcessCallbacksCountLabel;
    HWND ProcessCallbacksListView;
    HMENU ProcessCallbacksContextMenu;
    
    // Thread Callbacks Tab
    HWND ThreadCallbacksPage;
    HWND ThreadCallbacksRefreshButton;
    HWND ThreadCallbacksCountLabel;
    HWND ThreadCallbacksListView;
    HMENU ThreadCallbacksContextMenu;
    
    // Registry Callbacks Tab
    HWND RegistryCallbacksPage;
    HWND RegistryCallbacksRefreshButton;
    HWND RegistryCallbacksCountLabel;
    HWND RegistryCallbacksListView;
    HMENU RegistryCallbacksContextMenu;
    
    // Filesystem Callbacks Tab
    HWND FilesystemCallbacksPage;
    HWND FilesystemCallbacksRefreshButton;
    HWND FilesystemCallbacksCountLabel;
    HWND FilesystemCallbacksListView;
    HMENU FilesystemCallbacksContextMenu;
    
    // Object Callbacks Tab
    HWND ObjectCallbacksPage;
    HWND ObjectCallbacksRefreshButton;
    HWND ObjectCallbacksCountLabel;
    HWND ObjectCallbacksListView;
    HMENU ObjectCallbacksContextMenu;

    // About Tab
    HWND AboutPage;
    HWND AboutLabel;
} wh;

// Window data structure
struct WINDOW_DATA {
    std::vector<MODULE_INFO> Modules;
    std::vector<CALLBACK_INFO_SHARED> ProcessCallbacks;
    std::vector<CALLBACK_INFO_SHARED> ThreadCallbacks;
    std::vector<CALLBACK_INFO_SHARED> RegistryCallbacks;
    std::vector<CALLBACK_INFO_SHARED> FilesystemCallbacks;
    std::vector<CALLBACK_INFO_SHARED> ObjectCallbacks;
} wd;

// Menu command identifiers
#define IDM_REFRESH_MODULES    1001
#define IDM_REFRESH_PROCESS_CALLBACKS 1006
#define IDM_REFRESH_THREAD_CALLBACKS  1007
#define IDM_REFRESH_REGISTRY_CALLBACKS 1008
#define IDM_REFRESH_FILESYSTEM_CALLBACKS 1009
#define IDM_REFRESH_OBJECT_CALLBACKS 1010
#define IDM_COPY_MODULE       1003
#define IDM_COPY_CALLBACK     1004
#define IDM_EXIT             1005

// Function declarations for menu commands
void RefreshModules();
void RefreshProcessCallbacks();
void RefreshThreadCallbacks();
void RefreshRegistryCallbacks();
void RefreshFilesystemCallbacks();
void RefreshObjectCallbacks();
void CopySelectedModule();
void CopySelectedCallback();

// Forward declarations for window procedures
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK ModulesWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK CallbacksWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK AboutWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
VOID PaintWindow(HWND hWnd);
VOID ResizeWindow(HWND hWnd);

// Constants for kernel addresses, offsets, and sizes
#define CLIENT_MAX_MODULES 512  // Renamed to avoid conflict
#define MAX_PATH_LENGTH 260
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

// Add after the global variables section and before the function implementations

// Logging mutex for thread safety
static std::mutex g_LogMutex;
static const wchar_t* LOG_FILE_PATH = L"C:\\log_elemetry.txt";
static HANDLE g_LogFile = INVALID_HANDLE_VALUE;

// Helper function to get current timestamp as string
std::wstring GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::wstringstream ss;
    wchar_t timestamp[26];
    tm localTime;
    localtime_s(&localTime, &time);
    wcsftime(timestamp, sizeof(timestamp), L"%Y-%m-%d %H:%M:%S", &localTime);
    ss << timestamp << L"." << std::setw(3) << std::setfill(L'0') << ms.count();
    return ss.str();
}

// Helper function to get log level string
const wchar_t* GetLogLevelString(int level) {
    switch (level) {
        case 0: return L"ERROR";
        case 1: return L"WARNING";
        case 2: return L"INFO";
        case 3: return L"DEBUG";
        case 4: return L"TRACE";
        default: return L"UNKNOWN";
    }
}

// Initialize logging
bool InitializeLogging() {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    
    // First try to create/truncate the file
    g_LogFile = CreateFileW(
        LOG_FILE_PATH,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,  // Changed from OPEN_ALWAYS to CREATE_ALWAYS to truncate
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (g_LogFile == INVALID_HANDLE_VALUE) {
        MessageBoxW(NULL, L"Failed to open log file", L"Logging Error", MB_OK | MB_ICONERROR);
            return false;
        }
        
    // Write UTF-16 BOM
    const WORD bom = 0xFEFF;
    DWORD bytesWritten;
    WriteFile(g_LogFile, &bom, sizeof(bom), &bytesWritten, NULL);
        
    // Write header
    std::wstring timestamp = GetTimestamp();
    std::wstring headerLine = L"=== Log Started at " + timestamp + L" ===\r\n\r\n";
    
    WriteFile(
        g_LogFile,
        headerLine.c_str(),
        static_cast<DWORD>(headerLine.length() * sizeof(wchar_t)),
        &bytesWritten,
        NULL
    );

        return true;
    }

// Cleanup logging
void CleanupLogging() {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    if (g_LogFile != INVALID_HANDLE_VALUE) {
        std::wstring timestamp = GetTimestamp();
        std::wstring footer = L"\r\n=== Log Ended at " + timestamp + L" ===\r\n";
        
        DWORD bytesWritten;
        WriteFile(
            g_LogFile,
            footer.c_str(),
            static_cast<DWORD>(footer.length() * sizeof(wchar_t)),
            &bytesWritten,
            NULL
        );

        CloseHandle(g_LogFile);
        g_LogFile = INVALID_HANDLE_VALUE;
    }
}

// Generic logging function
void LogMessage(int level, const wchar_t* format, va_list args) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    
    if (g_LogFile == INVALID_HANDLE_VALUE) {
        return;
    }
    
    try {
        // Get thread ID
        DWORD threadId = GetCurrentThreadId();
        
        // Format the message
        wchar_t message[4096];
        _vsnwprintf_s(message, _countof(message), _TRUNCATE, format, args);
        
        // Create the log line
        std::wstring timestamp = GetTimestamp();
        std::wstringstream ss;
        ss << timestamp << L" ["
           << std::setw(8) << std::left << GetLogLevelString(level) << L"] "
           << L"[Thread " << threadId << L"] "
           << message << L"\r\n";
        
        std::wstring logLine = ss.str();
        
        // Write to file
        DWORD bytesWritten;
        WriteFile(
            g_LogFile,
            logLine.c_str(),
            static_cast<DWORD>(logLine.length() * sizeof(wchar_t)),
            &bytesWritten,
            NULL
        );
        
        // Flush file buffers
        FlushFileBuffers(g_LogFile);
        
    } catch (const std::exception& e) {
        // If logging fails, show a message box (but not too frequently)
        static DWORD lastError = 0;
        DWORD now = GetTickCount();
        if (now - lastError > 5000) { // Show error at most every 5 seconds
            std::string error = "Logging failed: ";
            error += e.what();
            MessageBoxA(NULL, error.c_str(), "Logging Error", MB_OK | MB_ICONERROR);
            lastError = now;
        }
    }
}

// Specific logging functions
void LogError(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    LogMessage(0, format, args);
    va_end(args);
}

void LogWarning(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    LogMessage(1, format, args);
    va_end(args);
}

void LogInfo(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    LogMessage(2, format, args);
    va_end(args);
}

void LogDebug(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    LogMessage(3, format, args);
    va_end(args);
}

void LogTrace(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    LogMessage(4, format, args);
    va_end(args);
}

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

    // Clear the appropriate vector in the window data structure based on callback type
    switch (tableType) {
        case CallbackTableLoadImage:
            // Not implemented in wd yet
            break;
        case CallbackTableCreateProcess:
            wd.ProcessCallbacks.clear();
            wd.ProcessCallbacks.resize(request->FoundCallbacks);
            break;
        case CallbackTableCreateThread:
            wd.ThreadCallbacks.clear();
            wd.ThreadCallbacks.resize(request->FoundCallbacks);
            break;
        case CallbackTableRegistry:
            wd.RegistryCallbacks.clear();
            wd.RegistryCallbacks.resize(request->FoundCallbacks);
            break;
        case CallbackTableFilesystem:
            wd.FilesystemCallbacks.clear();
            wd.FilesystemCallbacks.resize(request->FoundCallbacks);
            break;
        default:
            break;
    }

    // Print callback information and store in window data
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

        // Store callback in the appropriate window data vector
        switch (tableType) {
            case CallbackTableLoadImage:
                // Not implemented in wd yet
                break;
            case CallbackTableCreateProcess:
                if (i < wd.ProcessCallbacks.size()) {
                    wd.ProcessCallbacks[i] = *info;
                }
                break;
            case CallbackTableCreateThread:
                if (i < wd.ThreadCallbacks.size()) {
                    wd.ThreadCallbacks[i] = *info;
                }
                break;
            case CallbackTableRegistry:
                if (i < wd.RegistryCallbacks.size()) {
                    wd.RegistryCallbacks[i] = *info;
                }
                break;
            case CallbackTableFilesystem:
                if (i < wd.FilesystemCallbacks.size()) {
                    wd.FilesystemCallbacks[i] = *info;
                }
                break;
            default:
                break;
        }
    }

    // Add logging for the window data size
    switch (tableType) {
        case CallbackTableCreateProcess:
            LogInfo(L"Stored %d process callbacks in window data", wd.ProcessCallbacks.size());
            break;
        case CallbackTableCreateThread:
            LogInfo(L"Stored %d thread callbacks in window data", wd.ThreadCallbacks.size());
            break;
        case CallbackTableRegistry:
            LogInfo(L"Stored %d registry callbacks in window data", wd.RegistryCallbacks.size());
            break;
        case CallbackTableFilesystem:
            LogInfo(L"Stored %d filesystem callbacks in window data", wd.FilesystemCallbacks.size());
            break;
        default:
            break;
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

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Initialize logging
    if (!InitializeLogging()) {
        MessageBox(NULL, L"Failed to initialize logging", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    LogInfo(L"Application starting...");

    // The main window class name.
    static TCHAR szWindowClass[] = _T("ElemetryClient");

    // The string that appears in the application's title bar.
    WCHAR szTitle[MAX_PATH] = { 0 };
    StringCbPrintfW(szTitle, MAX_PATH, L"Elemetry Client v1.0.0");

    WNDCLASSEX wcex;
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = MainWndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = szWindowClass;
    wcex.hIconSm = LoadIcon(wcex.hInstance, IDI_APPLICATION);

    if (!RegisterClassEx(&wcex))
    {
        DWORD error = GetLastError();
        WCHAR errorMsg[256];
        StringCbPrintfW(errorMsg, sizeof(errorMsg), L"RegisterClassEx failed with error %d", error);
        MessageBoxW(NULL, errorMsg, L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Store instance handle in our global variable.
    g_hInst = hInstance;

    // Create the main window and show it.
    wh.Main = CreateWindowEx(
        NULL,
        szWindowClass,
        szTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 500,
        NULL,
        NULL,
        hInstance,
        NULL
    );

    if (!wh.Main)
    {
        DWORD error = GetLastError();
        WCHAR errorMsg[256];
        StringCbPrintfW(errorMsg, sizeof(errorMsg), L"CreateWindowEx failed with error %d", error);
        MessageBoxW(NULL, errorMsg, L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(wh.Main, nCmdShow);
    UpdateWindow(wh.Main);

    // Main message loop:
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    LogInfo(L"Application shutting down...");
    CleanupLogging();
    return (int)msg.wParam;
}

LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
            // Initialize window.
        PaintWindow(hWnd);
        
            // Show modules page.
        ShowWindow(wh.ModulesPage, SW_SHOW);
            ShowWindow(wh.ProcessCallbacksPage, SW_HIDE);
            ShowWindow(wh.ThreadCallbacksPage, SW_HIDE);
            ShowWindow(wh.RegistryCallbacksPage, SW_HIDE);
            ShowWindow(wh.FilesystemCallbacksPage, SW_HIDE);
            ShowWindow(wh.ObjectCallbacksPage, SW_HIDE);
        ShowWindow(wh.AboutPage, SW_HIDE);

            // Set initial tab.
        TabCtrl_SetCurSel(wh.TabControl, 0);

        break;
    }

    case WM_SIZE:
    {
        ResizeWindow(hWnd);
        break;
    }

    case WM_NOTIFY:
    {
            LPNMHDR pnmh = (LPNMHDR)lParam;
            switch (pnmh->code)
            {
            case TCN_SELCHANGE:
            {
                // Hide all pages first
                ShowWindow(wh.ModulesPage, SW_HIDE);
                ShowWindow(wh.ProcessCallbacksPage, SW_HIDE);
                ShowWindow(wh.ThreadCallbacksPage, SW_HIDE);
                ShowWindow(wh.RegistryCallbacksPage, SW_HIDE);
                ShowWindow(wh.FilesystemCallbacksPage, SW_HIDE);
                ShowWindow(wh.ObjectCallbacksPage, SW_HIDE);
                ShowWindow(wh.AboutPage, SW_HIDE);
                
                // Get the selected tab
                int iPage = TabCtrl_GetCurSel(wh.TabControl);

                // Show the selected page and refresh its data
                switch (iPage)
                {
                    case 0: // Modules
                        ShowWindow(wh.ModulesPage, SW_SHOW);
                    RefreshModules();
                        break;
                case 1: // Process Callbacks
                    ShowWindow(wh.ProcessCallbacksPage, SW_SHOW);
                    RefreshProcessCallbacks();
                        break;
                case 2: // Thread Callbacks
                    ShowWindow(wh.ThreadCallbacksPage, SW_SHOW);
                    RefreshThreadCallbacks();
                    break;
                case 3: // Registry Callbacks
                    ShowWindow(wh.RegistryCallbacksPage, SW_SHOW);
                    RefreshRegistryCallbacks();
                    break;
                case 4: // Filesystem Callbacks
                    ShowWindow(wh.FilesystemCallbacksPage, SW_SHOW);
                    RefreshFilesystemCallbacks();
                    break;
                case 5: // Object Callbacks
                    ShowWindow(wh.ObjectCallbacksPage, SW_SHOW);
                    RefreshObjectCallbacks();
                    break;
                case 6: // About
                        ShowWindow(wh.AboutPage, SW_SHOW);
                        break;
                }
                break;
            }

                case NM_RCLICK:
                {
                    // Get selected tab
                    int iPage = TabCtrl_GetCurSel(wh.TabControl);

                    // Show context menu for selected page
                    switch (iPage)
                    {
                        case 0: // Modules
                            if (pnmh->hwndFrom == wh.ModulesListView)
                            {
                                POINT pt;
                                GetCursorPos(&pt);
                                TrackPopupMenu(wh.ModulesContextMenu,
                                    TPM_LEFTALIGN | TPM_RIGHTBUTTON,
                                    pt.x, pt.y, 0, hWnd, NULL);
                            }
                            break;

                        case 1: // Process Callbacks
                            if (pnmh->hwndFrom == wh.ProcessCallbacksListView)
                            {
                                POINT pt;
                                GetCursorPos(&pt);
                                TrackPopupMenu(wh.ProcessCallbacksContextMenu,
                                    TPM_LEFTALIGN | TPM_RIGHTBUTTON,
                                    pt.x, pt.y, 0, hWnd, NULL);
        }
        break;

                        case 2: // Thread Callbacks
                            if (pnmh->hwndFrom == wh.ThreadCallbacksListView)
                            {
                                POINT pt;
                                GetCursorPos(&pt);
                                TrackPopupMenu(wh.ThreadCallbacksContextMenu,
                                    TPM_LEFTALIGN | TPM_RIGHTBUTTON,
                                    pt.x, pt.y, 0, hWnd, NULL);
                            }
                            break;

                        case 3: // Registry Callbacks
                            if (pnmh->hwndFrom == wh.RegistryCallbacksListView)
                            {
                                POINT pt;
                                GetCursorPos(&pt);
                                TrackPopupMenu(wh.RegistryCallbacksContextMenu,
                                    TPM_LEFTALIGN | TPM_RIGHTBUTTON,
                                    pt.x, pt.y, 0, hWnd, NULL);
                            }
                            break;

                        case 4: // Filesystem Callbacks
                            if (pnmh->hwndFrom == wh.FilesystemCallbacksListView)
                            {
                                POINT pt;
                                GetCursorPos(&pt);
                                TrackPopupMenu(wh.FilesystemCallbacksContextMenu,
                                    TPM_LEFTALIGN | TPM_RIGHTBUTTON,
                                    pt.x, pt.y, 0, hWnd, NULL);
                            }
                            break;

                        case 5: // Object Callbacks
                            if (pnmh->hwndFrom == wh.ObjectCallbacksListView)
                            {
                                POINT pt;
                                GetCursorPos(&pt);
                                TrackPopupMenu(wh.ObjectCallbacksContextMenu,
                                    TPM_LEFTALIGN | TPM_RIGHTBUTTON,
                                    pt.x, pt.y, 0, hWnd, NULL);
                            }
            break;
        }
        break;
    }
    }
            break;
}

    case WM_COMMAND:
    {
            // Get the command source
            WORD cmdSource = HIWORD(wParam);
            WORD cmdId = LOWORD(wParam);

            // Handle button clicks (BN_CLICKED = 0)
            if (cmdSource == BN_CLICKED || cmdSource == 0)
            {
                switch (cmdId)
                {
                    case IDM_REFRESH_MODULES:
                        RefreshModules();
            break;
                    case IDM_REFRESH_PROCESS_CALLBACKS:
                        RefreshProcessCallbacks();
                        break;
                    case IDM_REFRESH_THREAD_CALLBACKS:
                        RefreshThreadCallbacks();
                        break;
                    case IDM_REFRESH_REGISTRY_CALLBACKS:
                        RefreshRegistryCallbacks();
                        break;
                    case IDM_REFRESH_FILESYSTEM_CALLBACKS:
                        RefreshFilesystemCallbacks();
                        break;
                    case IDM_REFRESH_OBJECT_CALLBACKS:
                        RefreshObjectCallbacks();
                        break;
                    case IDM_COPY_MODULE:
                        CopySelectedModule();
                        break;
                    case IDM_COPY_CALLBACK:
                        CopySelectedCallback();
                        break;
                    case IDM_EXIT:
                        DestroyWindow(hWnd);
            break;
        }
        }
        break;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0;
}

VOID PaintWindow(HWND hWnd)
{
    // Get global instance.
    g_hInst = (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE);

    // Get bounding box for window.
    RECT rcMain;
    GetClientRect(hWnd, &rcMain);

    // Set font to default GUI font.
    LOGFONT lf;
    GetObject(GetStockObject(DEFAULT_GUI_FONT), sizeof(LOGFONT), &lf);
    HFONT hFont = CreateFont(
        lf.lfHeight, lf.lfWidth,
        lf.lfEscapement, lf.lfOrientation, lf.lfWeight,
        lf.lfItalic, lf.lfUnderline, lf.lfStrikeOut,
        lf.lfCharSet, lf.lfOutPrecision, lf.lfClipPrecision,
        lf.lfQuality, lf.lfPitchAndFamily, lf.lfFaceName);
    SendMessage(hWnd, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Begin painting.
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hWnd, &ps);

    // Status bar.
    wh.StatusBar = CreateWindowEx(
        NULL,                                   // no extended styles
        STATUSCLASSNAME,                        // name of status bar class
        (PCTSTR)NULL,                           // no text when first created
        WS_CHILD | WS_VISIBLE,                  // creates a visible child window
        0, 0, 0, 0,                             // ignores size and position
        hWnd,                                   // handle to parent window
        (HMENU)0,                               // child window identifier
        g_hInst,                                // handle to application instance
        NULL);                                  // no window creation data
    SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)L"Ready");

    // Tab control.
    wh.TabControl = CreateWindowEx(
        NULL,                                   // no extended styles
        WC_TABCONTROL,                          // name of tab control class
        NULL,                                   // no text
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,// creates a visible child window
        0, 0, rcMain.right, rcMain.bottom,      // size and position
        hWnd,                                   // handle to parent window
        (HMENU)0,                               // child window identifier
        g_hInst,                                // handle to application instance
        NULL);                                  // no window creation data

    // Add tabs
    TCITEM tie;
    tie.mask = TCIF_TEXT;

    tie.pszText = (LPWSTR)L"Modules";
    TabCtrl_InsertItem(wh.TabControl, 0, &tie);

    tie.pszText = (LPWSTR)L"Process Callbacks";
    TabCtrl_InsertItem(wh.TabControl, 1, &tie);

    tie.pszText = (LPWSTR)L"Thread Callbacks";
    TabCtrl_InsertItem(wh.TabControl, 2, &tie);
    
    tie.pszText = (LPWSTR)L"Registry Callbacks";
    TabCtrl_InsertItem(wh.TabControl, 3, &tie);

    tie.pszText = (LPWSTR)L"Filesystem Callbacks";
    TabCtrl_InsertItem(wh.TabControl, 4, &tie);

    tie.pszText = (LPWSTR)L"Object Callbacks";
    TabCtrl_InsertItem(wh.TabControl, 5, &tie);

    tie.pszText = (LPWSTR)L"About";
    TabCtrl_InsertItem(wh.TabControl, 6, &tie);

    // Create tab pages
    // Modules page
    wh.ModulesPage = CreateWindowEx(
        NULL,                                   // no extended styles
        L"STATIC",                              // name of static control class
        NULL,                                   // no text
        WS_CHILD | WS_VISIBLE,                  // creates a visible child window
        0, 30, rcMain.right, rcMain.bottom - 30,// size and position
        hWnd,                                   // handle to parent window
        (HMENU)0,                               // child window identifier
        g_hInst,                                // handle to application instance
        NULL);                                  // no window creation data

    // Modules refresh button
    wh.ModulesRefreshButton = CreateWindowEx(
        NULL,                                   // no extended styles
        L"BUTTON",                              // name of button control class
        L"Refresh",                             // button text
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,  // creates a visible child window
        10, 40, 100, 25,                        // size and position
        hWnd,                                   // handle to parent window
        (HMENU)IDM_REFRESH_MODULES,             // child window identifier - using our command ID
        g_hInst,                                // handle to application instance
        NULL);                                  // no window creation data

    // Modules count label
    wh.ModulesCountLabel = CreateWindowEx(
        NULL,                                   // no extended styles
        L"STATIC",                              // name of static control class
        L"Modules found: 0",                    // initial text
        WS_CHILD | WS_VISIBLE | SS_LEFT,        // creates a visible child window
        120, 45, 200, 20,                       // size and position
        hWnd,                                   // handle to parent window
        (HMENU)0,                               // child window identifier
        g_hInst,                                // handle to application instance
        NULL);                                  // no window creation data

    // Modules list view
    wh.ModulesListView = CreateWindowEx(
        NULL,                                   // no extended styles
        WC_LISTVIEW,                            // name of list view class
        NULL,                                   // no text
        WS_CHILD | WS_VISIBLE | LVS_REPORT,     // creates a visible child window
        10, 70, rcMain.right - 20, rcMain.bottom - 100,// size and position
        hWnd,                                   // handle to parent window
        (HMENU)0,                               // child window identifier
        g_hInst,                                // handle to application instance
        NULL);                                  // no window creation data

    // Add columns to modules list view
    LVCOLUMN lvc;
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.pszText = (LPWSTR)L"Path";
    lvc.cx = 300;
    ListView_InsertColumn(wh.ModulesListView, 0, &lvc);

    lvc.pszText = (LPWSTR)L"Type";
    lvc.cx = 100;
    ListView_InsertColumn(wh.ModulesListView, 1, &lvc);

    lvc.pszText = (LPWSTR)L"Address";
    lvc.cx = 140;
    ListView_InsertColumn(wh.ModulesListView, 2, &lvc);

    lvc.pszText = (LPWSTR)L"Size";
    lvc.cx = 100;
    ListView_InsertColumn(wh.ModulesListView, 3, &lvc);

    lvc.pszText = (LPWSTR)L"Flags";
    lvc.cx = 100;
    ListView_InsertColumn(wh.ModulesListView, 4, &lvc);

    // Create similar pages and controls for each callback type...
    // (Process Callbacks, Thread Callbacks, Registry Callbacks, etc.)
    // The code is similar to the Modules page but with different labels and columns

    // End painting
    EndPaint(hWnd, &ps);

    // Create context menus
    wh.ModulesContextMenu = CreatePopupMenu();
    AppendMenuW(wh.ModulesContextMenu, MF_STRING, IDM_REFRESH_MODULES, L"Refresh");
    AppendMenuW(wh.ModulesContextMenu, MF_STRING, IDM_COPY_MODULE, L"Copy");

    // Create similar context menus for each callback type...
}

VOID ResizeWindow(HWND hWnd)
{
    // Get bounding box for window.
    RECT rcMain;
    GetClientRect(hWnd, &rcMain);

    // Resize status bar.
    SendMessage(wh.StatusBar, WM_SIZE, 0, 0);

    // Resize tab control.
    SetWindowPos(wh.TabControl, NULL,
        0, 0, rcMain.right, rcMain.bottom,
        SWP_NOZORDER);

    // Resize pages.
    SetWindowPos(wh.ModulesPage, NULL,
        0, 30, rcMain.right, rcMain.bottom - 30,
        SWP_NOZORDER);
    SetWindowPos(wh.ProcessCallbacksPage, NULL,
        0, 30, rcMain.right, rcMain.bottom - 30,
        SWP_NOZORDER);
    SetWindowPos(wh.ThreadCallbacksPage, NULL,
        0, 30, rcMain.right, rcMain.bottom - 30,
        SWP_NOZORDER);
    SetWindowPos(wh.RegistryCallbacksPage, NULL,
        0, 30, rcMain.right, rcMain.bottom - 30,
        SWP_NOZORDER);
    SetWindowPos(wh.FilesystemCallbacksPage, NULL,
        0, 30, rcMain.right, rcMain.bottom - 30,
        SWP_NOZORDER);
    SetWindowPos(wh.ObjectCallbacksPage, NULL,
        0, 30, rcMain.right, rcMain.bottom - 30,
        SWP_NOZORDER);
    SetWindowPos(wh.AboutPage, NULL,
        0, 30, rcMain.right, rcMain.bottom - 30,
        SWP_NOZORDER);

    // Resize refresh buttons
    SetWindowPos(wh.ModulesRefreshButton, NULL,
        10, 40, 100, 25,
        SWP_NOZORDER);
    SetWindowPos(wh.ProcessCallbacksRefreshButton, NULL,
        10, 40, 100, 25,
        SWP_NOZORDER);
    SetWindowPos(wh.ThreadCallbacksRefreshButton, NULL,
        10, 40, 100, 25,
        SWP_NOZORDER);
    SetWindowPos(wh.RegistryCallbacksRefreshButton, NULL,
        10, 40, 100, 25,
        SWP_NOZORDER);
    SetWindowPos(wh.FilesystemCallbacksRefreshButton, NULL,
        10, 40, 100, 25,
        SWP_NOZORDER);
    SetWindowPos(wh.ObjectCallbacksRefreshButton, NULL,
        10, 40, 100, 25,
        SWP_NOZORDER);

    // Resize count labels
    SetWindowPos(wh.ModulesCountLabel, NULL,
        120, 45, 200, 20,
        SWP_NOZORDER);
    SetWindowPos(wh.ProcessCallbacksCountLabel, NULL,
        120, 45, 200, 20,
        SWP_NOZORDER);
    SetWindowPos(wh.ThreadCallbacksCountLabel, NULL,
        120, 45, 200, 20,
        SWP_NOZORDER);
    SetWindowPos(wh.RegistryCallbacksCountLabel, NULL,
        120, 45, 200, 20,
        SWP_NOZORDER);
    SetWindowPos(wh.FilesystemCallbacksCountLabel, NULL,
        120, 45, 200, 20,
        SWP_NOZORDER);
    SetWindowPos(wh.ObjectCallbacksCountLabel, NULL,
        120, 45, 200, 20,
        SWP_NOZORDER);

    // Resize list views.
    SetWindowPos(wh.ModulesListView, NULL,
        10, 70, rcMain.right - 20, rcMain.bottom - 100,
        SWP_NOZORDER);
    SetWindowPos(wh.ProcessCallbacksListView, NULL,
        10, 70, rcMain.right - 20, rcMain.bottom - 100,
        SWP_NOZORDER);
    SetWindowPos(wh.ThreadCallbacksListView, NULL,
        10, 70, rcMain.right - 20, rcMain.bottom - 100,
        SWP_NOZORDER);
    SetWindowPos(wh.RegistryCallbacksListView, NULL,
        10, 70, rcMain.right - 20, rcMain.bottom - 100,
        SWP_NOZORDER);
    SetWindowPos(wh.FilesystemCallbacksListView, NULL,
        10, 70, rcMain.right - 20, rcMain.bottom - 100,
        SWP_NOZORDER);
    SetWindowPos(wh.ObjectCallbacksListView, NULL,
        10, 70, rcMain.right - 20, rcMain.bottom - 100,
        SWP_NOZORDER);

    // Resize about label.
    SetWindowPos(wh.AboutLabel, NULL,
        10, 40, rcMain.right - 20, 100,
        SWP_NOZORDER);
}

void PopulateCallbackListView(HWND hListView, PCALLBACK_INFO_SHARED pCallbacks, DWORD count)
{
    ListView_DeleteAllItems(hListView);

    for (DWORD i = 0; i < count; i++)
    {
        LVITEM lvItem = { 0 };
        lvItem.mask = LVIF_TEXT;
        lvItem.iItem = i;

        // Name column
        lvItem.iSubItem = 0;
        lvItem.pszText = (LPWSTR)pCallbacks[i].CallbackName;
        ListView_InsertItem(hListView, &lvItem);

        // Type column
        wchar_t typeStr[32] = L"";
        switch (pCallbacks[i].Type)
        {
            case CALLBACK_TYPE::Unknown:
                StringCchCopy(typeStr, _countof(typeStr), L"Unknown");
                break;
            case CALLBACK_TYPE::PsLoadImage:
                StringCchCopy(typeStr, _countof(typeStr), L"PsLoadImage");
                break;
            case CALLBACK_TYPE::PsProcessCreation:
                StringCchCopy(typeStr, _countof(typeStr), L"PsProcessCreation");
                break;
            case CALLBACK_TYPE::PsThreadCreation:
                StringCchCopy(typeStr, _countof(typeStr), L"PsThreadCreation");
                break;
            case CALLBACK_TYPE::CmRegistry:
                StringCchCopy(typeStr, _countof(typeStr), L"CmRegistry");
                break;
            case CALLBACK_TYPE::ObProcessHandlePre:
                StringCchCopy(typeStr, _countof(typeStr), L"ObProcessHandlePre");
                break;
            case CALLBACK_TYPE::ObProcessHandlePost:
                StringCchCopy(typeStr, _countof(typeStr), L"ObProcessHandlePost");
                break;
            case CALLBACK_TYPE::ObThreadHandlePre:
                StringCchCopy(typeStr, _countof(typeStr), L"ObThreadHandlePre");
                break;
            case CALLBACK_TYPE::ObThreadHandlePost:
                StringCchCopy(typeStr, _countof(typeStr), L"ObThreadHandlePost");
                break;
            case CALLBACK_TYPE::FsPreCreate:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPreCreate");
                break;
            case CALLBACK_TYPE::FsPostCreate:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPostCreate");
                break;
            case CALLBACK_TYPE::FsPreClose:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPreClose");
                break;
            case CALLBACK_TYPE::FsPostClose:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPostClose");
                break;
            case CALLBACK_TYPE::FsPreRead:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPreRead");
                break;
            case CALLBACK_TYPE::FsPostRead:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPostRead");
                break;
            case CALLBACK_TYPE::FsPreWrite:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPreWrite");
                break;
            case CALLBACK_TYPE::FsPostWrite:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPostWrite");
                break;
            case CALLBACK_TYPE::FsPreQueryInfo:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPreQueryInfo");
                break;
            case CALLBACK_TYPE::FsPostQueryInfo:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPostQueryInfo");
                break;
            case CALLBACK_TYPE::FsPreSetInfo:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPreSetInfo");
                break;
            case CALLBACK_TYPE::FsPostSetInfo:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPostSetInfo");
                break;
            case CALLBACK_TYPE::FsPreDirCtrl:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPreDirCtrl");
                break;
            case CALLBACK_TYPE::FsPostDirCtrl:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPostDirCtrl");
                break;
            case CALLBACK_TYPE::FsPreFsCtrl:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPreFsCtrl");
                break;
            case CALLBACK_TYPE::FsPostFsCtrl:
                StringCchCopy(typeStr, _countof(typeStr), L"FsPostFsCtrl");
                break;
            default:
                StringCchCopy(typeStr, _countof(typeStr), L"Unknown");
                break;
        }
        lvItem.iSubItem = 1;
        lvItem.pszText = typeStr;
        ListView_SetItem(hListView, &lvItem);

        // Address column
        wchar_t addrStr[32];
        StringCchPrintf(addrStr, _countof(addrStr), L"0x%p", pCallbacks[i].Address);
        lvItem.iSubItem = 2;
        lvItem.pszText = addrStr;
        ListView_SetItem(hListView, &lvItem);

        // Module column
        lvItem.iSubItem = 3;
        lvItem.pszText = (LPWSTR)pCallbacks[i].ModuleName;
        ListView_SetItem(hListView, &lvItem);
    }
}

void PopulateModuleListView(HWND hListView, PMODULE_INFO pModules, DWORD count)
{
    ListView_DeleteAllItems(hListView);

    for (DWORD i = 0; i < count; i++)
    {
        LVITEM lvItem = { 0 };
        lvItem.mask = LVIF_TEXT;
        lvItem.iItem = i;

        // Path column
        lvItem.iSubItem = 0;
        lvItem.pszText = (LPWSTR)pModules[i].Path;
        ListView_InsertItem(hListView, &lvItem);

        // Type column - just show "Kernel Module" for all entries
        lvItem.iSubItem = 1;
        lvItem.pszText = (LPWSTR)L"Kernel Module";
        ListView_SetItem(hListView, &lvItem);

        // Address column
        wchar_t addrStr[32];
        StringCchPrintf(addrStr, _countof(addrStr), L"0x%p", pModules[i].BaseAddress);
        lvItem.iSubItem = 2;
        lvItem.pszText = addrStr;
        ListView_SetItem(hListView, &lvItem);

        // Size column
        wchar_t sizeStr[32];
        StringCchPrintf(sizeStr, _countof(sizeStr), L"%zu bytes", pModules[i].Size);
        lvItem.iSubItem = 3;
        lvItem.pszText = sizeStr;
        ListView_SetItem(hListView, &lvItem);

        // Flags column
        wchar_t flagsStr[32];
        StringCchPrintf(flagsStr, _countof(flagsStr), L"0x%X", pModules[i].Flags);
        lvItem.iSubItem = 4;
        lvItem.pszText = flagsStr;
        ListView_SetItem(hListView, &lvItem);
    }
}

void RefreshModules()
{
    // Get handle to driver
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        MessageBox(wh.Main, L"Failed to open driver handle", L"Error", MB_OK | MB_ICONERROR);
        return;
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
        MessageBox(wh.Main, L"Failed to get modules", L"Error", MB_OK | MB_ICONERROR);
        CloseHandle(deviceHandle);
        return;
    }

    // Calculate number of modules returned
    DWORD moduleCount = bytesReturned / sizeof(MODULE_INFO);
    
    // Update modules count label
    wchar_t countLabel[32];
    StringCchPrintf(countLabel, _countof(countLabel), L"Modules found: %d", moduleCount);
    SetWindowText(wh.ModulesCountLabel, countLabel);

    // Update list view
    PopulateModuleListView(wh.ModulesListView, moduleInfos, moduleCount);

    CloseHandle(deviceHandle);
}

void RefreshProcessCallbacks()
{
    LogInfo(L"Starting process callback refresh...");

    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        LogError(L"Failed to open driver handle. Error code: %d", error);
        MessageBox(wh.Main, L"Failed to open driver handle", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    LogInfo(L"Successfully opened driver handle");

    // For process callbacks, we need to use the EnumerateCallbacksWithSymbolTable function
    // since we need a valid table address for the PspCreateProcessNotifyRoutine table
    LogInfo(L"Using EnumerateCallbacksWithSymbolTable with SYMBOL_PROCESS_CALLBACKS");
    if (EnumerateCallbacksWithSymbolTable(deviceHandle, CallbackTableCreateProcess, SYMBOL_PROCESS_CALLBACKS)) {
        LogInfo(L"Successfully retrieved process callbacks");
        
        // Count the number of process callbacks for display
        DWORD callbackCount = static_cast<DWORD>(wd.ProcessCallbacks.size());
        
        // Update count label
        wchar_t countLabel[32];
        StringCchPrintf(countLabel, _countof(countLabel), L"Callbacks found: %d", callbackCount);
        SetWindowText(wh.ProcessCallbacksCountLabel, countLabel);
        LogDebug(L"Updated count label: %s", countLabel);
        
        // Log each callback found
        for (DWORD i = 0; i < callbackCount; i++) {
            LogDebug(L"Callback[%d]: Name=%hs, Type=%d, Address=0x%p, Module=%hs",
                    i,
                    wd.ProcessCallbacks[i].CallbackName,
                    wd.ProcessCallbacks[i].Type,
                    wd.ProcessCallbacks[i].Address,
                    wd.ProcessCallbacks[i].ModuleName);
        }
        
        // Update list view with the callbacks from the window data
        PopulateCallbackListView(wh.ProcessCallbacksListView, wd.ProcessCallbacks.data(), callbackCount);
    } else {
        LogError(L"Failed to enumerate process callbacks");
        MessageBox(wh.Main, L"Failed to get process callbacks", L"Error", MB_OK | MB_ICONERROR);
    }

    CloseHandle(deviceHandle);
    LogInfo(L"Process callback refresh completed");
}

void RefreshThreadCallbacks()
{
    LogInfo(L"Starting thread callback refresh...");

    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        LogError(L"Failed to open driver handle. Error code: %d", error);
        MessageBox(wh.Main, L"Failed to open driver handle", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    LogInfo(L"Successfully opened driver handle");

    // Keep the calculation simple - just use a fixed size for the entire buffer
    // that's big enough to hold the header plus all possible callbacks
    const DWORD maxCallbacks = MAX_CALLBACKS_SHARED;
    const DWORD headerSize = sizeof(CALLBACK_ENUM_REQUEST) - sizeof(CALLBACK_INFO_SHARED); // Header without the first array element
    const DWORD callbacksSize = maxCallbacks * sizeof(CALLBACK_INFO_SHARED);
    const DWORD requestSize = headerSize + callbacksSize;
    
    LogDebug(L"Allocating buffer. Size: %d bytes (header: %d + callbacks: %d), Max callbacks: %d", 
             requestSize, headerSize, callbacksSize, maxCallbacks);

    // Allocate buffer for the request, zeroing it out
    std::vector<BYTE> requestBuffer(requestSize, 0);
    PCALLBACK_ENUM_REQUEST request = reinterpret_cast<PCALLBACK_ENUM_REQUEST>(requestBuffer.data());

    // Initialize request
    request->Type = CallbackTableCreateThread;
    request->TableAddress = nullptr; // Driver will find the table
    request->MaxCallbacks = maxCallbacks;
    request->FoundCallbacks = 0;

    // Send request to driver
    DWORD bytesReturned = 0;
    LogInfo(L"Sending IOCTL_ENUM_CALLBACKS to driver...");
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_ENUM_CALLBACKS,
        request, requestSize,
        request, requestSize,
        &bytesReturned,
        nullptr
    );

    if (!success) {
        DWORD error = GetLastError();
        LogError(L"DeviceIoControl failed. Error code: %d", error);
        LogError(L"BytesReturned: %d, Expected: %d", bytesReturned, requestSize);
        MessageBox(wh.Main, L"Failed to get thread callbacks", L"Error", MB_OK | MB_ICONERROR);
        CloseHandle(deviceHandle);
        return;
    }
    LogInfo(L"Successfully received callback data. BytesReturned: %d", bytesReturned);

    // Validate the response
    if (bytesReturned < sizeof(CALLBACK_ENUM_REQUEST)) {
        LogError(L"Insufficient data received. BytesReturned: %d, Minimum expected: %d", 
                bytesReturned, sizeof(CALLBACK_ENUM_REQUEST));
        MessageBox(wh.Main, L"Insufficient data received from driver", L"Error", MB_OK | MB_ICONERROR);
        CloseHandle(deviceHandle);
        return;
    }

    LogInfo(L"Found %d thread callbacks", request->FoundCallbacks);
    
    // Update count label
    wchar_t countLabel[32];
    StringCchPrintf(countLabel, _countof(countLabel), L"Callbacks found: %d", request->FoundCallbacks);
    SetWindowText(wh.ThreadCallbacksCountLabel, countLabel);

    // Validate callback data before populating
    if (request->FoundCallbacks > maxCallbacks) {
        LogError(L"Driver returned too many callbacks: %d (max: %d)", 
                request->FoundCallbacks, maxCallbacks);
        MessageBox(wh.Main, L"Invalid callback count received", L"Error", MB_OK | MB_ICONERROR);
        CloseHandle(deviceHandle);
        return;
    }

    // Update list view
    PopulateCallbackListView(wh.ThreadCallbacksListView, request->Callbacks, request->FoundCallbacks);

    CloseHandle(deviceHandle);
    LogInfo(L"Thread callback refresh completed successfully");
}

void RefreshRegistryCallbacks()
{
    LogInfo(L"Starting registry callback refresh...");

    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        LogError(L"Failed to open driver handle. Error code: %d", error);
        MessageBox(wh.Main, L"Failed to open driver handle", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    LogInfo(L"Successfully opened driver handle");

    // Keep the calculation simple - just use a fixed size for the entire buffer
    // that's big enough to hold the header plus all possible callbacks
    const DWORD maxCallbacks = MAX_CALLBACKS_SHARED;
    const DWORD headerSize = sizeof(CALLBACK_ENUM_REQUEST) - sizeof(CALLBACK_INFO_SHARED); // Header without the first array element
    const DWORD callbacksSize = maxCallbacks * sizeof(CALLBACK_INFO_SHARED);
    const DWORD requestSize = headerSize + callbacksSize;
    
    LogDebug(L"Allocating buffer. Size: %d bytes (header: %d + callbacks: %d), Max callbacks: %d", 
             requestSize, headerSize, callbacksSize, maxCallbacks);

    // Allocate buffer for the request, zeroing it out
    std::vector<BYTE> requestBuffer(requestSize, 0);
    PCALLBACK_ENUM_REQUEST request = reinterpret_cast<PCALLBACK_ENUM_REQUEST>(requestBuffer.data());

    // Initialize request
    request->Type = CallbackTableRegistry;
    request->TableAddress = nullptr; // Driver will find the table
    request->MaxCallbacks = maxCallbacks;
    request->FoundCallbacks = 0;

    // Send request to driver
    DWORD bytesReturned = 0;
    LogInfo(L"Sending IOCTL_ENUM_CALLBACKS to driver...");
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_ENUM_CALLBACKS,
        request, requestSize,
        request, requestSize,
        &bytesReturned,
        nullptr
    );

    if (!success) {
        DWORD error = GetLastError();
        LogError(L"DeviceIoControl failed. Error code: %d", error);
        LogError(L"BytesReturned: %d, Expected: %d", bytesReturned, requestSize);
        MessageBox(wh.Main, L"Failed to get registry callbacks", L"Error", MB_OK | MB_ICONERROR);
        CloseHandle(deviceHandle);
        return;
    }
    LogInfo(L"Successfully received callback data. BytesReturned: %d", bytesReturned);

    // Validate the response
    if (bytesReturned < sizeof(CALLBACK_ENUM_REQUEST)) {
        LogError(L"Insufficient data received. BytesReturned: %d, Minimum expected: %d", 
                bytesReturned, sizeof(CALLBACK_ENUM_REQUEST));
        MessageBox(wh.Main, L"Insufficient data received from driver", L"Error", MB_OK | MB_ICONERROR);
        CloseHandle(deviceHandle);
        return;
    }

    LogInfo(L"Found %d registry callbacks", request->FoundCallbacks);
    
    // Update count label
    wchar_t countLabel[32];
    StringCchPrintf(countLabel, _countof(countLabel), L"Callbacks found: %d", request->FoundCallbacks);
    SetWindowText(wh.RegistryCallbacksCountLabel, countLabel);

    // Validate callback data before populating
    if (request->FoundCallbacks > maxCallbacks) {
        LogError(L"Driver returned too many callbacks: %d (max: %d)", 
                request->FoundCallbacks, maxCallbacks);
        MessageBox(wh.Main, L"Invalid callback count received", L"Error", MB_OK | MB_ICONERROR);
        CloseHandle(deviceHandle);
        return;
    }

    // Update list view
    PopulateCallbackListView(wh.RegistryCallbacksListView, request->Callbacks, request->FoundCallbacks);

    CloseHandle(deviceHandle);
    LogInfo(L"Registry callback refresh completed successfully");
}

void RefreshFilesystemCallbacks()
{
    LogInfo(L"Starting filesystem callback refresh...");

    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        LogError(L"Failed to open driver handle. Error code: %d", error);
        MessageBox(wh.Main, L"Failed to open driver handle", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    LogInfo(L"Successfully opened driver handle");

    // Keep the calculation simple - just use a fixed size for the entire buffer
    // that's big enough to hold the header plus all possible callbacks
    const DWORD maxCallbacks = MAX_CALLBACKS_SHARED;
    const DWORD headerSize = sizeof(CALLBACK_ENUM_REQUEST) - sizeof(CALLBACK_INFO_SHARED); // Header without the first array element
    const DWORD callbacksSize = maxCallbacks * sizeof(CALLBACK_INFO_SHARED);
    const DWORD requestSize = headerSize + callbacksSize;
    
    LogDebug(L"Allocating buffer. Size: %d bytes (header: %d + callbacks: %d), Max callbacks: %d", 
             requestSize, headerSize, callbacksSize, maxCallbacks);

    // Allocate buffer for the request, zeroing it out
    std::vector<BYTE> requestBuffer(requestSize, 0);
    PCALLBACK_ENUM_REQUEST request = reinterpret_cast<PCALLBACK_ENUM_REQUEST>(requestBuffer.data());

    // Initialize request
    request->Type = CallbackTableFilesystem;
    request->TableAddress = nullptr; // Driver will find the table
    request->MaxCallbacks = maxCallbacks;
    request->FoundCallbacks = 0;

    // Send request to driver
    DWORD bytesReturned = 0;
    LogInfo(L"Sending IOCTL_ENUM_CALLBACKS to driver...");
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_ENUM_CALLBACKS,
        request, requestSize,
        request, requestSize,
        &bytesReturned,
        nullptr
    );

    if (!success) {
        DWORD error = GetLastError();
        LogError(L"DeviceIoControl failed. Error code: %d", error);
        LogError(L"BytesReturned: %d, Expected: %d", bytesReturned, requestSize);
        MessageBox(wh.Main, L"Failed to get filesystem callbacks", L"Error", MB_OK | MB_ICONERROR);
        CloseHandle(deviceHandle);
        return;
    }
    LogInfo(L"Successfully received callback data. BytesReturned: %d", bytesReturned);

    // Validate the response
    if (bytesReturned < sizeof(CALLBACK_ENUM_REQUEST)) {
        LogError(L"Insufficient data received. BytesReturned: %d, Minimum expected: %d", 
                bytesReturned, sizeof(CALLBACK_ENUM_REQUEST));
        MessageBox(wh.Main, L"Insufficient data received from driver", L"Error", MB_OK | MB_ICONERROR);
        CloseHandle(deviceHandle);
        return;
    }

    LogInfo(L"Found %d filesystem callbacks", request->FoundCallbacks);
    
    // Update count label
    wchar_t countLabel[32];
    StringCchPrintf(countLabel, _countof(countLabel), L"Callbacks found: %d", request->FoundCallbacks);
    SetWindowText(wh.FilesystemCallbacksCountLabel, countLabel);

    // Validate callback data before populating
    if (request->FoundCallbacks > maxCallbacks) {
        LogError(L"Driver returned too many callbacks: %d (max: %d)", 
                request->FoundCallbacks, maxCallbacks);
        MessageBox(wh.Main, L"Invalid callback count received", L"Error", MB_OK | MB_ICONERROR);
        CloseHandle(deviceHandle);
        return;
    }

    // Update list view
    PopulateCallbackListView(wh.FilesystemCallbacksListView, request->Callbacks, request->FoundCallbacks);

    CloseHandle(deviceHandle);
    LogInfo(L"Filesystem callback refresh completed successfully");
}

void RefreshObjectCallbacks()
{
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        MessageBox(wh.Main, L"Failed to open driver handle", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    const DWORD maxCallbacks = MAX_CALLBACKS_SHARED;
    const DWORD requestSize = sizeof(CALLBACK_ENUM_REQUEST) + (maxCallbacks * sizeof(CALLBACK_INFO_SHARED));
    std::vector<BYTE> buffer(requestSize, 0);
    PCALLBACK_ENUM_REQUEST request = reinterpret_cast<PCALLBACK_ENUM_REQUEST>(buffer.data());

    // For object callbacks, we need to enumerate both process and thread handle callbacks
    std::vector<CALLBACK_INFO_SHARED> allCallbacks;

    // First, get process handle callbacks
    request->Type = CallbackTableCreateProcess;
    request->MaxCallbacks = maxCallbacks;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_ENUM_CALLBACKS,
        request, requestSize,
        request, requestSize,
        &bytesReturned,
        nullptr
    );

    if (success) {
        for (DWORD i = 0; i < request->FoundCallbacks; i++) {
            if (request->Callbacks[i].Type == CALLBACK_TYPE::ObProcessHandlePre ||
                request->Callbacks[i].Type == CALLBACK_TYPE::ObProcessHandlePost) {
                allCallbacks.push_back(request->Callbacks[i]);
            }
        }
    }

    // Then, get thread handle callbacks
    request->Type = CallbackTableCreateThread;
    success = DeviceIoControl(
        deviceHandle,
        IOCTL_ENUM_CALLBACKS,
        request, requestSize,
        request, requestSize,
        &bytesReturned,
        nullptr
    );

    if (success) {
        for (DWORD i = 0; i < request->FoundCallbacks; i++) {
            if (request->Callbacks[i].Type == CALLBACK_TYPE::ObThreadHandlePre ||
                request->Callbacks[i].Type == CALLBACK_TYPE::ObThreadHandlePost) {
                allCallbacks.push_back(request->Callbacks[i]);
            }
        }
    }

    wchar_t countLabel[32];
    StringCchPrintf(countLabel, _countof(countLabel), L"Callbacks found: %d", (DWORD)allCallbacks.size());
    SetWindowText(wh.ObjectCallbacksCountLabel, countLabel);

    if (!allCallbacks.empty()) {
        PopulateCallbackListView(wh.ObjectCallbacksListView, allCallbacks.data(), (DWORD)allCallbacks.size());
    }

    CloseHandle(deviceHandle);
}

void CopySelectedModule()
{
    // Get selected item
    int selectedIndex = ListView_GetNextItem(wh.ModulesListView, -1, LVNI_SELECTED);
    if (selectedIndex == -1) {
        return;
    }

    // Get module path
    wchar_t modulePath[MAX_PATH];
    LVITEM lvItem = { 0 };
    lvItem.mask = LVIF_TEXT;
    lvItem.iItem = selectedIndex;
    lvItem.iSubItem = 0;
    lvItem.pszText = modulePath;
    lvItem.cchTextMax = MAX_PATH;
    ListView_GetItem(wh.ModulesListView, &lvItem);

    // Copy to clipboard
    if (OpenClipboard(wh.Main)) {
        size_t len = wcslen(modulePath) + 1;
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len * sizeof(wchar_t));
        if (hMem) {
            wchar_t* data = (wchar_t*)GlobalLock(hMem);
            if (data) {
                wcscpy_s(data, len, modulePath);
                GlobalUnlock(hMem);
                EmptyClipboard();
                SetClipboardData(CF_UNICODETEXT, hMem);
            }
        }
        CloseClipboard();
    }
}

void CopySelectedCallback()
{
    // Get current tab
    int currentTab = TabCtrl_GetCurSel(wh.TabControl);
    HWND currentListView = NULL;

    // Select the appropriate list view
    switch (currentTab) {
        case 1: // Process Callbacks
            currentListView = wh.ProcessCallbacksListView;
        break;
        case 2: // Thread Callbacks
            currentListView = wh.ThreadCallbacksListView;
        break;
        case 3: // Registry Callbacks
            currentListView = wh.RegistryCallbacksListView;
        break;
        case 4: // Filesystem Callbacks
            currentListView = wh.FilesystemCallbacksListView;
        break;
        case 5: // Object Callbacks
            currentListView = wh.ObjectCallbacksListView;
        break;
        default:
            return;
    }

    // Get selected item
    int selectedIndex = ListView_GetNextItem(currentListView, -1, LVNI_SELECTED);
    if (selectedIndex == -1) {
        return;
    }

    // Get callback name
    wchar_t callbackName[MAX_CALLBACK_NAME];
    LVITEM lvItem = { 0 };
    lvItem.mask = LVIF_TEXT;
    lvItem.iItem = selectedIndex;
    lvItem.iSubItem = 0;
    lvItem.pszText = callbackName;
    lvItem.cchTextMax = MAX_CALLBACK_NAME;
    ListView_GetItem(currentListView, &lvItem);

    // Copy to clipboard
    if (OpenClipboard(wh.Main)) {
        size_t len = wcslen(callbackName) + 1;
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len * sizeof(wchar_t));
        if (hMem) {
            wchar_t* data = (wchar_t*)GlobalLock(hMem);
            if (data) {
                wcscpy_s(data, len, callbackName);
                GlobalUnlock(hMem);
                EmptyClipboard();
                SetClipboardData(CF_UNICODETEXT, hMem);
            }
        }
        CloseClipboard();
    }
}
