#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <unordered_map>
#include <fstream>
#include <filesystem>
#include <sstream>  // Add sstream header
#include <DbgHelp.h>
#include <Psapi.h>  // For EnumProcessModules, GetModuleInformation
#include <ctime>    // For timestamp in logging
#include <direct.h>  // Add this near the top with other includes

// Windows UI headers
#include <tchar.h>
#include <windowsx.h>
#include <strsafe.h>
#include <commctrl.h>

// Define a new IOCTL code for version check
#define IOCTL_GET_VERSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Define a version structure
typedef struct _DRIVER_VERSION {
    ULONG Major;
    ULONG Minor;
    ULONG Patch;
    ULONG Build;
} DRIVER_VERSION, *PDRIVER_VERSION;

// Current client version
const ULONG CLIENT_VERSION_MAJOR = 1;
const ULONG CLIENT_VERSION_MINOR = 0;
const ULONG CLIENT_VERSION_PATCH = 0;
const ULONG CLIENT_VERSION_BUILD = 1;

// Constants that must match driver definitions
#define MAX_PATH_LENGTH 260
#define MAX_CALLBACKS_SHARED 64  // Updated to match driver's value
#define MAX_MODULE_NAME 256
#define MAX_CALLBACK_NAME 256

// Function declaration for version check
bool CheckDriverVersion(HANDLE deviceHandle);

// Additional required message constants
#ifndef HDM_FIRST
#define HDM_FIRST               0x1200      // Header messages
#endif

#ifndef HDM_GETITEM
#define HDM_GETITEM             (HDM_FIRST + 11)
#endif

#ifndef HDM_GETITEMCOUNT
#define HDM_GETITEMCOUNT        (HDM_FIRST + 0)
#endif

#ifndef LVM_GETHEADER
#define LVM_GETHEADER           (LVM_FIRST + 31)
#endif

#ifndef LVM_GETITEMSTATE
#define LVM_GETITEMSTATE        (LVM_FIRST + 44)
#endif

#ifndef LVM_GETNEXTITEM
#define LVM_GETNEXTITEM         (LVM_FIRST + 12)
#endif

#ifndef LVM_GETITEMRECT
#define LVM_GETITEMRECT         (LVM_FIRST + 14)
#endif

#ifndef LVM_GETITEMTEXT
#define LVM_GETITEMTEXT         (LVM_FIRST + 45)
#endif

#ifndef HDI_TEXT
#define HDI_TEXT                0x0002
#endif

#ifndef SB_SETPARTS
#define SB_SETPARTS             (WM_USER+4)
#endif

#ifndef SB_SETTEXT
#define SB_SETTEXT              (WM_USER+1)
#endif

#ifndef HDITEM
typedef struct _HDITEMW {
    UINT    mask;
    int     cxy;
    LPWSTR  pszText;
    HBITMAP hbm;
    int     cchTextMax;
    int     fmt;
    LPARAM  lParam;
    int     iImage;
    int     iOrder;
    UINT    type;
    void*   pvFilter;
    UINT    state;
} HDITEMW, *PHDITEMW;
typedef HDITEMW HDITEM;
#endif

// Link against required libraries
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "comctl32.lib")

// Enable visual styles
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include "elemetry.h"

// Additional ListView macros
#ifndef ListView_GetHeader
#define ListView_GetHeader(hwndLV) \
    (HWND)SendMessage((hwndLV), LVM_GETHEADER, 0, 0)
#endif

#ifndef Header_GetItemCount
#define Header_GetItemCount(hwndHD) \
    (int)SendMessage((hwndHD), HDM_GETITEMCOUNT, 0, 0)
#endif

#ifndef Header_GetItem
#define Header_GetItem(hwndHD, i, phdi) \
    (BOOL)SendMessage((hwndHD), HDM_GETITEM, (WPARAM)(int)(i), (LPARAM)(HDITEM *)(phdi))
#endif

#ifndef ListView_GetItemState
#define ListView_GetItemState(hwndLV, i, mask) \
    (UINT)SendMessage((hwndLV), LVM_GETITEMSTATE, (WPARAM)(i), (LPARAM)(mask))
#endif

#ifndef ListView_GetNextItem
#define ListView_GetNextItem(hwndLV, i, flags) \
    (int)SendMessage((hwndLV), LVM_GETNEXTITEM, (WPARAM)(i), MAKELPARAM((flags), 0))
#endif

#ifndef ListView_GetItemRect
#define ListView_GetItemRect(hwndLV, i, prc, code) \
    (BOOL)SendMessage((hwndLV), LVM_GETITEMRECT, (WPARAM)(int)(i), \
                      ((prc) ? (((RECT *)(prc))->left = (code), (LPARAM)(RECT *)(prc)) : (LPARAM)(RECT *)NULL))
#endif

#ifndef ListView_GetItemText
#define ListView_GetItemText(hwndLV, i, iSubItem, pszText, cchTextMax) \
{ LVITEM _lvi; \
  _lvi.iSubItem = (iSubItem); \
  _lvi.cchTextMax = (cchTextMax); \
  _lvi.pszText = (pszText); \
  SendMessage((hwndLV), LVM_GETITEMTEXT, (WPARAM)(i), (LPARAM)(LV_ITEM *)&_lvi); \
}
#endif

#ifndef LVNI_SELECTED
#define LVNI_SELECTED 0x0002
#endif

#ifndef LVIR_LABEL
#define LVIR_LABEL 0x0002
#endif

// Constants for kernel addresses, offsets, and sizes
#define CLIENT_MAX_MODULES 512  // Renamed to avoid conflict
#define MAX_PATH_LENGTH 260
#define MAX_CALLBACK_INFO_LENGTH 4096

// Global variables and structures for Windows Forms UI
HINSTANCE g_hInst;

// Window handle structure
struct WINDOW_HANDLES {
    HWND Main;
    HWND StatusBar;
    HWND TabControl;

    // Modules Tab
    HWND ModulesPage;
    HWND ModulesRefreshButton;
    HWND ModulesCountLabel;
    HWND ModulesListView;

    // Callbacks Tab
    HWND CallbacksPage;
    HWND CallbacksRefreshButton;
    HWND CallbacksTypeComboBox;
    HWND CallbacksCountLabel;
    HWND CallbacksListView;

    // About Tab
    HWND AboutPage;
    HWND AboutLabel;
} wh;

// Window data structure
struct WINDOW_DATA {
    std::vector<MODULE_INFO> Modules;
    std::vector<CALLBACK_INFO_SHARED> Callbacks;
} wd;

// Function declarations for Windows Forms UI
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK ModulesWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK CallbacksWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK AboutWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
VOID PaintWindow(HWND hWnd);
VOID ResizeWindow(HWND hWnd);
VOID LoadModules();
bool LoadCallbacks(CALLBACK_TABLE_TYPE callbackType);  // Changed from VOID to bool
int CALLBACK ModulesCompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
int CALLBACK CallbacksCompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);

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

// Global log file path
const char* LOG_FILE_PATH = "C:\\log_elemetry.txt";
std::ofstream g_LogFile;

// Logging function for debug and diagnostics
void LogMessage(const std::string& message, bool printToConsole = true) {
    // Get current time
    std::time_t now = std::time(nullptr);
    char timestamp[64];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    
    // Format log message with timestamp
    std::string logMessage = std::string(timestamp) + " - " + message;
    
    // Write to log file if open
    if (g_LogFile.is_open()) {
        g_LogFile << logMessage << std::endl;
        g_LogFile.flush(); // Ensure it's written immediately
    }
    
    // Also print to console if requested
    if (printToConsole) {
        std::cout << logMessage << std::endl;
    }
}

// Initialize log file
bool InitializeLogging() {
    try {
        // Create or truncate the log file
        g_LogFile.open(LOG_FILE_PATH, std::ios::out | std::ios::trunc);
        
        if (!g_LogFile.is_open()) {
            std::cerr << "Failed to open log file: " << LOG_FILE_PATH << std::endl;
            return false;
        }
        
        // Write initial log header
        std::time_t now = std::time(nullptr);
        char timestamp[64];
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
        
        g_LogFile << "=========================================" << std::endl;
        g_LogFile << "Elemetry Client Log - Session started at " << timestamp << std::endl;
        g_LogFile << "Client version: " << CLIENT_VERSION_MAJOR << "." 
                 << CLIENT_VERSION_MINOR << "." 
                 << CLIENT_VERSION_PATCH << " (build " 
                 << CLIENT_VERSION_BUILD << ")" << std::endl;
        g_LogFile << "=========================================" << std::endl << std::endl;
        
        g_LogFile.flush();
        
        std::cout << "Logging initialized. Log file: " << LOG_FILE_PATH << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Error initializing logging: " << e.what() << std::endl;
        return false;
    }
}

// Close logging
void CloseLogging() {
    if (g_LogFile.is_open()) {
        // Write closing message
        std::time_t now = std::time(nullptr);
        char timestamp[64];
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
        
        g_LogFile << std::endl;
        g_LogFile << "=========================================" << std::endl;
        g_LogFile << "Elemetry Client Log - Session ended at " << timestamp << std::endl;
        g_LogFile << "=========================================" << std::endl;
        
        g_LogFile.close();
        std::cout << "Logging closed." << std::endl;
    }
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
    const int MAX_RETRIES = 3;
    int retryCount = 0;
    DWORD lastError = 0;
    
    LogMessage("Attempting to open driver handle: " + std::string(DRIVER_NAME));
    
    while (retryCount < MAX_RETRIES) {
        HANDLE deviceHandle = CreateFileA(
            DRIVER_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (deviceHandle != INVALID_HANDLE_VALUE) {
            if (retryCount > 0) {
                LogMessage("Successfully opened device handle after " + std::to_string(retryCount) + " retries");
            } else {
                LogMessage("Successfully opened device handle on first attempt");
            }
            return deviceHandle;
        }

        lastError = GetLastError();
        
        // Build error message
        std::string errorMsg = "Failed to open device handle '" + std::string(DRIVER_NAME) + 
                              "'. Error code: " + std::to_string(lastError);
        
        // Add human-readable error message
        switch (lastError) {
            case ERROR_FILE_NOT_FOUND:
                errorMsg += " (ERROR_FILE_NOT_FOUND - Driver not loaded or device name incorrect)";
                break;
            case ERROR_ACCESS_DENIED:
                errorMsg += " (ERROR_ACCESS_DENIED - Insufficient permissions or driver locked)";
                break;
            case ERROR_SHARING_VIOLATION:
                errorMsg += " (ERROR_SHARING_VIOLATION - Driver in use by another process)";
                break;
            case ERROR_NOT_READY:
                errorMsg += " (ERROR_NOT_READY - Device not ready, possibly still initializing)";
                break;
            case ERROR_BAD_UNIT:
                errorMsg += " (ERROR_BAD_UNIT - Invalid device identifier)";
                break;
            case ERROR_GEN_FAILURE:
                errorMsg += " (ERROR_GEN_FAILURE - Device not functioning)";
                break;
        }
        
        LogMessage(errorMsg);
        
        // Different retry behavior based on error
        if (lastError == ERROR_FILE_NOT_FOUND) {
            LogMessage("Driver not found. Please make sure the Elemetry driver is loaded.");
            // No point in retrying for a not found error
            break;
        }
        else if (lastError == ERROR_ACCESS_DENIED) {
            LogMessage("Access denied. Checking if running with admin privileges...");
            
            // Here we could check for admin, but just retry for now
            retryCount++;
            LogMessage("Retrying in 500ms... (Attempt " + std::to_string(retryCount) + " of " + std::to_string(MAX_RETRIES) + ")");
            Sleep(500); // Wait a bit before retry
            continue;
        }
        else if (lastError == ERROR_NOT_READY || lastError == ERROR_GEN_FAILURE) {
            // These might be transient, wait longer
            retryCount++;
            LogMessage("Device not ready. Retrying in 1 second... (Attempt " + std::to_string(retryCount) + " of " + std::to_string(MAX_RETRIES) + ")");
            Sleep(1000); // Wait longer before retry
            continue;
        }
        
        // For other errors, retry with shorter delay
        retryCount++;
        LogMessage("Retrying in 500ms... (Attempt " + std::to_string(retryCount) + " of " + std::to_string(MAX_RETRIES) + ")");
        Sleep(500);
    }

    LogMessage("Failed to open device handle after " + std::to_string(retryCount) + " retries. Last error code: " + std::to_string(lastError), true);
    return INVALID_HANDLE_VALUE;
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
    
    // Get count from response and validate
    DWORD callbackCount = response->FoundCallbacks;
    LogMessage("Processing " + std::to_string(callbackCount) + " callbacks from driver");
    
    // Verify we got a valid callback count that doesn't exceed our buffer
    if (callbackCount == 0) {
        SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)L"No callbacks found");
        LogMessage("No callbacks found for type " + std::to_string(static_cast<int>(CallbackTableFilesystem)));
        CloseHandle(deviceHandle);
        return false;
    }

    // Validate callback count against maximum
    if (callbackCount > MAX_CALLBACKS_SHARED) {
        LogMessage("Warning: Driver reported more callbacks than maximum allowed. Limiting to " + 
                  std::to_string(MAX_CALLBACKS_SHARED));
        callbackCount = MAX_CALLBACKS_SHARED;
    }
    
    // Calculate expected data size based on the number of callbacks
    size_t expectedDataSize = FIELD_OFFSET(CALLBACK_ENUM_REQUEST, Callbacks) + 
                             (callbackCount * sizeof(CALLBACK_INFO_SHARED));
    
    if (bytesReturned < expectedDataSize) {
        StringCbPrintfW(statusText, sizeof(statusText), 
                      L"Warning: Driver returned partial data. Expected %zu bytes, got %d", 
                      expectedDataSize, bytesReturned);
        SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)statusText);
        
        LogMessage("Warning: Driver returned partial data. Expected " + std::to_string(expectedDataSize) + 
                  " bytes, got " + std::to_string(bytesReturned));
        
        // Adjust callback count to what we actually received
        callbackCount = (bytesReturned - FIELD_OFFSET(CALLBACK_ENUM_REQUEST, Callbacks)) / 
                        sizeof(CALLBACK_INFO_SHARED);
        
        if (callbackCount == 0) {
            SetWindowTextW(wh.CallbacksCountLabel, L"Error: No valid callbacks received");
            LogMessage("Error: No valid callbacks received after adjusting for partial data");
            CloseHandle(deviceHandle);
            return false;
        }
        
        // Update count label with corrected count
        StringCbPrintfW(statusText, sizeof(statusText), L"Callbacks found: %d (truncated)", callbackCount);
        SetWindowTextW(wh.CallbacksCountLabel, statusText);
        LogMessage("Adjusted callback count to " + std::to_string(callbackCount) + " due to partial data");
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

// Menu command IDs
#define IDM_COPY_SELECTED          101
#define IDM_COPY_ALL               102
#define IDM_EXPORT_TO_FILE         103
#define IDM_REFRESH                104
#define IDM_VIEW_DETAILS           105

// Function to create a context menu for list views
HMENU CreateListContextMenu()
{
    HMENU hMenu = CreatePopupMenu();
    AppendMenu(hMenu, MF_STRING, IDM_COPY_SELECTED, L"Copy Selected");
    AppendMenu(hMenu, MF_STRING, IDM_COPY_ALL, L"Copy All");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, IDM_EXPORT_TO_FILE, L"Export to File...");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, IDM_REFRESH, L"Refresh");
    return hMenu;
}

// Function to handle copying listview content to clipboard
void CopyListViewItemsToClipboard(HWND hListView, bool selectedOnly)
{
    int itemCount = ListView_GetItemCount(hListView);
    if (itemCount == 0) return;

    std::wstring clipboardText;
    WCHAR buffer[1024];

    // Get the column headers
    HWND header = ListView_GetHeader(hListView);
    int columnCount = Header_GetItemCount(header);

    for (int col = 0; col < columnCount; col++) {
        HDITEM hdi = { 0 };
        hdi.mask = HDI_TEXT;
        hdi.pszText = buffer;
        hdi.cchTextMax = _countof(buffer);
        
        Header_GetItem(header, col, &hdi);
        clipboardText += buffer;
        clipboardText += L"\t";
    }
    clipboardText += L"\r\n";

    // Get the data rows
    for (int i = 0; i < itemCount; i++) {
        if (selectedOnly && !(ListView_GetItemState(hListView, i, LVIS_SELECTED) & LVIS_SELECTED))
            continue;

        for (int col = 0; col < columnCount; col++) {
            ListView_GetItemText(hListView, i, col, buffer, _countof(buffer));
            clipboardText += buffer;
            clipboardText += L"\t";
        }
        clipboardText += L"\r\n";
    }

    // Copy to clipboard
    if (!clipboardText.empty() && OpenClipboard(NULL)) {
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (clipboardText.size() + 1) * sizeof(WCHAR));
        if (hMem) {
            WCHAR* pMem = (WCHAR*)GlobalLock(hMem);
            wcscpy_s(pMem, clipboardText.size() + 1, clipboardText.c_str());
            GlobalUnlock(hMem);
            
            EmptyClipboard();
            SetClipboardData(CF_UNICODETEXT, hMem);
        }
        CloseClipboard();
    }
}

// Function to export listview content to a file
void ExportListViewToFile(HWND hWnd, HWND hListView)
{
    WCHAR filePath[MAX_PATH] = { 0 };
    
    OPENFILENAME ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = L"Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"txt";
    
    if (GetSaveFileName(&ofn)) {
        int itemCount = ListView_GetItemCount(hListView);
        if (itemCount == 0) return;
        
        FILE* file = NULL;
        if (_wfopen_s(&file, filePath, L"w, ccs=UTF-8") != 0 || file == NULL) {
            MessageBox(hWnd, L"Failed to open file for writing", L"Error", MB_ICONERROR);
            return;
        }
        
        WCHAR buffer[1024];
        
        // Write the column headers
        HWND header = ListView_GetHeader(hListView);
        int columnCount = Header_GetItemCount(header);
        
        for (int col = 0; col < columnCount; col++) {
            HDITEM hdi = { 0 };
            hdi.mask = HDI_TEXT;
            hdi.pszText = buffer;
            hdi.cchTextMax = _countof(buffer);
            
            Header_GetItem(header, col, &hdi);
            fwprintf(file, L"%s\t", buffer);
        }
        fwprintf(file, L"\n");
        
        // Write the data rows
        for (int i = 0; i < itemCount; i++) {
            for (int col = 0; col < columnCount; col++) {
                ListView_GetItemText(hListView, i, col, buffer, _countof(buffer));
                fwprintf(file, L"%s\t", buffer);
            }
            fwprintf(file, L"\n");
        }
        
        fclose(file);
        MessageBox(hWnd, L"Export completed successfully", L"Success", MB_ICONINFORMATION);
    }
}

// Main window procedure
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    LPMINMAXINFO lpMMI = (LPMINMAXINFO)lParam;
    static HMENU hContextMenu = NULL;

    switch (message)
    {
    case WM_CREATE:
    {
        PaintWindow(hWnd);
        
        // Create context menu
        hContextMenu = CreateListContextMenu();
        
        // Initialize status bar parts
        int statwidths[] = { 300, -1 };
        SendMessage(wh.StatusBar, SB_SETPARTS, 2, (LPARAM)statwidths);

        // Initialize and show the Modules page first
        LoadModules();
        
        // Make sure we see the correct initial tab
        ShowWindow(wh.ModulesPage, SW_SHOW);
        ShowWindow(wh.CallbacksPage, SW_HIDE);
        ShowWindow(wh.AboutPage, SW_HIDE);
        TabCtrl_SetCurSel(wh.TabControl, 0);
        break;
    }
    case WM_CONTEXTMENU:
    {
        HWND hwndFrom = (HWND)wParam;
        
        // Check if the context menu was invoked from a list view
        if (hwndFrom == wh.ModulesListView || hwndFrom == wh.CallbacksListView) {
            POINT pt = { LOWORD(lParam), HIWORD(lParam) };
            
            // If the coordinates are (-1, -1), it means the menu was invoked via keyboard
            if (pt.x == -1 && pt.y == -1) {
                // Get the position of the selected item
                int selectedItem = ListView_GetNextItem(hwndFrom, -1, LVNI_SELECTED);
                if (selectedItem != -1) {
                    RECT rc;
                    ListView_GetItemRect(hwndFrom, selectedItem, &rc, LVIR_LABEL);
                    pt.x = rc.left;
                    pt.y = rc.bottom;
                    ClientToScreen(hwndFrom, &pt);
                } else {
                    // If no item is selected, use the center of the listview
                    RECT rc;
                    GetClientRect(hwndFrom, &rc);
                    pt.x = (rc.left + rc.right) / 2;
                    pt.y = (rc.top + rc.bottom) / 2;
                    ClientToScreen(hwndFrom, &pt);
                }
            }
            
            TrackPopupMenu(hContextMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON, 
                          pt.x, pt.y, 0, hWnd, NULL);
        }
        break;
    }
    case WM_COMMAND:
    {
        // Handle menu commands
        switch (LOWORD(wParam))
        {
        case IDM_COPY_SELECTED:
        {
            // Determine which list view is active
            HWND activeListView = NULL;
            int currentTab = TabCtrl_GetCurSel(wh.TabControl);
            
            if (currentTab == 0)
                activeListView = wh.ModulesListView;
            else if (currentTab == 1)
                activeListView = wh.CallbacksListView;
                
            if (activeListView) {
                CopyListViewItemsToClipboard(activeListView, true);
                SendMessage(wh.StatusBar, SB_SETTEXT, 1, (LPARAM)L"Selected items copied to clipboard");
            }
            break;
        }
        case IDM_COPY_ALL:
        {
            // Determine which list view is active
            HWND activeListView = NULL;
            int currentTab = TabCtrl_GetCurSel(wh.TabControl);
            
            if (currentTab == 0)
                activeListView = wh.ModulesListView;
            else if (currentTab == 1)
                activeListView = wh.CallbacksListView;
                
            if (activeListView) {
                CopyListViewItemsToClipboard(activeListView, false);
                SendMessage(wh.StatusBar, SB_SETTEXT, 1, (LPARAM)L"All items copied to clipboard");
            }
            break;
        }
        case IDM_EXPORT_TO_FILE:
        {
            // Determine which list view is active
            HWND activeListView = NULL;
            int currentTab = TabCtrl_GetCurSel(wh.TabControl);
            
            if (currentTab == 0)
                activeListView = wh.ModulesListView;
            else if (currentTab == 1)
                activeListView = wh.CallbacksListView;
                
            if (activeListView) {
                ExportListViewToFile(hWnd, activeListView);
            }
            break;
        }
        case IDM_REFRESH:
        {
            // Refresh the current view
            int currentTab = TabCtrl_GetCurSel(wh.TabControl);
            
            if (currentTab == 0) {
                LoadModules();
                SendMessage(wh.StatusBar, SB_SETTEXT, 1, (LPARAM)L"Modules refreshed");
            }
            else if (currentTab == 1) {
                int selectedIndex = ComboBox_GetCurSel(wh.CallbacksTypeComboBox);
                LoadCallbacks(static_cast<CALLBACK_TABLE_TYPE>(selectedIndex));
                SendMessage(wh.StatusBar, SB_SETTEXT, 1, (LPARAM)L"Callbacks refreshed");
            }
            break;
        }
        }
        break;
    }
    case WM_DESTROY:
    {
        // Clean up context menu if it exists
        if (hContextMenu) {
            DestroyMenu(hContextMenu);
            hContextMenu = NULL;
        }

        // Clean up window handles
        if (wh.ModulesListView) DestroyWindow(wh.ModulesListView);
        if (wh.CallbacksListView) DestroyWindow(wh.CallbacksListView);
        if (wh.ModulesRefreshButton) DestroyWindow(wh.ModulesRefreshButton);
        if (wh.CallbacksRefreshButton) DestroyWindow(wh.CallbacksRefreshButton);
        if (wh.CallbacksTypeComboBox) DestroyWindow(wh.CallbacksTypeComboBox);
        if (wh.ModulesCountLabel) DestroyWindow(wh.ModulesCountLabel);
        if (wh.CallbacksCountLabel) DestroyWindow(wh.CallbacksCountLabel);
        if (wh.AboutLabel) DestroyWindow(wh.AboutLabel);
        
        // Clean up tab pages
        if (wh.ModulesPage) DestroyWindow(wh.ModulesPage);
        if (wh.CallbacksPage) DestroyWindow(wh.CallbacksPage);
        if (wh.AboutPage) DestroyWindow(wh.AboutPage);
        
        // Clean up tab control and status bar
        if (wh.TabControl) DestroyWindow(wh.TabControl);
        if (wh.StatusBar) DestroyWindow(wh.StatusBar);

        // Clear the vectors
        wd.Modules.clear();
        wd.Callbacks.clear();

        // Close logging
        CloseLogging();
        
        PostQuitMessage(0);
        break;
    }
    case WM_GETMINMAXINFO:
    {
        lpMMI->ptMinTrackSize.x = 900; // Minimum window size
        lpMMI->ptMinTrackSize.y = 500;
        break;
    }
    case WM_SIZE:
    {
        ResizeWindow(hWnd);
        break;
    }
    case WM_NOTIFY:
    {
        NMHDR* pnmh = (LPNMHDR)lParam;
        
        // Check which control sent the notification
        if (pnmh->hwndFrom == wh.TabControl) {
            switch (pnmh->code)
            {
            case TCN_SELCHANGE:
            {
                // Get the newly selected tab
                int TabIndex = TabCtrl_GetCurSel(wh.TabControl);
                
                // Hide all pages first
                ShowWindow(wh.ModulesPage, SW_HIDE);
                ShowWindow(wh.CallbacksPage, SW_HIDE);
                ShowWindow(wh.AboutPage, SW_HIDE);
                
                // Show only the selected page
                switch (TabIndex) {
                    case 0: // Modules
                        ShowWindow(wh.ModulesPage, SW_SHOW);
                        SendMessage(wh.StatusBar, SB_SETTEXT, 0, (LPARAM)L"Modules Tab");
                        LoadModules();  // Load modules data when tab is selected
                        break;
                    case 1: // Callbacks
                        ShowWindow(wh.CallbacksPage, SW_SHOW);
                        SendMessage(wh.StatusBar, SB_SETTEXT, 0, (LPARAM)L"Callbacks Tab");
                        {
                            // Load callbacks for the currently selected type
                            int selectedIndex = ComboBox_GetCurSel(wh.CallbacksTypeComboBox);
                            if (selectedIndex != CB_ERR) {
                                LoadCallbacks(static_cast<CALLBACK_TABLE_TYPE>(selectedIndex));
                            }
                        }
                        break;
                    case 2: // About
                        ShowWindow(wh.AboutPage, SW_SHOW);
                        SendMessage(wh.StatusBar, SB_SETTEXT, 0, (LPARAM)L"About Tab");
                        break;
                }
                
                // Force immediate redraw
                UpdateWindow(wh.TabControl);
                return 0;
            }
            }
        }
        break;
    }
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Modules window procedure
LRESULT CALLBACK ModulesWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
    {
        switch (HIWORD(wParam))
        {
        case BN_CLICKED:
        {
            if (wh.ModulesRefreshButton == (HWND)lParam)
                LoadModules();
            break;
        }
        }
        break;
    }
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Callbacks window procedure
LRESULT CALLBACK CallbacksWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
    {
        switch (HIWORD(wParam))
        {
        case BN_CLICKED:
        {
            if (wh.CallbacksRefreshButton == (HWND)lParam)
            {
                // Get the selected callback type
                int selectedIndex = ComboBox_GetCurSel(wh.CallbacksTypeComboBox);
                LoadCallbacks(static_cast<CALLBACK_TABLE_TYPE>(selectedIndex));
            }
            break;
        }
        case CBN_SELCHANGE:
        {
            if (wh.CallbacksTypeComboBox == (HWND)lParam)
            {
                // Reload callbacks when selection changes
                int selectedIndex = ComboBox_GetCurSel(wh.CallbacksTypeComboBox);
                LoadCallbacks(static_cast<CALLBACK_TABLE_TYPE>(selectedIndex));
            }
            break;
        }
        }
        break;
    }
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// About window procedure
LRESULT CALLBACK AboutWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        
        // Paint the background
        RECT rc;
        GetClientRect(hWnd, &rc);
        FillRect(hdc, &rc, (HBRUSH)(COLOR_WINDOW+1));
        
        // Draw a visible border rectangle
        HBRUSH hBrush = CreateSolidBrush(RGB(200, 220, 240));
        FrameRect(hdc, &rc, hBrush);
        DeleteObject(hBrush);
        
        EndPaint(hWnd, &ps);
        return 0;
    }
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Create and initialize the UI
VOID PaintWindow(HWND hWnd)
{
    // Get client rect for positioning controls
    RECT rcClient;
    GetClientRect(hWnd, &rcClient);
    
    // Set font to default GUI font
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    
    // Create status bar
    wh.StatusBar = CreateWindowEx(
        0,
        STATUSCLASSNAME,
        NULL,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        hWnd,
        NULL,
        g_hInst,
        NULL
    );

    // Calculate initial status bar height
    int statusHeight = 20;
    
    // Create tab control with initial size
    int tabTop = 0;
    int tabWidth = rcClient.right - rcClient.left;
    int tabHeight = rcClient.bottom - rcClient.top - statusHeight;
    
    wh.TabControl = CreateWindowEx(
        0,
        WC_TABCONTROL,
        NULL,
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0, tabTop, tabWidth, tabHeight,
        hWnd,
        NULL,
        g_hInst,
        NULL
    );
    
    // Set font for tab control
    SendMessage(wh.TabControl, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Add tabs
    TCITEM tie = { 0 };
    tie.mask = TCIF_TEXT;

    tie.pszText = const_cast<LPWSTR>(L"Modules");
    TabCtrl_InsertItem(wh.TabControl, 0, &tie);

    tie.pszText = const_cast<LPWSTR>(L"Callbacks");
    TabCtrl_InsertItem(wh.TabControl, 1, &tie);

    tie.pszText = const_cast<LPWSTR>(L"About");
    TabCtrl_InsertItem(wh.TabControl, 2, &tie);
    
    // Get the tab control's client area
    RECT rcTab;
    GetClientRect(wh.TabControl, &rcTab);
    TabCtrl_AdjustRect(wh.TabControl, FALSE, &rcTab);
    
    // Calculate the tab page dimensions
    int pageX = rcTab.left;
    int pageY = rcTab.top;
    int pageWidth = rcTab.right - rcTab.left;
    int pageHeight = rcTab.bottom - rcTab.top;

    // Create Modules page - MAKE SURE IT'S VISIBLE
    wh.ModulesPage = CreateWindowEx(
        0,
        L"STATIC",
        NULL,
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        pageX, pageY, pageWidth, pageHeight,
        hWnd,  // Make it a child of the main window, not the tab control
        NULL,
        g_hInst,
        NULL
    );
    SetWindowLongPtr(wh.ModulesPage, GWLP_WNDPROC, (LONG_PTR)ModulesWndProc);

    // Create Modules UI elements
    wh.ModulesRefreshButton = CreateWindowEx(
        0,
        L"BUTTON",
        L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 10, 100, 25,
        wh.ModulesPage,
        NULL,
        g_hInst,
        NULL
    );
    SendMessage(wh.ModulesRefreshButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    wh.ModulesCountLabel = CreateWindowEx(
        0,
        L"STATIC",
        L"No modules loaded",
        WS_CHILD | WS_VISIBLE,
        120, 15, 200, 20,
        wh.ModulesPage,
        NULL,
        g_hInst,
        NULL
    );
    SendMessage(wh.ModulesCountLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Create Modules ListView
    wh.ModulesListView = CreateWindowEx(
        0,
        WC_LISTVIEW,
        NULL,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        10, 45, pageWidth - 20, pageHeight - 55,
        wh.ModulesPage,
        NULL,
        g_hInst,
        NULL
    );
    SendMessage(wh.ModulesListView, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Set listview columns
    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;

    lvc.iSubItem = 0;
    lvc.cx = 250;
    lvc.pszText = const_cast<LPWSTR>(L"Path");
    ListView_InsertColumn(wh.ModulesListView, 0, &lvc);

    lvc.iSubItem = 1;
    lvc.cx = 150;
    lvc.pszText = const_cast<LPWSTR>(L"Base Address");
    ListView_InsertColumn(wh.ModulesListView, 1, &lvc);

    lvc.iSubItem = 2;
    lvc.cx = 100;
    lvc.pszText = const_cast<LPWSTR>(L"Size");
    ListView_InsertColumn(wh.ModulesListView, 2, &lvc);

    lvc.iSubItem = 3;
    lvc.cx = 100;
    lvc.pszText = const_cast<LPWSTR>(L"Flags");
    ListView_InsertColumn(wh.ModulesListView, 3, &lvc);

    // Set extended style
    ListView_SetExtendedListViewStyle(wh.ModulesListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // Create Callbacks page - INITIALLY HIDDEN
    wh.CallbacksPage = CreateWindowEx(
        0,
        L"STATIC",
        NULL,
        WS_CHILD | WS_CLIPSIBLINGS, // No WS_VISIBLE
        pageX, pageY, pageWidth, pageHeight,
        hWnd,  // Make it a child of the main window, not the tab control
        NULL,
        g_hInst,
        NULL
    );
    SetWindowLongPtr(wh.CallbacksPage, GWLP_WNDPROC, (LONG_PTR)CallbacksWndProc);

    // Create Callbacks UI elements
    wh.CallbacksTypeComboBox = CreateWindowEx(
        0,
        WC_COMBOBOX,
        NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        10, 10, 250, 200,
        wh.CallbacksPage,
        NULL,
        g_hInst,
        NULL
    );
    SendMessage(wh.CallbacksTypeComboBox, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Add items to combobox
    ComboBox_AddString(wh.CallbacksTypeComboBox, L"Load Image Callbacks");
    ComboBox_AddString(wh.CallbacksTypeComboBox, L"Process Creation Callbacks");
    ComboBox_AddString(wh.CallbacksTypeComboBox, L"Thread Creation Callbacks");
    ComboBox_AddString(wh.CallbacksTypeComboBox, L"Registry Callbacks");
    ComboBox_AddString(wh.CallbacksTypeComboBox, L"Minifilter Callbacks");
    ComboBox_SetCurSel(wh.CallbacksTypeComboBox, 0);

    wh.CallbacksRefreshButton = CreateWindowEx(
        0,
        L"BUTTON",
        L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        270, 10, 100, 25,
        wh.CallbacksPage,
        NULL,
        g_hInst,
        NULL
    );
    SendMessage(wh.CallbacksRefreshButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    wh.CallbacksCountLabel = CreateWindowEx(
        0,
        L"STATIC",
        L"No callbacks loaded",
        WS_CHILD | WS_VISIBLE,
        380, 15, 200, 20,
        wh.CallbacksPage,
        NULL,
        g_hInst,
        NULL
    );
    SendMessage(wh.CallbacksCountLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Create Callbacks ListView
    wh.CallbacksListView = CreateWindowEx(
        0,
        WC_LISTVIEW,
        NULL,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        10, 45, pageWidth - 20, pageHeight - 55,
        wh.CallbacksPage,
        NULL,
        g_hInst,
        NULL
    );
    SendMessage(wh.CallbacksListView, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Set listview columns
    lvc.iSubItem = 0;
    lvc.cx = 200;
    lvc.pszText = const_cast<LPWSTR>(L"Name");
    ListView_InsertColumn(wh.CallbacksListView, 0, &lvc);

    lvc.iSubItem = 1;
    lvc.cx = 100;
    lvc.pszText = const_cast<LPWSTR>(L"Type");
    ListView_InsertColumn(wh.CallbacksListView, 1, &lvc);

    lvc.iSubItem = 2;
    lvc.cx = 150;
    lvc.pszText = const_cast<LPWSTR>(L"Address");
    ListView_InsertColumn(wh.CallbacksListView, 2, &lvc);

    lvc.iSubItem = 3;
    lvc.cx = 200;
    lvc.pszText = const_cast<LPWSTR>(L"Module");
    ListView_InsertColumn(wh.CallbacksListView, 3, &lvc);

    // Set extended style
    ListView_SetExtendedListViewStyle(wh.CallbacksListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // Create About page - INITIALLY HIDDEN
    wh.AboutPage = CreateWindowEx(
        0,
        L"STATIC",
        NULL,
        WS_CHILD | WS_CLIPSIBLINGS, // No WS_VISIBLE
        pageX, pageY, pageWidth, pageHeight,
        hWnd,  // Make it a child of the main window, not the tab control
        NULL,
        g_hInst,
        NULL
    );
    SetWindowLongPtr(wh.AboutPage, GWLP_WNDPROC, (LONG_PTR)AboutWndProc);

    wh.AboutLabel = CreateWindowEx(
        0,
        L"STATIC",
        L"Elemetry Client v1.0\n\n"
        L"Windows Kernel Driver Interface\n\n"
        L"This tool allows you to inspect Windows kernel modules and callbacks.\n"
        L"It communicates with the Elemetry kernel-mode driver to retrieve\n"
        L"information about loaded modules and registered callbacks.\n\n"
        L"Features:\n"
        L"- View loaded kernel modules\n"
        L"- Inspect PsLoadImage callbacks\n"
        L"- Inspect Process Creation callbacks\n"
        L"- Inspect Thread Creation callbacks\n"
        L"- Inspect Registry callbacks\n"
        L"- Inspect Minifilter callbacks\n\n"
        L"© 2023",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        5,
        50,
        pageWidth - 10,
        pageHeight - 60,
        wh.AboutPage,
        NULL,
        g_hInst,
        NULL
    );
    SendMessage(wh.AboutLabel, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

    // Apply fonts to all controls
    EnumChildWindows(hWnd, [](HWND hwndChild, LPARAM lParam) -> BOOL {
        SendMessage(hwndChild, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
        return TRUE;
    }, 0);

    // Make sure default tab is visible
    ShowWindow(wh.ModulesPage, SW_SHOW);
    ShowWindow(wh.CallbacksPage, SW_HIDE);
    ShowWindow(wh.AboutPage, SW_HIDE);
    
    // Set the active tab
    TabCtrl_SetCurSel(wh.TabControl, 0);
}

// Resize the window and controls
VOID ResizeWindow(HWND hWnd)
{
    RECT rcClient;
    GetClientRect(hWnd, &rcClient);

    int statusHeight = 20;
    int width = rcClient.right - rcClient.left;
    int height = rcClient.bottom - rcClient.top - statusHeight;

    // Position the status bar
    MoveWindow(wh.StatusBar, 0, height, width, statusHeight, TRUE);

    // Position the tab control to fill the remaining space
    MoveWindow(wh.TabControl, 0, 0, width, height, TRUE);

    // Get tab client area
    RECT rcTab;
    GetClientRect(wh.TabControl, &rcTab);
    
    // Get the tab control display area (excluding the tabs themselves)
    RECT rcDisplay = rcTab;
    TabCtrl_AdjustRect(wh.TabControl, FALSE, &rcDisplay);

    // Convert tab control coordinates to main window coordinates 
    // since our pages are children of the main window
    POINT ptOrigin = { rcDisplay.left, rcDisplay.top };
    ClientToScreen(wh.TabControl, &ptOrigin);
    ScreenToClient(hWnd, &ptOrigin);
    
    // Position the child windows
    int pageX = ptOrigin.x;
    int pageY = ptOrigin.y;
    int pageWidth = rcDisplay.right - rcDisplay.left;
    int pageHeight = rcDisplay.bottom - rcDisplay.top;

    // Move the tab pages to the tab control's display area
    MoveWindow(wh.ModulesPage, pageX, pageY, pageWidth, pageHeight, TRUE);
    MoveWindow(wh.CallbacksPage, pageX, pageY, pageWidth, pageHeight, TRUE);
    MoveWindow(wh.AboutPage, pageX, pageY, pageWidth, pageHeight, TRUE);
    
    // Resize the list views to fit the new tab page size
    if (wh.ModulesListView != NULL) {
        MoveWindow(wh.ModulesListView, 
                  10, 45, 
                  pageWidth - 20, pageHeight - 55, 
                  TRUE);
    }
    
    if (wh.CallbacksListView != NULL) {
        MoveWindow(wh.CallbacksListView, 
                  10, 45, 
                  pageWidth - 20, pageHeight - 55, 
                  TRUE);
    }
    
    if (wh.AboutLabel != NULL) {
        MoveWindow(wh.AboutLabel,
                  5, 50,
                  pageWidth - 10, pageHeight - 60,
                  TRUE);
    }
    
    // Force redraw of tab control and its children
    InvalidateRect(wh.TabControl, NULL, TRUE);
    InvalidateRect(wh.ModulesPage, NULL, TRUE);
    InvalidateRect(wh.CallbacksPage, NULL, TRUE);
    InvalidateRect(wh.AboutPage, NULL, TRUE);
    
    // Apply visibility based on current tab selection
    int currentTab = TabCtrl_GetCurSel(wh.TabControl);
    ShowWindow(wh.ModulesPage, (currentTab == 0) ? SW_SHOW : SW_HIDE);
    ShowWindow(wh.CallbacksPage, (currentTab == 1) ? SW_SHOW : SW_HIDE);
    ShowWindow(wh.AboutPage, (currentTab == 2) ? SW_SHOW : SW_HIDE);
    
    UpdateWindow(hWnd);
}

// Load modules into the ListView
VOID LoadModules()
{
    SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)L"Loading kernel modules...");

    // Clear the ListView
    ListView_DeleteAllItems(wh.ModulesListView);
    wd.Modules.clear();

    // Open driver handle
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        SetWindowTextW(wh.ModulesCountLabel, L"Error: Failed to open driver handle");
        SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)L"Error: Failed to open driver handle");
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
        SetWindowTextW(wh.ModulesCountLabel, L"Error: Failed to retrieve modules");
        SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)L"Error: Failed to retrieve modules");
        CloseHandle(deviceHandle);
        return;
    }

    // Calculate number of modules returned
    DWORD moduleCount = bytesReturned / sizeof(MODULE_INFO);
    
    // Update count label
    WCHAR countText[100];
    StringCbPrintfW(countText, 100, L"Modules found: %d", moduleCount);
    SetWindowTextW(wh.ModulesCountLabel, countText);

    // Add modules to the vector
    for (DWORD i = 0; i < moduleCount; i++) {
        wd.Modules.push_back(moduleInfos[i]);
    }

    // Add modules to ListView
    DWORD listItemCount = 0;
    for (DWORD i = 0; i < moduleCount; i++) {
        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT | LVIF_PARAM;
        lvi.iItem = listItemCount++;
        lvi.iSubItem = 0;
        lvi.lParam = i;
        
        // Path
        lvi.pszText = moduleInfos[i].Path;
        int index = ListView_InsertItem(wh.ModulesListView, &lvi);

        // Base Address
        WCHAR baseAddr[32];
        StringCbPrintfW(baseAddr, 32, L"0x%p", moduleInfos[i].BaseAddress);
        ListView_SetItemText(wh.ModulesListView, index, 1, baseAddr);

        // Size
        WCHAR size[32];
        StringCbPrintfW(size, 32, L"%u", moduleInfos[i].Size);
        ListView_SetItemText(wh.ModulesListView, index, 2, size);

        // Flags
        WCHAR flags[32];
        StringCbPrintfW(flags, 32, L"0x%X", moduleInfos[i].Flags);
        ListView_SetItemText(wh.ModulesListView, index, 3, flags);
    }

    // Sort by module path
    ListView_SortItems(wh.ModulesListView, ModulesCompareFunc, 0);

    CloseHandle(deviceHandle);
    SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)L"Ready");
}

// Load callbacks into the ListView
bool LoadCallbacks(CALLBACK_TABLE_TYPE callbackType)
{
    WCHAR statusText[256] = L"Loading callbacks...";
    SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)statusText);
    LogMessage("Loading callbacks of type " + std::to_string(static_cast<int>(callbackType)));

    // Clear the ListView
    ListView_DeleteAllItems(wh.CallbacksListView);
    wd.Callbacks.clear();

    // Open driver handle
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        StringCbPrintfW(statusText, sizeof(statusText), L"Error: Failed to open driver handle (Error: %d)", error);
        SetWindowTextW(wh.CallbacksCountLabel, L"Error: Failed to open driver handle");
        SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)statusText);
        
        LogMessage("Failed to open driver handle for callback enumeration. Error code: " + std::to_string(error));
        return false;
    }

    // Get the callback table address using symbol resolution
    PVOID tableAddress = nullptr;
    if (callbackType != CallbackTableFilesystem) {
        // Initialize symbols
        HANDLE hProcess = GetCurrentProcess();
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG);
        if (!SymInitialize(hProcess, DEFAULT_SYMBOL_PATH, FALSE)) {
            DWORD error = GetLastError();
            StringCbPrintfW(statusText, sizeof(statusText), L"Error: Failed to initialize symbols (Error: %d)", error);
            SetWindowTextW(wh.CallbacksCountLabel, statusText);
            SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)statusText);
            LogMessage("Failed to initialize symbols. Error code: " + std::to_string(error));
            CloseHandle(deviceHandle);
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
            DWORD error = GetLastError();
            StringCbPrintfW(statusText, sizeof(statusText), L"Error: Failed to get modules (Error: %d)", error);
            SetWindowTextW(wh.CallbacksCountLabel, statusText);
            SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)statusText);
            LogMessage("Failed to get modules. Error code: " + std::to_string(error));
            SymCleanup(hProcess);
            CloseHandle(deviceHandle);
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
                LogMessage("Found ntoskrnl at: 0x" + std::to_string((ULONG_PTR)ntosAddr));
                break;
            }
        }

        if (!ntosAddr) {
            StringCbPrintfW(statusText, sizeof(statusText), L"Error: Failed to find ntoskrnl.exe module");
            SetWindowTextW(wh.CallbacksCountLabel, statusText);
            SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)statusText);
            LogMessage("Failed to find ntoskrnl.exe module");
            SymCleanup(hProcess);
            CloseHandle(deviceHandle);
            return false;
        }

        // Get path to ntoskrnl.exe
        std::string ntoskrnlPath = GetNtoskrnlPath();
        if (ntoskrnlPath.empty()) {
            LogMessage("Warning: Could not find ntoskrnl.exe in current directory or System32. Using default name.");
            ntoskrnlPath = "ntoskrnl.exe";
        }

        // Load ntoskrnl symbols
        DWORD64 baseAddr = SymLoadModuleEx(hProcess, NULL, ntoskrnlPath.c_str(), NULL, (DWORD64)ntosAddr, 0, NULL, 0);
        if (baseAddr == 0 && GetLastError() != ERROR_SUCCESS) {
            DWORD error = GetLastError();
            StringCbPrintfW(statusText, sizeof(statusText), L"Error: Failed to load symbols (Error: %d)", error);
            SetWindowTextW(wh.CallbacksCountLabel, statusText);
            SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)statusText);
            LogMessage("Failed to load symbols for ntoskrnl.exe. Error code: " + std::to_string(error));
            SymCleanup(hProcess);
            CloseHandle(deviceHandle);
            return false;
        }

        // Get the appropriate symbol name based on callback type
        const char* symbolName = nullptr;
        switch (callbackType) {
            case CallbackTableLoadImage:
                symbolName = SYMBOL_LOAD_IMAGE_CALLBACKS;
                break;
            case CallbackTableCreateProcess:
                symbolName = SYMBOL_PROCESS_CALLBACKS;
                break;
            case CallbackTableCreateThread:
                symbolName = SYMBOL_THREAD_CALLBACKS;
                break;
            case CallbackTableRegistry:
                symbolName = SYMBOL_REGISTRY_CALLBACKS;
                break;
            default:
                break;
        }

        if (symbolName) {
            SYMBOL_INFO_PACKAGE symbolInfo = { 0 };
            symbolInfo.si.SizeOfStruct = sizeof(SYMBOL_INFO);
            symbolInfo.si.MaxNameLen = MAX_SYM_NAME;

            if (!SymFromName(hProcess, symbolName, &symbolInfo.si)) {
                DWORD error = GetLastError();
                StringCbPrintfW(statusText, sizeof(statusText), L"Error: Failed to find symbol %hs (Error: %d)", 
                              symbolName, error);
                SetWindowTextW(wh.CallbacksCountLabel, statusText);
                SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)statusText);
                LogMessage("Failed to find symbol: " + std::string(symbolName) + ". Error code: " + 
                          std::to_string(error));
                SymCleanup(hProcess);
                CloseHandle(deviceHandle);
                return false;
            }

            tableAddress = (PVOID)symbolInfo.si.Address;
            LogMessage("Found symbol " + std::string(symbolName) + " at address: 0x" + 
                      std::to_string((ULONG_PTR)tableAddress));
        }

        SymCleanup(hProcess);
    }

    // Allocate buffer for callback information
    const DWORD maxCallbacks = MAX_CALLBACKS_SHARED;  // Now using correct value of 64
    
    // Calculate total size needed for the request structure including the variable-sized array
    // CALLBACK_ENUM_REQUEST includes 1 element in Callbacks array, so subtract 1 from maxCallbacks
    const DWORD bufferSize = FIELD_OFFSET(CALLBACK_ENUM_REQUEST, Callbacks) + 
                            ((maxCallbacks - 1) * sizeof(CALLBACK_INFO_SHARED));
    
    LogMessage("Allocating buffer for " + std::to_string(maxCallbacks) + 
               " callbacks, total size: " + std::to_string(bufferSize) + " bytes");
    
    // Allocate input buffer with proper array space
    std::vector<BYTE> inputBuffer(bufferSize);
    PCALLBACK_ENUM_REQUEST request = reinterpret_cast<PCALLBACK_ENUM_REQUEST>(inputBuffer.data());
    
    // Allocate output buffer with same size
    std::vector<BYTE> outputBuffer(bufferSize);
    PCALLBACK_ENUM_REQUEST response = reinterpret_cast<PCALLBACK_ENUM_REQUEST>(outputBuffer.data());
    
    // Initialize the request structure with valid array space
    request->Type = callbackType;
    request->TableAddress = tableAddress;  // Now using resolved table address
    request->MaxCallbacks = maxCallbacks;
    request->FoundCallbacks = 0;
    
    // Initialize the Callbacks array to prevent garbage data
    memset(&request->Callbacks[0], 0, maxCallbacks * sizeof(CALLBACK_INFO_SHARED));

    LogMessage("Sending IOCTL_ENUM_CALLBACKS for type " + std::to_string(static_cast<int>(callbackType)) +
               " with TableAddress = 0x" + std::to_string((ULONG_PTR)tableAddress) +
               ", MaxCallbacks = " + std::to_string(maxCallbacks) + 
               ", buffer size = " + std::to_string(bufferSize));
    
    // Send IOCTL to get callbacks
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_ENUM_CALLBACKS,
        request, bufferSize,      // Use full buffer size including array space
        response, bufferSize,
        &bytesReturned,
        nullptr
    );

    if (!success) {
        DWORD error = GetLastError();
        StringCbPrintfW(statusText, sizeof(statusText), 
                      L"Error: Failed to retrieve callbacks (Error: %d)", error);
        SetWindowTextW(wh.CallbacksCountLabel, statusText);
        SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)statusText);
        
        LogMessage("DeviceIoControl IOCTL_ENUM_CALLBACKS failed. Error code: " + std::to_string(error));
        CloseHandle(deviceHandle);
        return false;
    }

    if (bytesReturned < FIELD_OFFSET(CALLBACK_ENUM_REQUEST, Callbacks)) {
        StringCbPrintfW(statusText, sizeof(statusText), 
                      L"Error: Driver returned insufficient data (%d bytes)", bytesReturned);
        SetWindowTextW(wh.CallbacksCountLabel, statusText);
        SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)statusText);
        
        LogMessage("DeviceIoControl returned insufficient data: " + std::to_string(bytesReturned) + " bytes");
        CloseHandle(deviceHandle);
        return false;
    }

    // Get count from response
    DWORD callbackCount = response->FoundCallbacks;
    
    // Update count label
    StringCbPrintfW(statusText, sizeof(statusText), L"Callbacks found: %d", callbackCount);
    SetWindowTextW(wh.CallbacksCountLabel, statusText);
    
    LogMessage("Driver reported " + std::to_string(callbackCount) + " callbacks");

    // Verify we got a valid callback count that doesn't exceed our buffer
    if (callbackCount == 0) {
        SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)L"No callbacks found");
        LogMessage("No callbacks found for type " + std::to_string(static_cast<int>(callbackType)));
        CloseHandle(deviceHandle);
        return false;
    }
    
    // Calculate expected data size based on the number of callbacks
    size_t expectedDataSize = FIELD_OFFSET(CALLBACK_ENUM_REQUEST, Callbacks) + 
                              (callbackCount * sizeof(CALLBACK_INFO_SHARED));
    
    if (bytesReturned < expectedDataSize) {
        StringCbPrintfW(statusText, sizeof(statusText), 
                      L"Warning: Driver returned partial data. Expected %zu bytes, got %d", 
                      expectedDataSize, bytesReturned);
        SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)statusText);
        
        LogMessage("Warning: Driver returned partial data. Expected " + std::to_string(expectedDataSize) + 
                  " bytes, got " + std::to_string(bytesReturned));
        
        // Adjust callback count to what we actually received
        callbackCount = (bytesReturned - FIELD_OFFSET(CALLBACK_ENUM_REQUEST, Callbacks)) / 
                        sizeof(CALLBACK_INFO_SHARED);
        
        if (callbackCount == 0) {
            SetWindowTextW(wh.CallbacksCountLabel, L"Error: No valid callbacks received");
            LogMessage("Error: No valid callbacks received after adjusting for partial data");
            CloseHandle(deviceHandle);
            return false;
        }
        
        // Update count label with corrected count
        StringCbPrintfW(statusText, sizeof(statusText), L"Callbacks found: %d (truncated)", callbackCount);
        SetWindowTextW(wh.CallbacksCountLabel, statusText);
        LogMessage("Adjusted callback count to " + std::to_string(callbackCount) + " due to partial data");
    }

    // Calculate number of callbacks returned
    DWORD callbackCount = response->FoundCallbacks;
    LogMessage("Processing " + std::to_string(callbackCount) + " callbacks from driver");
    
    // Validate callback count
    if (callbackCount > MAX_CALLBACKS_SHARED) {
        LogMessage("Warning: Driver reported more callbacks than maximum allowed. Limiting to " + 
                  std::to_string(MAX_CALLBACKS_SHARED));
        callbackCount = MAX_CALLBACKS_SHARED;
    }

    // Store the callbacks in our global data
    wd.Callbacks.clear();  // Clear existing callbacks
    LogMessage("Copying callbacks to global storage...");
    
    for (DWORD i = 0; i < callbackCount; i++) {
        try {
            // Log the raw callback data first
            std::stringstream ss;
            ss << std::hex << "Raw Callback " << i << ": "
               << "Address=0x" << (ULONG_PTR)response->Callbacks[i].Address << ", "
               << "Type=" << std::dec << static_cast<int>(response->Callbacks[i].Type) << ", "
               << "Name ptr=0x" << std::hex << (void*)response->Callbacks[i].CallbackName << ", "
               << "Module ptr=0x" << (void*)response->Callbacks[i].ModuleName;
            LogMessage(ss.str());

            // Validate callback data before copying
            if (!response->Callbacks[i].Address ||
                (ULONG_PTR)response->Callbacks[i].Address < 0xFFFF000000000000) {
                LogMessage("Warning: Invalid callback address at index " + std::to_string(i));
                continue;
            }

            if (!response->Callbacks[i].CallbackName) {
                LogMessage("Warning: Null callback name pointer at index " + std::to_string(i));
                continue;
            }

            if (!response->Callbacks[i].ModuleName) {
                LogMessage("Warning: Null module name pointer at index " + std::to_string(i));
                continue;
            }

            // Log string contents if pointers are valid
            ss.str("");
            ss << "Callback " << i << " strings: "
               << "Name=\"" << response->Callbacks[i].CallbackName << "\", "
               << "Module=\"" << response->Callbacks[i].ModuleName << "\"";
            LogMessage(ss.str());

            // Copy the callback to our global storage
            wd.Callbacks.push_back(response->Callbacks[i]);
            LogMessage("Successfully copied callback " + std::to_string(i) + " to global storage");
        }
        catch (const std::exception& e) {
            LogMessage("Exception while copying callback " + std::to_string(i) + ": " + e.what());
        }
        catch (...) {
            LogMessage("Unknown exception while copying callback " + std::to_string(i));
        }
    }

    LogMessage("Successfully copied " + std::to_string(wd.Callbacks.size()) + " callbacks");

    // Update count label with actual number of valid callbacks
    StringCbPrintfW(statusText, sizeof(statusText), L"Valid callbacks found: %zu", wd.Callbacks.size());
    SetWindowTextW(wh.CallbacksCountLabel, statusText);

    // Add callbacks to ListView
    DWORD listItemCount = 0;
    LogMessage("Starting to populate ListView with " + std::to_string(wd.Callbacks.size()) + " callbacks");
    
    // Clear existing items first
    ListView_DeleteAllItems(wh.CallbacksListView);
    
    for (DWORD i = 0; i < wd.Callbacks.size(); i++) {
        try {
            // Log callback details before processing
            std::stringstream ss;
            ss << "Processing callback " << i << ": ";
            
            // Validate callback name
            if (!wd.Callbacks[i].CallbackName) {
                LogMessage("Warning: Null callback name pointer at index " + std::to_string(i));
                continue;
            }
            
            // Validate module name
            if (!wd.Callbacks[i].ModuleName) {
                LogMessage("Warning: Null module name pointer at index " + std::to_string(i));
                continue;
            }
            
            // Log the raw data for debugging
            ss << "Address=0x" << std::hex << (ULONG_PTR)wd.Callbacks[i].Address 
               << ", Type=" << std::dec << static_cast<int>(wd.Callbacks[i].Type)
               << ", Name=" << (wd.Callbacks[i].CallbackName ? wd.Callbacks[i].CallbackName : "NULL")
               << ", Module=" << (wd.Callbacks[i].ModuleName ? wd.Callbacks[i].ModuleName : "NULL");
            LogMessage(ss.str());
            
            // Validate strings before conversion
            if (wd.Callbacks[i].CallbackName[0] == '\0') {
                LogMessage("Warning: Empty callback name at index " + std::to_string(i));
                continue;
            }
            
            if (wd.Callbacks[i].ModuleName[0] == '\0') {
                LogMessage("Warning: Empty module name at index " + std::to_string(i));
                continue;
            }
            
            // Validate callback address
            if (!wd.Callbacks[i].Address) {
                LogMessage("Warning: Null callback address at index " + std::to_string(i));
                continue;
            }
            
            // Convert callback name to wide string with error checking
            std::vector<WCHAR> nameBuffer(MAX_CALLBACK_NAME);
            int nameResult = MultiByteToWideChar(CP_UTF8, 0, 
                                               wd.Callbacks[i].CallbackName,
                                               -1, nameBuffer.data(), MAX_CALLBACK_NAME);
            if (nameResult == 0) {
                DWORD error = GetLastError();
                LogMessage("Failed to convert callback name for index " + std::to_string(i) + 
                          ". Error: " + std::to_string(error));
                continue;
            }
            
            // Initialize list view item with try-catch
            try {
                LVITEM lvi = { 0 };
                lvi.mask = LVIF_TEXT | LVIF_PARAM;
                lvi.iItem = listItemCount;
                lvi.iSubItem = 0;
                lvi.lParam = i;
                lvi.pszText = nameBuffer.data();
                
                // Insert item with error checking
                int index = ListView_InsertItem(wh.CallbacksListView, &lvi);
                if (index == -1) {
                    LogMessage("ListView_InsertItem failed for index " + std::to_string(i));
                    continue;
                }
                
                // Add type column with bounds checking
                WCHAR typeBuffer[64] = { 0 };
                int typeValue = static_cast<int>(wd.Callbacks[i].Type);
                if (typeValue < 0 || typeValue > 50) { // Arbitrary upper bound for sanity check
                    swprintf_s(typeBuffer, L"Unknown (%d)", typeValue);
                } else {
                    switch (wd.Callbacks[i].Type) {
                        case CALLBACK_TYPE::PsLoadImage:
                            wcscpy_s(typeBuffer, L"Load Image");
                            break;
                        case CALLBACK_TYPE::PsProcessCreation:
                            wcscpy_s(typeBuffer, L"Process Creation");
                            break;
                        case CALLBACK_TYPE::PsThreadCreation:
                            wcscpy_s(typeBuffer, L"Thread Creation");
                            break;
                        case CALLBACK_TYPE::CmRegistry:
                            wcscpy_s(typeBuffer, L"Registry");
                            break;
                        default:
                            swprintf_s(typeBuffer, L"Type %d", typeValue);
                            break;
                    }
                }
                ListView_SetItemText(wh.CallbacksListView, index, 1, typeBuffer);
                
                // Add address column with bounds checking
                WCHAR addressBuffer[32] = { 0 };
                if (wd.Callbacks[i].Address && 
                    (ULONG_PTR)wd.Callbacks[i].Address >= 0xFFFF000000000000) {
                    StringCbPrintfW(addressBuffer, sizeof(addressBuffer), L"0x%p", wd.Callbacks[i].Address);
                } else {
                    wcscpy_s(addressBuffer, L"Invalid Address");
                    LogMessage("Warning: Invalid address range at index " + std::to_string(i));
                }
                ListView_SetItemText(wh.CallbacksListView, index, 2, addressBuffer);
                
                // Add module name column with error checking
                std::vector<WCHAR> moduleBuffer(MAX_MODULE_NAME);
                int moduleResult = MultiByteToWideChar(CP_UTF8, 0,
                                                     wd.Callbacks[i].ModuleName,
                                                     -1, moduleBuffer.data(), MAX_MODULE_NAME);
                if (moduleResult > 0) {
                    ListView_SetItemText(wh.CallbacksListView, index, 3, moduleBuffer.data());
                } else {
                    DWORD error = GetLastError();
                    LogMessage("Failed to convert module name for index " + std::to_string(i) + 
                              ". Error: " + std::to_string(error));
                    WCHAR errorBuffer[32] = L"<Error>";
                    ListView_SetItemText(wh.CallbacksListView, index, 3, errorBuffer);
                }
                
                listItemCount++;
                LogMessage("Successfully added callback " + std::to_string(i) + " to ListView");
            }
            catch (const std::exception& e) {
                LogMessage("Exception while adding callback to ListView: " + std::string(e.what()));
                continue;
            }
        }
        catch (const std::exception& e) {
            LogMessage("Exception while processing callback " + std::to_string(i) + ": " + e.what());
            continue;
        }
        catch (...) {
            LogMessage("Unknown exception while processing callback " + std::to_string(i));
            continue;
        }
    }
    
    LogMessage("Finished populating ListView with " + std::to_string(listItemCount) + " items");
    
    // Only sort if we have items
    if (listItemCount > 0) {
        LogMessage("Starting ListView sort");
        try {
            ListView_SortItems(wh.CallbacksListView, CallbacksCompareFunc, 0);
            LogMessage("ListView sort completed successfully");
        }
        catch (const std::exception& e) {
            std::string errorMsg = "Exception during ListView sort: ";
            errorMsg += e.what();
            LogMessage(errorMsg);
        }
    }
    
    // Update status
    SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)L"Callbacks loaded successfully");
    
    // Close handle
    CloseHandle(deviceHandle);
    LogMessage("Device handle closed");
    
    // Update status
    if (!SendMessage(wh.StatusBar, SB_SETTEXT, (WPARAM)0, (LPARAM)L"Callbacks loaded successfully")) {
        LogMessage("Failed to update status bar");
        return false;
    }
    LogMessage("Status bar updated after loading callbacks");
    
    // Add defensive checks here
    if (!IsWindow(wh.Main)) {
        LogMessage("Main window handle invalid after loading callbacks");
        return false;
    }
    
    if (!IsWindow(wh.StatusBar)) {
        LogMessage("Status bar handle invalid after loading callbacks");
        return false;
    }
    
    LogMessage("Window handles still valid after loading callbacks");
    LogMessage("Preparing to enter main message loop phase");
    
    // Force a redraw of the window to ensure UI is up to date
    InvalidateRect(wh.Main, NULL, TRUE);
    UpdateWindow(wh.Main);
    LogMessage("Window refreshed before message loop");
    return true;
}

// Legacy console entry point, redirects to WinMain
int main() 
{
    return WinMain(GetModuleHandle(NULL), NULL, GetCommandLineA(), SW_SHOWDEFAULT);
}

// Function to check driver version and compatibility
bool CheckDriverVersion(HANDLE deviceHandle) {
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        LogMessage("Invalid device handle for version check.");
        return false;
    }

    // Set up our version
    DRIVER_VERSION clientVersion = {
        CLIENT_VERSION_MAJOR,
        CLIENT_VERSION_MINOR,
        CLIENT_VERSION_PATCH,
        CLIENT_VERSION_BUILD
    };

    // Log our version
    std::string versionStr = "Client version: " + 
                             std::to_string(clientVersion.Major) + "." + 
                             std::to_string(clientVersion.Minor) + "." + 
                             std::to_string(clientVersion.Patch) + 
                             " (build " + std::to_string(clientVersion.Build) + ")";
    LogMessage(versionStr);

    // This IOCTL might not be implemented in older driver versions
    // We'll try it but not fail catastrophically if it's not available
    DRIVER_VERSION driverVersion = {0};
    DWORD bytesReturned = 0;

    LogMessage("Sending IOCTL_GET_VERSION to driver");
    BOOL success = DeviceIoControl(
        deviceHandle,
        IOCTL_GET_VERSION,
        &clientVersion, sizeof(clientVersion),
        &driverVersion, sizeof(driverVersion),
        &bytesReturned,
        nullptr
    );

    if (!success) {
        DWORD error = GetLastError();
        if (error == ERROR_INVALID_FUNCTION) {
            LogMessage("Version check not supported by driver (older version). Compatibility not guaranteed.");
        } else {
            LogMessage("Failed to get driver version. Error code: " + std::to_string(error));
        }
        return true; // Continue anyway
    }

    if (bytesReturned != sizeof(DRIVER_VERSION)) {
        LogMessage("Unexpected version data size. Got " + std::to_string(bytesReturned) + " bytes.");
        return true; // Continue anyway
    }

    // Log driver version
    std::string driverVersionStr = "Driver version: " + 
                                   std::to_string(driverVersion.Major) + "." + 
                                   std::to_string(driverVersion.Minor) + "." + 
                                   std::to_string(driverVersion.Patch) + 
                                   " (build " + std::to_string(driverVersion.Build) + ")";
    LogMessage(driverVersionStr);

    // Check compatibility
    bool compatible = true;
    
    // Simple version check - client should be compatible with same major version
    if (driverVersion.Major != clientVersion.Major) {
        std::string warningMsg = "WARNING: Major version mismatch. Driver version: " + 
                                 std::to_string(driverVersion.Major) + ", Client expects: " + 
                                 std::to_string(clientVersion.Major);
        LogMessage(warningMsg);
        LogMessage("This may result in compatibility issues.");
        compatible = false;
    }

    // Warn if client is older than driver
    if (clientVersion.Minor < driverVersion.Minor) {
        LogMessage("WARNING: Client is older than driver. Some features may not be available.");
    }

    if (compatible) {
        LogMessage("Driver version is compatible with client.");
    }

    return compatible;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Initialize logging
    if (!InitializeLogging()) {
        MessageBoxA(NULL, "Failed to initialize logging", "Error", MB_ICONERROR);
        return 1;
    }

    LogMessage("Starting elemetryClient...");

    // Initialize Common Controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);

    // Register window class
    const wchar_t CLASS_NAME[] = L"ElemetryClientWindow";
    
    WNDCLASSEX wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = CLASS_NAME;
    wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassEx(&wcex)) {
        LogMessage("Failed to register window class", true);
        return 1;
    }

    // Store instance handle in our global variable
    g_hInst = hInstance;

    // Calculate window size
    RECT rc = { 0, 0, 900, 500 };
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);

    // Create the main window
    wh.Main = CreateWindowEx(
        0,                              // Optional window styles
        CLASS_NAME,                     // Window class
        L"Elemetry Client",            // Window text
        WS_OVERLAPPEDWINDOW,           // Window style
        CW_USEDEFAULT, CW_USEDEFAULT,  // Position
        rc.right - rc.left,            // Width
        rc.bottom - rc.top,            // Height
        NULL,                          // Parent window    
        NULL,                          // Menu
        hInstance,                     // Instance handle
        NULL                           // Additional application data
    );

    if (!wh.Main) {
        DWORD error = GetLastError();
        std::string errorMsg = "Failed to create window. Error code: " + std::to_string(error);
        LogMessage(errorMsg, true);
        return 1;
    }

    // Show and update the window
    ShowWindow(wh.Main, nCmdShow);
    UpdateWindow(wh.Main);

    LogMessage("Initialization complete. About to enter main message loop...");

    // Message loop
    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Cleanup
    CloseLogging();
    return (int)msg.wParam;
}

// Window Procedure
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    return MainWndProc(hWnd, message, wParam, lParam);
}

// Helper: Sort callback for modules
int CALLBACK ModulesCompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
    int nRetVal = 0;
    
    const MODULE_INFO& module1 = wd.Modules.at(lParam1);
    const MODULE_INFO& module2 = wd.Modules.at(lParam2);
    
    switch (lParamSort)
    {
    case 0: // Path
        nRetVal = wcscmp(module1.Path, module2.Path);
        break;
        
    case 1: // Base Address
        if ((ULONG64)module1.BaseAddress > (ULONG64)module2.BaseAddress)
            nRetVal = 1;
        else if ((ULONG64)module1.BaseAddress < (ULONG64)module2.BaseAddress)
            nRetVal = -1;
        else
            nRetVal = 0;
        break;
        
    case 2: // Size
        if (module1.Size > module2.Size)
            nRetVal = 1;
        else if (module1.Size < module2.Size)
            nRetVal = -1;
        else
            nRetVal = 0;
        break;
        
    case 3: // Flags
        if (module1.Flags > module2.Flags)
            nRetVal = 1;
        else if (module1.Flags < module2.Flags)
            nRetVal = -1;
        else
            nRetVal = 0;
        break;
        
    default:
        break;
    }
    
    return nRetVal;
}

// Helper: Sort callback for callbacks
int CALLBACK CallbacksCompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
    // Validate indices and vector size first
    if (wd.Callbacks.empty()) {
        return 0;
    }

    size_t size = wd.Callbacks.size();
    if (lParam1 < 0 || lParam2 < 0 || 
        static_cast<size_t>(lParam1) >= size || 
        static_cast<size_t>(lParam2) >= size) {
        return 0;  // Invalid indices, treat as equal
    }
    
    try {
        const CALLBACK_INFO_SHARED& callback1 = wd.Callbacks.at(lParam1);
        const CALLBACK_INFO_SHARED& callback2 = wd.Callbacks.at(lParam2);
        
        // Validate strings before comparison
        if (!callback1.CallbackName || !callback2.CallbackName ||
            !callback1.ModuleName || !callback2.ModuleName) {
            return 0;  // Invalid strings, treat as equal
        }
        
        switch (lParamSort)
        {
        case 0: // Name
            try {
                return _stricmp(callback1.CallbackName, callback2.CallbackName);
            }
            catch (...) {
                return 0;  // If string comparison fails, treat as equal
            }
            break;
            
        case 1: // Type
            return (callback1.Type > callback2.Type) ? 1 : 
                   (callback1.Type < callback2.Type) ? -1 : 0;
            
        case 2: // Address
            return ((ULONG_PTR)callback1.Address > (ULONG_PTR)callback2.Address) ? 1 :
                   ((ULONG_PTR)callback1.Address < (ULONG_PTR)callback2.Address) ? -1 : 0;
            
        case 3: // Module
            try {
                return _stricmp(callback1.ModuleName, callback2.ModuleName);
            }
            catch (...) {
                return 0;  // If string comparison fails, treat as equal
            }
            break;
            
        default:
            return 0;
        }
    }
    catch (...) {
        return 0;  // In case of any error, treat items as equal
    }
    
    return 0;  // Default case, treat as equal
}
