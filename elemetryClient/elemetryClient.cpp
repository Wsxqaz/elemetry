#include <Windows.h>
#include <commctrl.h>
#include <string>
#include <iostream>
#include <vector>
#include <iomanip>
#include <unordered_map>
#include <fstream>
#include <filesystem>
#include <DbgHelp.h>
#include <Psapi.h>  // For EnumProcessModules, GetModuleInformation

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")  // Link against psapi.lib
#pragma comment(lib, "comctl32.lib")

#include "elemetryClient.h"
#include "elemetry.h"
#include "symbols.h"
#include "utils.h"
#include "driver.h"
#include "enumerators.h"

// Constants for kernel addresses, offsets, and sizes
#define MAX_PATH_LENGTH 260
#define MAX_CALLBACKS_SHARED 256
#define MAX_CALLBACK_INFO_LENGTH 4096

// Global variables for symbol enumeration callback
PVOID g_LocalSymbolAddr = NULL;
const char* g_TargetSymbol = NULL;

// Global variables for symbol enumeration to file
FILE* g_SymbolDumpFile = NULL;

// Global variables
HINSTANCE g_hInst;
MainForm* g_pMainForm;

// Constants
#define IDC_DRIVER_MODULES_LISTVIEW 1001
#define IDC_CALLBACKS_LISTVIEW 1002
#define IDC_REGISTRY_CALLBACKS_LISTVIEW 1003
#define IDC_MINIFILTER_CALLBACKS_LISTVIEW 1004
#define IDC_SYMBOLS_LISTVIEW 1005
#define IDC_REFRESH_BUTTON 2001
#define IDC_SEARCH_BUTTON 2002
#define IDC_SEARCH_EDIT 2003

// Callback function for SymEnumSymbols
BOOL CALLBACK SymEnumCallback(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) {
    if (strcmp(pSymInfo->Name, g_TargetSymbol) == 0) {
        g_LocalSymbolAddr = (PVOID)pSymInfo->Address;
        return FALSE; // Stop enumeration, we found it
    }
    return TRUE; // Continue enumeration
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
    case CALLBACK_TYPE::PsLoadImage: return "PsLoadImage";
    case CALLBACK_TYPE::PsProcessCreation: return "PsProcessCreation";
    case CALLBACK_TYPE::PsThreadCreation: return "PsThreadCreation";
    case CALLBACK_TYPE::CmRegistry: return "CmRegistry";
    case CALLBACK_TYPE::ObProcessHandlePre: return "ObProcessHandlePre";
    case CALLBACK_TYPE::ObProcessHandlePost: return "ObProcessHandlePost";
    case CALLBACK_TYPE::ObThreadHandlePre: return "ObThreadHandlePre";
    case CALLBACK_TYPE::ObThreadHandlePost: return "ObThreadHandlePost";
    default: return "Other/Unknown";
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

// function to call new load image ioctl
bool LoadImageIOCTL(HANDLE  deviceHandle, const char* symbolName) {
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "Invalid device handle." << std::endl;
        return false;
    }

    // Get the address of the symbol
    DWORD64 symbolAddress = 0;
    if (LookupSymbol(deviceHandle, symbolName, symbolAddress) == -1) {
        std::cerr << "Failed to look up symbol: " << symbolName << std::endl;
        return false;
    }
    std::cout << "Symbol address: 0x" << std::hex << symbolAddress << std::dec << std::endl;

    const ULONG maxCallbacks = 64; // Reasonable limit for kernel callbacks
    ULONG requestSize = sizeof(CALLBACK_ENUM_REQUEST) + (maxCallbacks - 1) * sizeof(CALLBACK_INFO_SHARED);

    std::vector<BYTE> requestBuffer(requestSize, 0);
    PCALLBACK_ENUM_REQUEST request = reinterpret_cast<PCALLBACK_ENUM_REQUEST>(requestBuffer.data());

    request->Type = CallbackTableLoadImage;
    request->TableAddress = (PVOID)symbolAddress;
    request->MaxCallbacks = maxCallbacks;

    DWORD bytesReturned = 0;
    BOOL success= DeviceIoControl(
        deviceHandle,
        IOCTL_ENUMERATE_LOAD_IMAGE,
        request, requestSize,
        request, requestSize,
        &bytesReturned,
        nullptr
    );

    if (!success) {
        std::cerr << "Failed to enumerate load image callbacks. Error code: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << std::endl << "==== Load Image Callbacks ====" << std::endl << std::endl;
    std::cout << "Retrieved " << request->FoundCallbacks << " callbacks from "
              << symbolName << " at address 0x" << std::hex << symbolAddress << std::dec << std::endl;

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


        std::cout << std::endl;
    }


    return true;
}

// MainForm implementation
MainForm::MainForm(HINSTANCE hInstance) {
    g_hInst = hInstance;
    m_hWnd = NULL;
    m_hStatusBar = NULL;
    m_hTabControl = NULL;
    m_hDriverModulesPage = NULL;
    m_hCallbacksPage = NULL;
    m_hRegistryCallbacksPage = NULL;
    m_hMinifilterCallbacksPage = NULL;
    m_hSymbolsPage = NULL;
    m_hAboutPage = NULL;
}

MainForm::~MainForm() {
    if (m_hWnd) {
        DestroyWindow(m_hWnd);
    }
}

bool MainForm::Create() {
    // Register the window class
    WNDCLASSEX wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = g_hInst;
    wcex.hIcon = LoadIcon(g_hInst, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = L"elemetryClient";
    wcex.hIconSm = LoadIcon(wcex.hInstance, IDI_APPLICATION);

    if (!RegisterClassEx(&wcex)) {
        return false;
    }

    // Create the main window
    m_hWnd = CreateWindowEx(
        0,
        L"elemetryClient",
        L"elemetryClient",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 500,
        NULL,
        NULL,
        g_hInst,
        NULL
    );

    if (!m_hWnd) {
        return false;
    }

    // Create the status bar
    m_hStatusBar = CreateWindowEx(
        0,
        STATUSCLASSNAME,
        NULL,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        m_hWnd,
        NULL,
        g_hInst,
        NULL
    );

    // Create the tab control
    m_hTabControl = CreateWindowEx(
        0,
        WC_TABCONTROL,
        NULL,
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0, 0, 0, 0,
        m_hWnd,
        NULL,
        g_hInst,
        NULL
    );

    // Add tabs
    TCITEM tie = { 0 };
    tie.mask = TCIF_TEXT;

    wchar_t tabText[32];
    
    wcscpy_s(tabText, L"Driver Modules");
    tie.pszText = tabText;
    TabCtrl_InsertItem(m_hTabControl, 0, &tie);

    wcscpy_s(tabText, L"Callbacks");
    tie.pszText = tabText;
    TabCtrl_InsertItem(m_hTabControl, 1, &tie);

    wcscpy_s(tabText, L"Registry Callbacks");
    tie.pszText = tabText;
    TabCtrl_InsertItem(m_hTabControl, 2, &tie);

    wcscpy_s(tabText, L"Minifilter Callbacks");
    tie.pszText = tabText;
    TabCtrl_InsertItem(m_hTabControl, 3, &tie);

    wcscpy_s(tabText, L"Symbols");
    tie.pszText = tabText;
    TabCtrl_InsertItem(m_hTabControl, 4, &tie);

    wcscpy_s(tabText, L"About");
    tie.pszText = tabText;
    TabCtrl_InsertItem(m_hTabControl, 5, &tie);

    // Create pages
    CreateDriverModulesPage();
    CreateCallbacksPage();
    CreateRegistryCallbacksPage();
    CreateMinifilterCallbacksPage();
    CreateSymbolsPage();
    CreateAboutPage();

    // Show the first page
    ShowWindow(m_hDriverModulesPage, SW_SHOW);

    return true;
}

void MainForm::Show(int nCmdShow) {
    ShowWindow(m_hWnd, nCmdShow);
    UpdateWindow(m_hWnd);
}

void MainForm::Update() {
    // Update all pages
    UpdateDriverModules();
    UpdateCallbacks();
    UpdateRegistryCallbacks();
    UpdateMinifilterCallbacks();
    UpdateSymbols();
}

// Window procedure for the main window
LRESULT CALLBACK MainForm::WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        return 0;

    case WM_SIZE:
        g_pMainForm->ResizeWindow();
        return 0;

    case WM_NOTIFY:
        if (((LPNMHDR)lParam)->code == TCN_SELCHANGE) {
            int iTab = TabCtrl_GetCurSel(g_pMainForm->m_hTabControl);
            ShowWindow(g_pMainForm->m_hDriverModulesPage, (iTab == 0) ? SW_SHOW : SW_HIDE);
            ShowWindow(g_pMainForm->m_hCallbacksPage, (iTab == 1) ? SW_SHOW : SW_HIDE);
            ShowWindow(g_pMainForm->m_hRegistryCallbacksPage, (iTab == 2) ? SW_SHOW : SW_HIDE);
            ShowWindow(g_pMainForm->m_hMinifilterCallbacksPage, (iTab == 3) ? SW_SHOW : SW_HIDE);
            ShowWindow(g_pMainForm->m_hSymbolsPage, (iTab == 4) ? SW_SHOW : SW_HIDE);
            ShowWindow(g_pMainForm->m_hAboutPage, (iTab == 5) ? SW_SHOW : SW_HIDE);
        }
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
}

// Main function
int main() {
    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);

    // Create and show the main form
    g_hInst = GetModuleHandle(NULL);
    g_pMainForm = new MainForm(g_hInst);
    if (!g_pMainForm->Create()) {
        delete g_pMainForm;
        return 1;
    }

    g_pMainForm->Show(SW_SHOW);

    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    delete g_pMainForm;
    return 0;
}
