#include <Windows.h>
#include <commctrl.h>
#include <string>
#include <iostream>
#include <vector>
#include <iomanip>
#include <unordered_map>
#include <fstream>
#include <filesystem>
#include <Psapi.h>  // For EnumProcessModules, GetModuleInformation

#pragma comment(lib, "psapi.lib")  // Link against psapi.lib
#pragma comment(lib, "comctl32.lib")

#include "elemetryClient.h"
#include "elemetry.h"
#include "utils.h"
#include "driver.h"
#include "enumerators.h"

// Constants for kernel addresses, offsets, and sizes
#define MAX_PATH_LENGTH 260
#define MAX_CALLBACK_INFO_LENGTH 4096

// Global variables
HINSTANCE g_hInst;
MainForm* g_pMainForm;
HWND g_hWndMain;

// Constants
#define IDC_DRIVER_MODULES_LISTVIEW 1001
#define IDC_CALLBACKS_LISTVIEW 1002
#define IDC_REGISTRY_CALLBACKS_LISTVIEW 1003
#define IDC_MINIFILTER_CALLBACKS_LISTVIEW 1004
#define IDC_REFRESH_BUTTON 2001

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

// MainForm implementation
MainForm::MainForm(HINSTANCE hInstance) {
    // Initialize window handles
    m_hWnd = NULL;
    m_hStatusBar = NULL;
    m_hTabControl = NULL;

    // Initialize page handles
    m_hDriverModulesPage = NULL;
    m_hCallbacksPage = NULL;
    m_hRegistryCallbacksPage = NULL;
    m_hMinifilterCallbacksPage = NULL;
    m_hAboutPage = NULL;

    // Initialize Driver Modules page controls
    m_hDriverModulesListView = NULL;
    m_hDriverModulesRefreshButton = NULL;
    m_hDriverModulesCountLabel = NULL;

    // Initialize Callbacks page controls
    m_hCallbacksListView = NULL;
    m_hCallbacksRefreshButton = NULL;
    m_hCallbacksCountLabel = NULL;

    // Initialize Registry Callbacks page controls
    m_hRegistryCallbacksListView = NULL;
    m_hRegistryCallbacksRefreshButton = NULL;
    m_hRegistryCallbacksCountLabel = NULL;

    // Initialize Minifilter Callbacks page controls
    m_hMinifilterCallbacksListView = NULL;
    m_hMinifilterCallbacksRefreshButton = NULL;
    m_hMinifilterCallbacksCountLabel = NULL;

    // Initialize About page controls
    m_hAboutLabel = NULL;

    // Store instance handle
    g_hInst = hInstance;
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
        MessageBox(NULL, L"Failed to register window class", L"Error", MB_ICONERROR);
        return false;
    }

    // Create the main window
    m_hWnd = CreateWindowEx(
        0,
        L"elemetryClient",
        L"elemetryClient",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 600,
        NULL,
        NULL,
        g_hInst,
        NULL
    );

    if (!m_hWnd) {
        MessageBox(NULL, L"Failed to create main window", L"Error", MB_ICONERROR);
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
    TCITEM tie;
    tie.mask = TCIF_TEXT;

    tie.pszText = (LPWSTR)L"Driver Modules";
    TabCtrl_InsertItem(m_hTabControl, 0, &tie);

    tie.pszText = (LPWSTR)L"Callbacks";
    TabCtrl_InsertItem(m_hTabControl, 1, &tie);

    tie.pszText = (LPWSTR)L"Registry Callbacks";
    TabCtrl_InsertItem(m_hTabControl, 2, &tie);

    tie.pszText = (LPWSTR)L"Minifilter Callbacks";
    TabCtrl_InsertItem(m_hTabControl, 3, &tie);

    tie.pszText = (LPWSTR)L"About";
    TabCtrl_InsertItem(m_hTabControl, 4, &tie);

    // Create pages
    CreateDriverModulesPage();
    CreateCallbacksPage();
    CreateRegistryCallbacksPage();
    CreateMinifilterCallbacksPage();
    CreateAboutPage();

    // Set Driver Modules as the default tab
    TabCtrl_SetCurSel(m_hTabControl, 0);

    // Show the first page and hide others
    ShowWindow(m_hDriverModulesPage, SW_SHOW);
    ShowWindow(m_hCallbacksPage, SW_HIDE);
    ShowWindow(m_hRegistryCallbacksPage, SW_HIDE);
    ShowWindow(m_hMinifilterCallbacksPage, SW_HIDE);
    ShowWindow(m_hAboutPage, SW_HIDE);

    // Update the window
    ResizeWindow();
    UpdateDriverModules();  // Populate the Driver Modules page immediately

    return true;
}

void MainForm::Show(int nCmdShow) {
    // Show the main window
    ShowWindow(m_hWnd, nCmdShow);
    UpdateWindow(m_hWnd);

    // Show the initial tab's page and refresh button
    ShowWindow(m_hDriverModulesPage, SW_SHOW);
    ShowWindow(m_hDriverModulesRefreshButton, SW_SHOW);
    }

void MainForm::Update() {
    // Update all pages
    UpdateDriverModules();
    UpdateCallbacks();
    UpdateRegistryCallbacks();
    UpdateMinifilterCallbacks();
    }

// Window procedure for the main window
LRESULT CALLBACK MainForm::WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
    {
        // Create status bar
        g_pMainForm->m_hStatusBar = CreateWindowEx(
            0,
            STATUSCLASSNAME,
            NULL,
            WS_CHILD | WS_VISIBLE,
            0, 0, 0, 0,
            hWnd,
            NULL,
            g_hInst,
            NULL
        );

        // Create tab control
        g_pMainForm->m_hTabControl = CreateWindowEx(
            0,
            WC_TABCONTROL,
            NULL,
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
            0, 0, 0, 0,
            hWnd,
            NULL,
            g_hInst,
            NULL
        );

        // Add tabs
        TCITEM tie;
        tie.mask = TCIF_TEXT;

        tie.pszText = (LPWSTR)L"Driver Modules";
        TabCtrl_InsertItem(g_pMainForm->m_hTabControl, 0, &tie);

        tie.pszText = (LPWSTR)L"Callbacks";
        TabCtrl_InsertItem(g_pMainForm->m_hTabControl, 1, &tie);

        tie.pszText = (LPWSTR)L"Registry Callbacks";
        TabCtrl_InsertItem(g_pMainForm->m_hTabControl, 2, &tie);

        tie.pszText = (LPWSTR)L"Minifilter Callbacks";
        TabCtrl_InsertItem(g_pMainForm->m_hTabControl, 3, &tie);

        tie.pszText = (LPWSTR)L"About";
        TabCtrl_InsertItem(g_pMainForm->m_hTabControl, 4, &tie);

        // Create pages
        g_pMainForm->CreateDriverModulesPage();
        g_pMainForm->CreateCallbacksPage();
        g_pMainForm->CreateRegistryCallbacksPage();
        g_pMainForm->CreateMinifilterCallbacksPage();
        g_pMainForm->CreateAboutPage();

        // Show first page
        ShowWindow(g_pMainForm->m_hDriverModulesPage, SW_SHOW);
        ShowWindow(g_pMainForm->m_hCallbacksPage, SW_HIDE);
        ShowWindow(g_pMainForm->m_hRegistryCallbacksPage, SW_HIDE);
        ShowWindow(g_pMainForm->m_hMinifilterCallbacksPage, SW_HIDE);
        ShowWindow(g_pMainForm->m_hAboutPage, SW_HIDE);

        // Update the window
        g_pMainForm->ResizeWindow();
        g_pMainForm->Update();
    }
    break;

    case WM_NOTIFY:
    {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        if (pnmh->hwndFrom == g_pMainForm->m_hTabControl && pnmh->code == TCN_SELCHANGE) {
            // Get the selected tab
            int iPage = TabCtrl_GetCurSel(g_pMainForm->m_hTabControl);

            // Hide all pages
            ShowWindow(g_pMainForm->m_hDriverModulesPage, SW_HIDE);
            ShowWindow(g_pMainForm->m_hCallbacksPage, SW_HIDE);
            ShowWindow(g_pMainForm->m_hRegistryCallbacksPage, SW_HIDE);
            ShowWindow(g_pMainForm->m_hMinifilterCallbacksPage, SW_HIDE);
            ShowWindow(g_pMainForm->m_hAboutPage, SW_HIDE);

            // Show the selected page
            switch (iPage) {
            case 0:
                ShowWindow(g_pMainForm->m_hDriverModulesPage, SW_SHOW);
            break;
            case 1:
                ShowWindow(g_pMainForm->m_hCallbacksPage, SW_SHOW);
                break;
            case 2:
                ShowWindow(g_pMainForm->m_hRegistryCallbacksPage, SW_SHOW);
                break;
            case 3:
                ShowWindow(g_pMainForm->m_hMinifilterCallbacksPage, SW_SHOW);
                break;
            case 4:
                ShowWindow(g_pMainForm->m_hAboutPage, SW_SHOW);
                break;
            }
        }
    }
    break;

    case WM_COMMAND:
    {
        if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == IDC_REFRESH_BUTTON) {
            // Get the selected tab
            int iPage = TabCtrl_GetCurSel(g_pMainForm->m_hTabControl);

            // Update the selected page
            switch (iPage) {
            case 0:
                g_pMainForm->UpdateDriverModules();
                break;
            case 1:
                g_pMainForm->UpdateCallbacks();
                break;
            case 2:
                g_pMainForm->UpdateRegistryCallbacks();
                break;
            case 3:
                g_pMainForm->UpdateMinifilterCallbacks();
                break;
        }
    }
    }
    break;

    case WM_SIZE:
        g_pMainForm->ResizeWindow();
        break;

    case WM_GETMINMAXINFO:
    {
        LPMINMAXINFO lpMMI = (LPMINMAXINFO)lParam;
        lpMMI->ptMinTrackSize.x = 900;  // Minimum width
        lpMMI->ptMinTrackSize.y = 600;  // Minimum height increased from 500 to 600
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
