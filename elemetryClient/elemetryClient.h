#pragma once

#include <Windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include "elemetry.h"
#include "symbols.h"
#include "utils.h"
#include "driver.h"

// Control IDs
#define IDC_DRIVER_MODULES_LISTVIEW 1001
#define IDC_CALLBACKS_LISTVIEW 1002
#define IDC_REGISTRY_CALLBACKS_LISTVIEW 1003
#define IDC_MINIFILTER_CALLBACKS_LISTVIEW 1004
#define IDC_SYMBOLS_LISTVIEW 1005
#define IDC_REFRESH_BUTTON 2001
#define IDC_SEARCH_BUTTON 2002
#define IDC_SEARCH_EDIT 2003

// Forward declarations
class MainForm;

// Global variables
extern HINSTANCE g_hInst;
extern MainForm* g_pMainForm;

// Main form class
class MainForm {
public:
    MainForm(HINSTANCE hInstance);
    ~MainForm();

    bool Create();
    void Show(int nCmdShow);
    void Update();

    // Window handles
    HWND m_hWnd;
    HWND m_hStatusBar;
    HWND m_hTabControl;

    // Pages
    HWND m_hDriverModulesPage;
    HWND m_hCallbacksPage;
    HWND m_hRegistryCallbacksPage;
    HWND m_hMinifilterCallbacksPage;
    HWND m_hSymbolsPage;
    HWND m_hAboutPage;

    // Driver Modules page controls
    HWND m_hDriverModulesListView;
    HWND m_hDriverModulesRefreshButton;
    HWND m_hDriverModulesCountLabel;

    // Callbacks page controls
    HWND m_hCallbacksListView;
    HWND m_hCallbacksRefreshButton;
    HWND m_hCallbacksCountLabel;

    // Registry Callbacks page controls
    HWND m_hRegistryCallbacksListView;
    HWND m_hRegistryCallbacksRefreshButton;
    HWND m_hRegistryCallbacksCountLabel;

    // Minifilter Callbacks page controls
    HWND m_hMinifilterCallbacksListView;
    HWND m_hMinifilterCallbacksRefreshButton;
    HWND m_hMinifilterCallbacksCountLabel;

    // Symbols page controls
    HWND m_hSymbolsListView;
    HWND m_hSymbolsRefreshButton;
    HWND m_hSymbolsCountLabel;
    HWND m_hSymbolsSearchEdit;
    HWND m_hSymbolsSearchButton;

    // About page controls
    HWND m_hAboutLabel;

private:
    void CreateDriverModulesPage();
    void CreateCallbacksPage();
    void CreateRegistryCallbacksPage();
    void CreateMinifilterCallbacksPage();
    void CreateSymbolsPage();
    void CreateAboutPage();
    void ResizeWindow();
    void UpdateDriverModules();
    void UpdateCallbacks();
    void UpdateRegistryCallbacks();
    void UpdateMinifilterCallbacks();
    void UpdateSymbols();

    static LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK DriverModulesWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK CallbacksWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK RegistryCallbacksWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK MinifilterCallbacksWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK SymbolsWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK AboutWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
}; 