#include "elemetryClient.h"
#include <strsafe.h>
#include "enumerators.h"

// Helper function to create a list view
HWND CreateListView(HWND hWndParent, int x, int y, int width, int height, DWORD id) {
    HWND hWndListView = CreateWindowEx(
        0,
        WC_LISTVIEW,
        NULL,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
        x, y, width, height,
        hWndParent,
        (HMENU)(LONG_PTR)id,
        g_hInst,
        NULL
    );

    if (hWndListView) {
        // Set extended styles
        ListView_SetExtendedListViewStyle(hWndListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    }

    return hWndListView;
}

// Helper function to add a column to a list view
void AddListViewColumn(HWND hWndListView, int index, const wchar_t* text, int width) {
    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.iSubItem = index;
    lvc.cx = width;
    lvc.pszText = (LPWSTR)text;
    ListView_InsertColumn(hWndListView, index, &lvc);
}

void MainForm::CreateDriverModulesPage() {
    // Create the page window
    m_hDriverModulesPage = CreateWindowEx(
        0,
        L"STATIC",
        NULL,
        WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0,
        m_hWnd,
        NULL,
        g_hInst,
        NULL
    );

    if (!m_hDriverModulesPage) {
        MessageBox(m_hWnd, L"Failed to create driver modules page", L"Error", MB_ICONERROR);
        return;
    }

    // Create the list view
    m_hDriverModulesListView = CreateListView(m_hDriverModulesPage, 10, 10, 860, 400, IDC_DRIVER_MODULES_LISTVIEW);

    if (!m_hDriverModulesListView) {
        MessageBox(m_hWnd, L"Failed to create driver modules list view", L"Error", MB_ICONERROR);
        return;
    }

    // Add columns
    AddListViewColumn(m_hDriverModulesListView, 0, L"Module Name", 200);
    AddListViewColumn(m_hDriverModulesListView, 1, L"Base Address", 100);
    AddListViewColumn(m_hDriverModulesListView, 2, L"Size", 100);
    AddListViewColumn(m_hDriverModulesListView, 3, L"Flags", 100);

    // Create the refresh button
    m_hDriverModulesRefreshButton = CreateWindowEx(
        0,
        L"BUTTON",
        L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 420, 100, 30,
        m_hWnd,  // Parent is main window instead of page
        (HMENU)IDC_REFRESH_BUTTON,
        g_hInst,
        NULL
    );

    if (!m_hDriverModulesRefreshButton) {
        MessageBox(m_hWnd, L"Failed to create refresh button", L"Error", MB_ICONERROR);
        return;
    }

    // Set button position relative to page
    RECT pageRect;
    GetWindowRect(m_hDriverModulesPage, &pageRect);
    MapWindowPoints(HWND_DESKTOP, m_hWnd, (LPPOINT)&pageRect, 2);
    SetWindowPos(m_hDriverModulesRefreshButton, NULL,
        pageRect.left + 10, pageRect.top + 420,
        100, 30,
        SWP_NOZORDER);

    // Create the count label
    m_hDriverModulesCountLabel = CreateWindowEx(
        0,
        L"STATIC",
        L"Modules: 0",
        WS_CHILD | WS_VISIBLE,
        120, 425, 200, 20,
        m_hDriverModulesPage,
        NULL,
        g_hInst,
        NULL
    );

    if (!m_hDriverModulesCountLabel) {
        MessageBox(m_hWnd, L"Failed to create count label", L"Error", MB_ICONERROR);
        return;
    }
}

void MainForm::CreateCallbacksPage() {
    // Create the page window
    m_hCallbacksPage = CreateWindowEx(
        0,
        L"STATIC",
        NULL,
        WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0,
        m_hWnd,
        NULL,
        g_hInst,
        NULL
    );

    // Create the list view
    m_hCallbacksListView = CreateListView(m_hCallbacksPage, 10, 10, 860, 400, IDC_CALLBACKS_LISTVIEW);

    // Add columns
    AddListViewColumn(m_hCallbacksListView, 0, L"Callback Type", 150);
    AddListViewColumn(m_hCallbacksListView, 1, L"Address", 100);
    AddListViewColumn(m_hCallbacksListView, 2, L"Module", 200);
    AddListViewColumn(m_hCallbacksListView, 3, L"Offset", 100);

    // Create the refresh button
    m_hCallbacksRefreshButton = CreateWindowEx(
        0,
        L"BUTTON",
        L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 420, 100, 30,
        m_hWnd,  // Parent is main window instead of page
        (HMENU)IDC_REFRESH_BUTTON,
        g_hInst,
        NULL
    );

    // Set button position relative to page
    RECT pageRect;
    GetWindowRect(m_hCallbacksPage, &pageRect);
    MapWindowPoints(HWND_DESKTOP, m_hWnd, (LPPOINT)&pageRect, 2);
    SetWindowPos(m_hCallbacksRefreshButton, NULL,
        pageRect.left + 10, pageRect.top + 420,
        100, 30,
        SWP_NOZORDER);

    // Create the count label
    m_hCallbacksCountLabel = CreateWindowEx(
        0,
        L"STATIC",
        L"Callbacks: 0",
        WS_CHILD | WS_VISIBLE,
        120, 425, 200, 20,
        m_hCallbacksPage,
        NULL,
        g_hInst,
        NULL
    );
}

void MainForm::CreateRegistryCallbacksPage() {
    // Create the page window
    m_hRegistryCallbacksPage = CreateWindowEx(
        0,
        L"STATIC",
        NULL,
        WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0,
        m_hWnd,
        NULL,
        g_hInst,
        NULL
    );

    // Create the list view
    m_hRegistryCallbacksListView = CreateListView(m_hRegistryCallbacksPage, 10, 10, 860, 400, IDC_REGISTRY_CALLBACKS_LISTVIEW);

    // Add columns
    AddListViewColumn(m_hRegistryCallbacksListView, 0, L"Callback Type", 150);
    AddListViewColumn(m_hRegistryCallbacksListView, 1, L"Address", 100);
    AddListViewColumn(m_hRegistryCallbacksListView, 2, L"Module", 200);
    AddListViewColumn(m_hRegistryCallbacksListView, 3, L"Offset", 100);

    // Create the refresh button
    m_hRegistryCallbacksRefreshButton = CreateWindowEx(
        0,
        L"BUTTON",
        L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 420, 100, 30,
        m_hWnd,  // Parent is main window instead of page
        (HMENU)IDC_REFRESH_BUTTON,
        g_hInst,
        NULL
    );

    // Set button position relative to page
    RECT pageRect;
    GetWindowRect(m_hRegistryCallbacksPage, &pageRect);
    MapWindowPoints(HWND_DESKTOP, m_hWnd, (LPPOINT)&pageRect, 2);
    SetWindowPos(m_hRegistryCallbacksRefreshButton, NULL,
        pageRect.left + 10, pageRect.top + 420,
        100, 30,
        SWP_NOZORDER);

    // Create the count label
    m_hRegistryCallbacksCountLabel = CreateWindowEx(
        0,
        L"STATIC",
        L"Registry Callbacks: 0",
        WS_CHILD | WS_VISIBLE,
        120, 425, 200, 20,
        m_hRegistryCallbacksPage,
        NULL,
        g_hInst,
        NULL
    );
}

void MainForm::CreateMinifilterCallbacksPage() {
    // Create the page window
    m_hMinifilterCallbacksPage = CreateWindowEx(
        0,
        L"STATIC",
        NULL,
        WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0,
        m_hWnd,
        NULL,
        g_hInst,
        NULL
    );

    // Create the list view
    m_hMinifilterCallbacksListView = CreateListView(m_hMinifilterCallbacksPage, 10, 10, 860, 400, IDC_MINIFILTER_CALLBACKS_LISTVIEW);

    // Add columns
    AddListViewColumn(m_hMinifilterCallbacksListView, 0, L"Callback Type", 150);
    AddListViewColumn(m_hMinifilterCallbacksListView, 1, L"Address", 100);
    AddListViewColumn(m_hMinifilterCallbacksListView, 2, L"Module", 200);
    AddListViewColumn(m_hMinifilterCallbacksListView, 3, L"Offset", 100);

    // Create the refresh button
    m_hMinifilterCallbacksRefreshButton = CreateWindowEx(
        0,
        L"BUTTON",
        L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 420, 100, 30,
        m_hWnd,  // Parent is main window instead of page
        (HMENU)IDC_REFRESH_BUTTON,
        g_hInst,
        NULL
    );

    // Set button position relative to page
    RECT pageRect;
    GetWindowRect(m_hMinifilterCallbacksPage, &pageRect);
    MapWindowPoints(HWND_DESKTOP, m_hWnd, (LPPOINT)&pageRect, 2);
    SetWindowPos(m_hMinifilterCallbacksRefreshButton, NULL,
        pageRect.left + 10, pageRect.top + 420,
        100, 30,
        SWP_NOZORDER);

    // Create the count label
    m_hMinifilterCallbacksCountLabel = CreateWindowEx(
        0,
        L"STATIC",
        L"Minifilter Callbacks: 0",
        WS_CHILD | WS_VISIBLE,
        120, 425, 200, 20,
        m_hMinifilterCallbacksPage,
        NULL,
        g_hInst,
        NULL
    );
}

void MainForm::CreateSymbolsPage() {
    // Create the page window
    m_hSymbolsPage = CreateWindowEx(
        0,
        L"STATIC",
        NULL,
        WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0,
        m_hWnd,
        NULL,
        g_hInst,
        NULL
    );

    // Create the list view
    m_hSymbolsListView = CreateListView(m_hSymbolsPage, 10, 10, 860, 400, IDC_SYMBOLS_LISTVIEW);

    // Add columns
    AddListViewColumn(m_hSymbolsListView, 0, L"Symbol Name", 300);
    AddListViewColumn(m_hSymbolsListView, 1, L"Address", 100);
    AddListViewColumn(m_hSymbolsListView, 2, L"Module", 200);

    // Create the search edit control
    m_hSymbolsSearchEdit = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        NULL,
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        10, 420, 200, 30,
        m_hSymbolsPage,
        (HMENU)IDC_SEARCH_EDIT,
        g_hInst,
        NULL
    );

    // Create the search button
    m_hSymbolsSearchButton = CreateWindowEx(
        0,
        L"BUTTON",
        L"Search",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        220, 420, 100, 30,
        m_hSymbolsPage,
        (HMENU)IDC_SEARCH_BUTTON,
        g_hInst,
        NULL
    );

    // Create the refresh button
    m_hSymbolsRefreshButton = CreateWindowEx(
        0,
        L"BUTTON",
        L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        330, 420, 100, 30,
        m_hWnd,  // Parent is main window instead of page
        (HMENU)IDC_REFRESH_BUTTON,
        g_hInst,
        NULL
    );

    // Set button position relative to page
    RECT pageRect;
    GetWindowRect(m_hSymbolsPage, &pageRect);
    MapWindowPoints(HWND_DESKTOP, m_hWnd, (LPPOINT)&pageRect, 2);
    SetWindowPos(m_hSymbolsRefreshButton, NULL,
        pageRect.left + 330, pageRect.top + 420,
        100, 30,
        SWP_NOZORDER);

    // Create the count label
    m_hSymbolsCountLabel = CreateWindowEx(
        0,
        L"STATIC",
        L"Symbols: 0",
        WS_CHILD | WS_VISIBLE,
        440, 425, 200, 20,
        m_hSymbolsPage,
        NULL,
        g_hInst,
        NULL
    );
}

void MainForm::CreateAboutPage() {
    // Create the page window
    m_hAboutPage = CreateWindowEx(
        0,
        L"STATIC",
        NULL,
        WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0,
        m_hWnd,
        NULL,
        g_hInst,
        NULL
    );

    // Create the about label
    m_hAboutLabel = CreateWindowEx(
        0,
        L"STATIC",
        L"elemetryClient v1.0\n\n"
        L"A tool for enumerating driver modules and callbacks\n\n"
        L"Created by [Your Name]\n"
        L"GitHub: [Your GitHub]",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        0, 0, 0, 0,
        m_hAboutPage,
        NULL,
        g_hInst,
        NULL
    );
}

void MainForm::ResizeWindow() {
    RECT rcClient;
    GetClientRect(m_hWnd, &rcClient);

    // Resize the status bar
    SendMessage(m_hStatusBar, WM_SIZE, 0, 0);

    // Get the status bar height
    RECT rcStatus;
    GetWindowRect(m_hStatusBar, &rcStatus);
    int statusHeight = rcStatus.bottom - rcStatus.top;

    // Resize the tab control
    SetWindowPos(m_hTabControl, NULL,
        0, 0,
        rcClient.right, rcClient.bottom - statusHeight,
        SWP_NOZORDER);

    // Get the tab control display area
    RECT rcTab;
    GetClientRect(m_hTabControl, &rcTab);
    TabCtrl_AdjustRect(m_hTabControl, FALSE, &rcTab);

    // Resize all pages
    SetWindowPos(m_hDriverModulesPage, NULL,
        rcTab.left, rcTab.top,
        rcTab.right - rcTab.left, rcTab.bottom - rcTab.top,
        SWP_NOZORDER);

    SetWindowPos(m_hCallbacksPage, NULL,
        rcTab.left, rcTab.top,
        rcTab.right - rcTab.left, rcTab.bottom - rcTab.top,
        SWP_NOZORDER);

    SetWindowPos(m_hRegistryCallbacksPage, NULL,
        rcTab.left, rcTab.top,
        rcTab.right - rcTab.left, rcTab.bottom - rcTab.top,
        SWP_NOZORDER);

    SetWindowPos(m_hMinifilterCallbacksPage, NULL,
        rcTab.left, rcTab.top,
        rcTab.right - rcTab.left, rcTab.bottom - rcTab.top,
        SWP_NOZORDER);

    SetWindowPos(m_hSymbolsPage, NULL,
        rcTab.left, rcTab.top,
        rcTab.right - rcTab.left, rcTab.bottom - rcTab.top,
        SWP_NOZORDER);

    SetWindowPos(m_hAboutPage, NULL,
        rcTab.left, rcTab.top,
        rcTab.right - rcTab.left, rcTab.bottom - rcTab.top,
        SWP_NOZORDER);

    // Center the about label
    RECT rcAbout;
    GetClientRect(m_hAboutPage, &rcAbout);
    SetWindowPos(m_hAboutLabel, NULL,
        (rcAbout.right - rcAbout.left) / 2 - 200,
        (rcAbout.bottom - rcAbout.top) / 2 - 100,
        400, 200,
        SWP_NOZORDER);
}

void MainForm::UpdateDriverModules() {
    // Clear the list view
    ListView_DeleteAllItems(m_hDriverModulesListView);

    // Get driver modules
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        MessageBox(m_hWnd, L"Failed to open driver handle", L"Error", MB_ICONERROR);
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
        DWORD error = GetLastError();
        wchar_t errorMsg[256];
        swprintf_s(errorMsg, L"DeviceIoControl failed with error: %d", error);
        MessageBox(m_hWnd, errorMsg, L"Error", MB_ICONERROR);
        CloseHandle(deviceHandle);
        return;
    }

    // Calculate number of modules returned
    DWORD moduleCount = bytesReturned / sizeof(MODULE_INFO);

    // Add items to the list view
    for (DWORD i = 0; i < moduleCount; i++) {
        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = ListView_GetItemCount(m_hDriverModulesListView);

        // Module name
        lvi.iSubItem = 0;
        lvi.pszText = moduleInfos[i].Path;
        ListView_InsertItem(m_hDriverModulesListView, &lvi);

        // Base address
        wchar_t addrBuffer[32];
        swprintf_s(addrBuffer, L"0x%llX", (ULONG_PTR)moduleInfos[i].BaseAddress);
        ListView_SetItemText(m_hDriverModulesListView, lvi.iItem, 1, addrBuffer);

        // Size
        wchar_t sizeBuffer[32];
        swprintf_s(sizeBuffer, L"%u", moduleInfos[i].Size);
        ListView_SetItemText(m_hDriverModulesListView, lvi.iItem, 2, sizeBuffer);

        // Flags
        wchar_t flagsBuffer[32];
        swprintf_s(flagsBuffer, L"0x%X", moduleInfos[i].Flags);
        ListView_SetItemText(m_hDriverModulesListView, lvi.iItem, 3, flagsBuffer);
    }

    CloseHandle(deviceHandle);

    // Update the count label
    wchar_t countBuffer[32];
    swprintf_s(countBuffer, L"Modules: %d", ListView_GetItemCount(m_hDriverModulesListView));
    SetWindowText(m_hDriverModulesCountLabel, countBuffer);
}

void MainForm::UpdateCallbacks() {
    // Clear the list view
    ListView_DeleteAllItems(m_hCallbacksListView);

    int len = 0;

    // Open a handle to the driver
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return;
    }

    const DWORD bufferSize = sizeof(CALLBACK_INFO_SHARED) * MAX_CALLBACKS_SHARED;
    std::vector<BYTE> buffer(bufferSize, 0);
    PCALLBACK_INFO_SHARED callbackInfos = reinterpret_cast<PCALLBACK_INFO_SHARED>(buffer.data());
    ULONG foundCallbacks = 0;

    // Load Image Callbacks
    if (EnumerateCallbacksWithSymbolTable(deviceHandle, CallbackTableLoadImage, SYMBOL_LOAD_IMAGE_CALLBACKS, callbackInfos, MAX_CALLBACKS_SHARED, foundCallbacks)) {
        for (ULONG i = 0; i < foundCallbacks; i++) {
            LVITEM lvi = { 0 };
            lvi.mask = LVIF_TEXT;
            lvi.iItem = ListView_GetItemCount(m_hCallbacksListView);
            lvi.iSubItem = 0;
            wchar_t typeBuffer[32];
            wcscpy_s(typeBuffer, L"Load Image");
            lvi.pszText = typeBuffer;
            ListView_InsertItem(m_hCallbacksListView, &lvi);
            wchar_t addrBuffer[32];
            swprintf_s(addrBuffer, L"0x%llX", (ULONG_PTR)callbackInfos[i].Address);
            ListView_SetItemText(m_hCallbacksListView, lvi.iItem, 1, addrBuffer);
            char safeModuleName[256];
            strncpy(safeModuleName, callbackInfos[i].ModuleName, 255);
            safeModuleName[255] = '\0';
            wchar_t moduleBuffer[256];
            int len = (int)strnlen(safeModuleName, 255);
            if (len > 0)
                MultiByteToWideChar(CP_ACP, 0, safeModuleName, len, moduleBuffer, 256);
            moduleBuffer[len] = L'\0';
            ListView_SetItemText(m_hCallbacksListView, lvi.iItem, 2, moduleBuffer);
        }
    }

    // Process Creation Callbacks
    if (EnumerateCallbacksWithSymbolTable(deviceHandle, CallbackTableCreateProcess, SYMBOL_PROCESS_CALLBACKS, callbackInfos, MAX_CALLBACKS_SHARED, foundCallbacks)) {
        for (ULONG i = 0; i < foundCallbacks; i++) {
            LVITEM lvi = { 0 };
            lvi.mask = LVIF_TEXT;
            lvi.iItem = ListView_GetItemCount(m_hCallbacksListView);
            lvi.iSubItem = 0;
            wchar_t typeBuffer[32];
            wcscpy_s(typeBuffer, L"Process Creation");
            lvi.pszText = typeBuffer;
            ListView_InsertItem(m_hCallbacksListView, &lvi);
            wchar_t addrBuffer[32];
            swprintf_s(addrBuffer, L"0x%llX", (ULONG_PTR)callbackInfos[i].Address);
            ListView_SetItemText(m_hCallbacksListView, lvi.iItem, 1, addrBuffer);
            char safeModuleName[256];
            strncpy(safeModuleName, callbackInfos[i].ModuleName, 255);
            safeModuleName[255] = '\0';
            wchar_t moduleBuffer[256];
            len = (int)strnlen(safeModuleName, 255);
            if (len > 0)
                MultiByteToWideChar(CP_ACP, 0, safeModuleName, len, moduleBuffer, 256);
            moduleBuffer[len] = L'\0';
            ListView_SetItemText(m_hCallbacksListView, lvi.iItem, 2, moduleBuffer);
        }
    }

    // Thread Creation Callbacks
    if (EnumerateCallbacksWithSymbolTable(deviceHandle, CallbackTableCreateThread, SYMBOL_THREAD_CALLBACKS, callbackInfos, MAX_CALLBACKS_SHARED, foundCallbacks)) {
        for (ULONG i = 0; i < foundCallbacks; i++) {
            LVITEM lvi = { 0 };
            lvi.mask = LVIF_TEXT;
            lvi.iItem = ListView_GetItemCount(m_hCallbacksListView);
            lvi.iSubItem = 0;
            wchar_t typeBuffer[32];
            wcscpy_s(typeBuffer, L"Thread Creation");
            lvi.pszText = typeBuffer;
            ListView_InsertItem(m_hCallbacksListView, &lvi);
            wchar_t addrBuffer[32];
            swprintf_s(addrBuffer, L"0x%llX", (ULONG_PTR)callbackInfos[i].Address);
            ListView_SetItemText(m_hCallbacksListView, lvi.iItem, 1, addrBuffer);
            char safeModuleName[256];
            strncpy(safeModuleName, callbackInfos[i].ModuleName, 255);
            safeModuleName[255] = '\0';
            wchar_t moduleBuffer[256];
            len = (int)strnlen(safeModuleName, 255);
            if (len > 0)
                MultiByteToWideChar(CP_ACP, 0, safeModuleName, len, moduleBuffer, 256);
            moduleBuffer[len] = L'\0';
            ListView_SetItemText(m_hCallbacksListView, lvi.iItem, 2, moduleBuffer);
        }
    }

    CloseHandle(deviceHandle);

    // Update the count label
    wchar_t countBuffer[32];
    swprintf_s(countBuffer, L"Callbacks: %d", ListView_GetItemCount(m_hCallbacksListView));
    SetWindowText(m_hCallbacksCountLabel, countBuffer);
}

void MainForm::UpdateRegistryCallbacks() {
    // Clear the list view
    ListView_DeleteAllItems(m_hRegistryCallbacksListView);

    int len = 0;

    // Open a handle to the driver
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return;
    }

    const DWORD bufferSize = sizeof(CALLBACK_INFO_SHARED) * MAX_CALLBACKS_SHARED;
    std::vector<BYTE> buffer(bufferSize, 0);
    PCALLBACK_INFO_SHARED callbackInfos = reinterpret_cast<PCALLBACK_INFO_SHARED>(buffer.data());
    ULONG foundCallbacks = 0;

    if (TryEnumerateRegistryCallbacks(deviceHandle, callbackInfos, MAX_CALLBACKS_SHARED, foundCallbacks)) {
        for (ULONG i = 0; i < foundCallbacks; i++) {
            LVITEM lvi = { 0 };
            lvi.mask = LVIF_TEXT;
            lvi.iItem = ListView_GetItemCount(m_hRegistryCallbacksListView);
            lvi.iSubItem = 0;
            wchar_t typeBuffer[32];
            wcscpy_s(typeBuffer, L"Registry");
            lvi.pszText = typeBuffer;
            ListView_InsertItem(m_hRegistryCallbacksListView, &lvi);
            wchar_t addrBuffer[32];
            swprintf_s(addrBuffer, L"0x%llX", (ULONG_PTR)callbackInfos[i].Address);
            ListView_SetItemText(m_hRegistryCallbacksListView, lvi.iItem, 1, addrBuffer);
            char safeModuleName[256];
            strncpy(safeModuleName, callbackInfos[i].ModuleName, 255);
            safeModuleName[255] = '\0';
            wchar_t moduleBuffer[256];
            len = (int)strnlen(safeModuleName, 255);
            if (len > 0)
                MultiByteToWideChar(CP_ACP, 0, safeModuleName, len, moduleBuffer, 256);
            moduleBuffer[len] = L'\0';
            ListView_SetItemText(m_hRegistryCallbacksListView, lvi.iItem, 2, moduleBuffer);
        }
    }

    CloseHandle(deviceHandle);

    // Update the count label
    wchar_t countBuffer[32];
    swprintf_s(countBuffer, L"Registry Callbacks: %d", ListView_GetItemCount(m_hRegistryCallbacksListView));
    SetWindowText(m_hRegistryCallbacksCountLabel, countBuffer);
}

void MainForm::UpdateMinifilterCallbacks() {
    // Clear the list view
    ListView_DeleteAllItems(m_hMinifilterCallbacksListView);

    int len = 0;

    const DWORD bufferSize = sizeof(CALLBACK_INFO_SHARED) * MAX_CALLBACKS_SHARED;
    std::vector<BYTE> buffer(bufferSize, 0);
    PCALLBACK_INFO_SHARED callbackInfos = reinterpret_cast<PCALLBACK_INFO_SHARED>(buffer.data());
    ULONG foundCallbacks = 0;

    if (GetDriverMinifilterCallbacks(callbackInfos, MAX_CALLBACKS_SHARED, foundCallbacks)) {
        for (ULONG i = 0; i < foundCallbacks; i++) {
            LVITEM lvi = { 0 };
            lvi.mask = LVIF_TEXT;
            lvi.iItem = ListView_GetItemCount(m_hMinifilterCallbacksListView);
            lvi.iSubItem = 0;
            wchar_t typeBuffer[32];
            wcscpy_s(typeBuffer, L"Minifilter");
            lvi.pszText = typeBuffer;
            ListView_InsertItem(m_hMinifilterCallbacksListView, &lvi);
            wchar_t addrBuffer[32];
            swprintf_s(addrBuffer, L"0x%llX", (ULONG_PTR)callbackInfos[i].Address);
            ListView_SetItemText(m_hMinifilterCallbacksListView, lvi.iItem, 1, addrBuffer);
            char safeModuleName[256];
            strncpy(safeModuleName, callbackInfos[i].ModuleName, 255);
            safeModuleName[255] = '\0';
            wchar_t moduleBuffer[256];
            len = (int)strnlen(safeModuleName, 255);
            if (len > 0)
                MultiByteToWideChar(CP_ACP, 0, safeModuleName, len, moduleBuffer, 256);
            moduleBuffer[len] = L'\0';
            ListView_SetItemText(m_hMinifilterCallbacksListView, lvi.iItem, 2, moduleBuffer);
        }
    }

    // Update the count label
    wchar_t countBuffer[32];
    swprintf_s(countBuffer, L"Minifilter Callbacks: %d", ListView_GetItemCount(m_hMinifilterCallbacksListView));
    SetWindowText(m_hMinifilterCallbacksCountLabel, countBuffer);
}

void MainForm::UpdateSymbols() {
    // Clear the list view
    ListView_DeleteAllItems(m_hSymbolsListView);

    // Open a handle to the driver
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return;
    }

    // Load kernel module symbols
    LoadKernelModuleSymbols(deviceHandle);

    CloseHandle(deviceHandle);

    // Update the count label
    wchar_t buffer[32];
    swprintf_s(buffer, L"Symbols: %d", ListView_GetItemCount(m_hSymbolsListView));
    SetWindowText(m_hSymbolsCountLabel, buffer);
} 