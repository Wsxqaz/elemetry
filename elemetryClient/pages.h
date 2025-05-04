#pragma once

#include <Windows.h>
#include <commctrl.h>
#include <vector>
#include "elemetry.h"

// Forward declarations
class MainForm;

// Helper functions
HWND CreateListView(HWND hWndParent, int x, int y, int width, int height, DWORD id);
void AddListViewColumn(HWND hWndListView, int index, LPCWSTR text, int width);
std::vector<MODULE_INFO> GetDriverModules(HANDLE deviceHandle, DWORD& moduleCount); 