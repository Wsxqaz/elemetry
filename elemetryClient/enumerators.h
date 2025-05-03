#pragma once

#include <Windows.h>
#include "elemetry.h"

// Function declarations for callback enumeration
bool EnumerateCallbacksWithSymbolTable(HANDLE deviceHandle, CALLBACK_TABLE_TYPE tableType, const char* symbolName);
bool TryEnumerateRegistryCallbacks(HANDLE deviceHandle);
bool GetDriverMinifilterCallbacks(); 