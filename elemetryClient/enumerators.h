#pragma once

#include <Windows.h>
#include "elemetry.h"

// Function declarations for callback enumeration
bool EnumerateCallbacksWithSymbolTable(
    HANDLE deviceHandle,
    CALLBACK_TABLE_TYPE type,
    const char* symbolName,
    PCALLBACK_INFO_SHARED callbacks,
    ULONG maxCallbacks,
    ULONG& foundCallbacks
);
bool TryEnumerateRegistryCallbacks(HANDLE deviceHandle, PCALLBACK_INFO_SHARED callbacks, ULONG maxCallbacks, ULONG& foundCallbacks);
bool GetDriverMinifilterCallbacks(PCALLBACK_INFO_SHARED callbacks, ULONG maxCallbacks, ULONG& foundCallbacks); 