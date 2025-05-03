#pragma once

#include <Windows.h>
#include "elemetry.h"

// Function declarations for callback enumeration
bool EnumerateCallbacksWithSymbolTable(
    HANDLE deviceHandle,
    CALLBACK_TABLE_TYPE tableType,
    const char* symbolName,
    PCALLBACK_INFO_SHARED outBuffer,
    ULONG maxCallbacks,
    ULONG& foundCallbacks
);
bool TryEnumerateRegistryCallbacks(HANDLE deviceHandle, PCALLBACK_INFO_SHARED outBuffer, ULONG maxCallbacks, ULONG& foundCallbacks);
bool GetDriverMinifilterCallbacks(PCALLBACK_INFO_SHARED outBuffer, ULONG maxCallbacks, ULONG& foundCallbacks); 