#include "enumerators.h"
#include "symbols.h"
#include "driver.h"
#include <vector>
#include <iostream>
#include <DbgHelp.h>

// Function to enumerate callbacks with symbol lookup
bool EnumerateCallbacksWithSymbolTable(
    HANDLE deviceHandle,
    CALLBACK_TABLE_TYPE tableType,
    const char* symbolName,
    PCALLBACK_INFO_SHARED outBuffer,
    ULONG maxCallbacks,
    ULONG& foundCallbacks
) {
    foundCallbacks = 0;
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

    // Get the address of the symbol
    DWORD64 symbolAddress = 0;
    if (LookupSymbol(deviceHandle, symbolName, symbolAddress) == -1) {
        std::cerr << "Failed to look up symbol: " << symbolName << std::endl;
        SymCleanup(hProcess);
        return false;
    }

    ULONG requestSize = sizeof(CALLBACK_ENUM_REQUEST) + (maxCallbacks - 1) * sizeof(CALLBACK_INFO_SHARED);
    std::vector<BYTE> requestBuffer(requestSize, 0);
    PCALLBACK_ENUM_REQUEST request = reinterpret_cast<PCALLBACK_ENUM_REQUEST>(requestBuffer.data());

    request->Type = tableType;
    request->TableAddress = (PVOID)symbolAddress;
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

    if (!success) {
        std::cerr << "Failed to enumerate callbacks. Error code: " << GetLastError() << std::endl;
        SymCleanup(hProcess);
        return false;
    }

    foundCallbacks = request->FoundCallbacks;
    if (outBuffer && foundCallbacks > 0) {
        ULONG toCopy = (foundCallbacks > maxCallbacks) ? maxCallbacks : foundCallbacks;
        memcpy(outBuffer, request->Callbacks, toCopy * sizeof(CALLBACK_INFO_SHARED));
    }

    SymCleanup(hProcess);
    return true;
}

bool TryEnumerateRegistryCallbacks(HANDLE deviceHandle, PCALLBACK_INFO_SHARED outBuffer, ULONG maxCallbacks, ULONG& foundCallbacks) {
    foundCallbacks = 0;
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "Invalid device handle." << std::endl;
        return false;
    }

    for (int i = 0; i < ALT_REGISTRY_COUNT; i++) {
        if (EnumerateCallbacksWithSymbolTable(deviceHandle, CallbackTableRegistry, ALT_REGISTRY_CALLBACKS[i], outBuffer, maxCallbacks, foundCallbacks)) {
            if (foundCallbacks > 0) return true;
        }
    }
    return false;
}

bool GetDriverMinifilterCallbacks(PCALLBACK_INFO_SHARED outBuffer, ULONG maxCallbacks, ULONG& foundCallbacks) {
    foundCallbacks = 0;
    HANDLE deviceHandle = OpenDriverHandle();
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    bool success = EnumerateCallbacksWithSymbolTable(deviceHandle, CallbackTableFilesystem, "FltGlobals", outBuffer, maxCallbacks, foundCallbacks);
    CloseHandle(deviceHandle);
    return success && foundCallbacks > 0;
} 