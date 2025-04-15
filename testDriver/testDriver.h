#pragma once

#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

// Callback declarations
VOID OnImageLoadCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
);

VOID OnProcessCreateCallback(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
);

VOID OnThreadCreateCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
);

NTSTATUS OnRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
);

// Function to initialize callbacks
NTSTATUS InitializeCallbacks(); 