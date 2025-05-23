#pragma once

// Define NTDDI_VERSION before including any Windows headers
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000000
#endif

// Include Common.h FIRST for shared definitions
#include "Common.h"

// Include other necessary headers
#include <ntdef.h>
#include <ntddk.h>
#include <ntstrsafe.h>

// Declare extern global constants/variables defined in callbacks.cpp
extern const ULONG g_HardcodedModuleCount; // Allow elemetryDriver.cpp to see this

// Define DRIVER_TAG for memory allocation
#define DRIVER_TAG 'ELMT'  // Elemetry Driver Tag

// Internal storage for found module information
extern MODULE_INFO* g_FoundModules;
extern ULONG g_ModuleCount;
extern BOOLEAN g_ModulesInitialized;


// --- Initialization and Cleanup ---
VOID CleanupCallbackTracking();

extern "C" PIRP GetCurrentIrpSafe();

// --- Module Operations ---
NTSTATUS GetDynamicModules(
    _Out_writes_bytes_opt_(OutputBufferLength) PMODULE_INFO OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWrittenOrRequired
);

NTSTATUS GetSystemModules(
    _Out_writes_bytes_opt_(OutputBufferLength) PMODULE_INFO OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWrittenOrRequired
);

// --- IOCTL Handlers ---
NTSTATUS HandleGetModulesIOCTL(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack);
extern "C" NTSTATUS HandleEnumerateCallbacksIOCTL(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack);
extern "C" NTSTATUS HandleEnumerateLoadImageCallbacksIOCTL(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack);

// --- Callback Enumeration Functions ---
extern "C" NTSTATUS EnumerateLoadImageCallbacks(
    _In_opt_ PVOID CallbackTable,
    _Out_writes_to_(MaxCallbacks, *FoundCallbacks) PCALLBACK_INFO_SHARED CallbackArray,
    _In_ ULONG MaxCallbacks,
    _Out_ PULONG FoundCallbacks
);

NTSTATUS EnumerateCreateProcessCallbacks(
    _In_opt_ PVOID CallbackTable,
    _Out_writes_to_(MaxCallbacks, *FoundCallbacks) PCALLBACK_INFO_SHARED CallbackArray,
    _In_ ULONG MaxCallbacks,
    _Out_ PULONG FoundCallbacks
);

NTSTATUS EnumerateCreateThreadCallbacks(
    _In_opt_ PVOID CallbackTable,
    _Out_writes_to_(MaxCallbacks, *FoundCallbacks) PCALLBACK_INFO_SHARED CallbackArray,
    _In_ ULONG MaxCallbacks,
    _Out_ PULONG FoundCallbacks
);

NTSTATUS EnumerateRegistryCallbacks(
    _In_opt_ PVOID CallbackTable,
    _Out_writes_to_(MaxCallbacks, *FoundCallbacks) PCALLBACK_INFO_SHARED CallbackArray,
    _In_ ULONG MaxCallbacks,
    _Out_ PULONG FoundCallbacks
);

NTSTATUS EnumerateFilesystemCallbacks(
    _Out_writes_to_(MaxCallbacks, *FoundCallbacks) PCALLBACK_INFO_SHARED CallbackArray,
    _In_ ULONG MaxCallbacks,
    _Out_ PULONG FoundCallbacks
);


// Forward declaration of DriverUnload function
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

// NO #endif here unless there was a matching #ifdef earlier
