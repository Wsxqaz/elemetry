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

// --- Initialization and Cleanup ---
NTSTATUS InitializeCallbackTracking();
VOID CleanupCallbackTracking();

// --- Module Operations ---
NTSTATUS GetDynamicModules(
    _Out_writes_bytes_opt_(OutputBufferLength) PMODULE_INFO OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWrittenOrRequired
);

// New function to get system modules similar to TelemetrySourcerer
NTSTATUS GetSystemModules(
    _Out_writes_bytes_opt_(OutputBufferLength) PMODULE_INFO OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWrittenOrRequired
);

// --- IOCTL Handlers ---
NTSTATUS HandleGetModulesIOCTL(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack);
extern "C" NTSTATUS HandleEnumerateCallbacksIOCTL(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack);

// --- PE Parsing Helper ---
NTSTATUS ParseModuleExports(_Inout_ PPE_PARSE_CONTEXT ParseContext);

// --- Callback Enumeration ---
NTSTATUS EnumerateCallbacks(
    _In_ PENUM_CALLBACKS_CALLBACK EnumCallback,
    _In_opt_ PVOID Context
);

// --- Kernel Memory Operations ---
NTSTATUS ReadKernelMemory(
    _In_ PVOID KernelAddress,
    _Out_writes_bytes_(Size) PVOID UserBuffer,
    _In_ SIZE_T Size,
    _Out_ PSIZE_T BytesRead
);

// Protected read helper
extern "C" NTSTATUS ReadProtectedKernelMemory(
    _In_ PVOID KernelAddress,
    _Out_writes_bytes_(Size) PVOID OutputBuffer,
    _In_ SIZE_T Size,
    _Out_ PSIZE_T BytesRead
);

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

// --- Callback Management ---
NTSTATUS RegisterCallback(PCALLBACK_INFO_SHARED CallbackInfo);
ULONG GetCallbackCount();
NTSTATUS GetCallbackByIndex(_In_ ULONG Index, _Out_ PCALLBACK_INFO_SHARED SharedCallbackInfo);
NTSTATUS GetCallbackByName(_In_ PCSTR CallbackName, _Out_ PCALLBACK_INFO_SHARED SharedCallbackInfo);
NTSTATUS GetCallbackByAddress(_In_ PVOID CallbackAddress, _Out_ PCALLBACK_INFO_SHARED SharedCallbackInfo);

// Forward declaration of DriverUnload function
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

// NO #endif here unless there was a matching #ifdef earlier
