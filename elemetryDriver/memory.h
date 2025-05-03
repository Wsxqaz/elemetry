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

// --- Kernel Memory Operations ---
extern NTSTATUS ReadKernelMemory(
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

// Util function for memory test read
extern "C" NTSTATUS TestReadAddress(
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PSIZE_T BytesRead
);


