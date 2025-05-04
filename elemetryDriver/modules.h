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

extern NTSTATUS GetDynamicModules(
    _Out_writes_bytes_opt_(OutputBufferLength) PMODULE_INFO OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWrittenOrRequired
);

