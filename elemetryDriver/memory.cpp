// Disable specific warnings
#pragma warning(disable: 4505) // Disable "unreferenced local function has been removed" warning
#pragma warning(disable: 4100) // Disable "unreferenced formal parameter" warning
#pragma warning(disable: 4201) // Disable "nameless struct/union" warning

// Include Windows headers with correct defines
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000000  // Windows 10
#endif

// Include Filter Manager headers
#include <fltKernel.h>
#include <ntddk.h>
#include <ntifs.h>
#include <aux_klib.h>  // For AuxKlib functions and structures

// Include Common.h FIRST for shared definitions
#include "Common.h"    // Project common definitions
#include "callbacks.h" // Function prototypes

// Include other headers in proper order
#include <wdm.h>       // Windows Driver Model
#include <ntstrsafe.h> // String functions
#include <ntimage.h>   // PE image parsing and loader structures

// Define pool flags if not available in current SDK
#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED  0x0000000000000040ULL
#endif

#ifndef POOL_FLAG_ZERO_ALLOCATION
#define POOL_FLAG_ZERO_ALLOCATION 0x0000000000000100ULL
#endif

// Fix unused status variable in ReadKernelMemory function
NTSTATUS ReadKernelMemory(
    _In_ PVOID KernelAddress,
    _Out_writes_bytes_(Size) PVOID UserBuffer,
    _In_ SIZE_T Size,
    _Out_ PSIZE_T BytesRead
)
{
    *BytesRead = 0;

    // Basic input validation
    if (!KernelAddress || !UserBuffer || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        // ProbeForRead validates memory can be safely read
        ProbeForRead(KernelAddress, Size, 1);

        // Use MmCopyMemory which is safer than direct memcpy
        MM_COPY_ADDRESS sourceAddress;
        sourceAddress.VirtualAddress = KernelAddress;

        return MmCopyMemory(
            UserBuffer,
            sourceAddress,
            Size,
            MM_COPY_MEMORY_VIRTUAL,
            BytesRead
        );
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS exceptionStatus = GetExceptionCode();
        DbgPrint("[elemetry] ReadKernelMemory: Exception 0x%X while reading memory at %p\n",
                exceptionStatus, KernelAddress);
        *BytesRead = 0;
        return exceptionStatus;
    }
}

// More robust kernel memory read function for protected areas
extern "C" NTSTATUS ReadProtectedKernelMemory(
    _In_ PVOID KernelAddress,
    _Out_writes_bytes_(Size) PVOID OutputBuffer,
    _In_ SIZE_T Size,
    _Out_ PSIZE_T BytesRead
)
{
    *BytesRead = 0;

    // Basic validation
    if (!KernelAddress || !OutputBuffer || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Use a different approach with MDL for reading protected memory
    PMDL mdl = NULL;
    PVOID mappedAddress = NULL;

    __try {
        // Create an MDL for the target memory
        mdl = IoAllocateMdl(KernelAddress, (ULONG)Size, FALSE, FALSE, NULL);
        if (!mdl) {
            DbgPrint("[elemetry] ReadProtectedKernelMemory: Failed to allocate MDL\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Try to probe and lock the pages
        __try {
            // Force mapping even for memory we don't normally have direct write access to
            MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            IoFreeMdl(mdl);
            DbgPrint("[elemetry] ReadProtectedKernelMemory: Exception 0x%X in MmProbeAndLockPages\n", GetExceptionCode());
            return STATUS_ACCESS_VIOLATION;
        }

        // Map the locked pages
        mappedAddress = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
        if (!mappedAddress) {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            DbgPrint("[elemetry] ReadProtectedKernelMemory: MmGetSystemAddressForMdlSafe failed\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Now copy from the mapped address to the output buffer
        RtlCopyMemory(OutputBuffer, mappedAddress, Size);
        *BytesRead = Size;

        // Clean up
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        DbgPrint("[elemetry] ReadProtectedKernelMemory: Successfully read %llu bytes from %p\n",
                 (ULONGLONG)Size, KernelAddress);

        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Clean up if exception occurs
        if (mdl) {
            if (mappedAddress) {
                MmUnlockPages(mdl);
            }
            IoFreeMdl(mdl);
        }

        NTSTATUS exceptionCode = GetExceptionCode();
        DbgPrint("[elemetry] ReadProtectedKernelMemory: Exception 0x%X while reading memory at %p\n",
                 exceptionCode, KernelAddress);
        return exceptionCode;
    }
}

// Util function for memory test read
extern "C" NTSTATUS TestReadAddress(
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PSIZE_T BytesRead
)
{
    NTSTATUS status = STATUS_SUCCESS;
    *BytesRead = 0;

    // Basic validation
    if (!Address || !Buffer || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ReadKernelMemory(Address, Buffer, Size, BytesRead);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] TestReadAddress: Failed to read memory at %p: 0x%X\n", Address, status);

        // Try protected read if normal read fails
        status = ReadProtectedKernelMemory(Address, Buffer, Size, BytesRead);

        if (!NT_SUCCESS(status)) {
            DbgPrint("[elemetry] TestReadAddress: Protected read also failed at %p: 0x%X\n", Address, status);
            return status;
        }
    }

    return status;
}

