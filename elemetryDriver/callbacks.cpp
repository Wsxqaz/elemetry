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
#include "memory.h"    // Memory read/write functions

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

// Global callback tracking array - using the shared struct
CALLBACK_INFO_SHARED g_CallbackInfo[MAX_CALLBACKS_SHARED];
ULONG g_CallbackCount = 0;

// Define the number of hardcoded modules we are looking for
#define INITIAL_MODULE_BUFFER_SIZE 1024  // Initial buffer size for module enumeration

// Keep const for logic, but use define for array sizes
const ULONG g_ModuleCountMax = INITIAL_MODULE_BUFFER_SIZE;
MODULE_INFO* g_FoundModules = NULL;
ULONG g_ModuleCount = 0;
BOOLEAN g_ModulesInitialized = FALSE;


// Define static buffers
#define MODULE_INFO_BUFFER_SIZE 2144  // Size needed for output modules
#define SYSTEM_MODULE_BUFFER_SIZE 96000  // Size needed for system module info (increased from 47368)

// Function pointers that may not be available in older Windows versions


NTSTATUS GetDynamicModules(
    _Out_writes_bytes_opt_(OutputBufferLength) PMODULE_INFO OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWrittenOrRequired
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG foundCount = 0;

    // Check if we're at PASSIVE_LEVEL
    KIRQL CurrentIrql = KeGetCurrentIrql();
    if (CurrentIrql > PASSIVE_LEVEL) {
        DbgPrint("[elemetry] GetDynamicModules: Running at IRQL %d, need PASSIVE_LEVEL\n", CurrentIrql);
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!OutputBuffer) {
        DbgPrint("[elemetry] GetDynamicModules: Invalid output buffer pointer.\n");
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        // Initialize AuxKlib for additional module information
        status = AuxKlibInitialize();
        if (!NT_SUCCESS(status)) {
            DbgPrint("[elemetry] GetDynamicModules: Failed to initialize AuxKlib: 0x%X\n", status);
            // Continue with ZwQuerySystemInformation as fallback
        }

        // First try with ZwQuerySystemInformation
        ULONG SystemInfoLength = SYSTEM_MODULE_BUFFER_SIZE;
        status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &SystemInfoLength);
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            DbgPrint("[elemetry] GetDynamicModules: Failed to get required size: 0x%X\n", status);
            return status;
        }

        // Allocate buffer for module information
        PSYSTEM_MODULE_INFORMATION ModuleInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            SystemInfoLength,
            DRIVER_TAG
        );

        if (!ModuleInfo) {
            DbgPrint("[elemetry] GetDynamicModules: Failed to allocate module info buffer\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Get actual module information
        status = ZwQuerySystemInformation(SystemModuleInformation, ModuleInfo, SystemInfoLength, &SystemInfoLength);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[elemetry] GetDynamicModules: Failed to get module information: 0x%X\n", status);
            ExFreePoolWithTag(ModuleInfo, DRIVER_TAG);
            return status;
        }

        // Allocate or reallocate internal storage if needed
        if (!g_FoundModules) {
            g_FoundModules = (PMODULE_INFO)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                ModuleInfo->Count * sizeof(MODULE_INFO),
                DRIVER_TAG
            );
            if (!g_FoundModules) {
                DbgPrint("[elemetry] GetDynamicModules: Failed to allocate internal storage\n");
                ExFreePoolWithTag(ModuleInfo, DRIVER_TAG);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        } else if (g_ModuleCount < ModuleInfo->Count) {
            ExFreePoolWithTag(g_FoundModules, DRIVER_TAG);
            g_FoundModules = (PMODULE_INFO)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                ModuleInfo->Count * sizeof(MODULE_INFO),
                DRIVER_TAG
            );
            if (!g_FoundModules) {
                DbgPrint("[elemetry] GetDynamicModules: Failed to reallocate internal storage\n");
                ExFreePoolWithTag(ModuleInfo, DRIVER_TAG);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        // Zero out the internal storage before populating
        RtlZeroMemory(g_FoundModules, ModuleInfo->Count * sizeof(MODULE_INFO));

        // Process each module from ZwQuerySystemInformation
        for (ULONG i = 0; i < ModuleInfo->Count; i++) {
            // Skip modules with NULL base address
            if (ModuleInfo->Modules[i].ImageBase == NULL) {
                continue;
            }

            // Store module information
            g_FoundModules[foundCount].BaseAddress = ModuleInfo->Modules[i].ImageBase;
            g_FoundModules[foundCount].Size = ModuleInfo->Modules[i].ImageSize;
            g_FoundModules[foundCount].Flags = 0;

            // Convert module name from ANSI to Unicode
            ANSI_STRING ansiName;
            UNICODE_STRING unicodeName;
            RtlInitAnsiString(&ansiName, ModuleInfo->Modules[i].ImageName);
            RtlAnsiStringToUnicodeString(&unicodeName, &ansiName, TRUE);

            // Copy the module path
            wcscpy_s(g_FoundModules[foundCount].Path, MAX_PATH, unicodeName.Buffer);
            RtlFreeUnicodeString(&unicodeName);

            // Copy to output buffer if provided and there's space
            if (OutputBuffer && (foundCount * sizeof(MODULE_INFO)) < OutputBufferLength) {
                RtlCopyMemory(&OutputBuffer[foundCount], &g_FoundModules[foundCount], sizeof(MODULE_INFO));
            }

            foundCount++;
        }

        // Now try with AuxKlib for additional modules
        if (NT_SUCCESS(AuxKlibInitialize())) {
            ULONG AuxModulesBufferSize = 0;
            status = AuxKlibQueryModuleInformation(&AuxModulesBufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), nullptr);
            if (NT_SUCCESS(status) && AuxModulesBufferSize > 0) {
                PAUX_MODULE_EXTENDED_INFO AuxModuleInfo = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    AuxModulesBufferSize,
                    DRIVER_TAG
                );

                if (AuxModuleInfo) {
                    status = AuxKlibQueryModuleInformation(&AuxModulesBufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), AuxModuleInfo);
                    if (NT_SUCCESS(status)) {
                        ULONG AuxModuleCount = AuxModulesBufferSize / sizeof(AUX_MODULE_EXTENDED_INFO);

                        // Check for modules not found in the first enumeration
                        for (ULONG i = 0; i < AuxModuleCount; i++) {
                            BOOLEAN alreadyFound = FALSE;

                            // Check if this module was already found
                            for (ULONG j = 0; j < foundCount; j++) {
                                if (g_FoundModules[j].BaseAddress == AuxModuleInfo[i].BasicInfo.ImageBase) {
                                    alreadyFound = TRUE;
                                    break;
                                }
                            }

                            if (!alreadyFound) {
                                // Reallocate internal storage if needed
                                if (foundCount >= g_ModuleCount) {
                                    PMODULE_INFO newModules = (PMODULE_INFO)ExAllocatePool2(
                                        POOL_FLAG_NON_PAGED,
                                        (foundCount + 1) * sizeof(MODULE_INFO),
                                        DRIVER_TAG
                                    );
                                    if (!newModules) {
                                        DbgPrint("[elemetry] GetDynamicModules: Failed to reallocate for additional modules\n");
                                        break;
                                    }

                                    RtlCopyMemory(newModules, g_FoundModules, foundCount * sizeof(MODULE_INFO));
                                    ExFreePoolWithTag(g_FoundModules, DRIVER_TAG);
                                    g_FoundModules = newModules;
                                    g_ModuleCount = foundCount + 1;
                                }

                                // Store the new module
                                g_FoundModules[foundCount].BaseAddress = AuxModuleInfo[i].BasicInfo.ImageBase;
                                g_FoundModules[foundCount].Size = AuxModuleInfo[i].ImageSize;
                                g_FoundModules[foundCount].Flags = 0;

                                // Convert and copy the module path
                                ANSI_STRING ansiName;
                                UNICODE_STRING unicodeName;
                                RtlInitAnsiString(&ansiName, (PCSZ)AuxModuleInfo[i].FullPathName);
                                RtlAnsiStringToUnicodeString(&unicodeName, &ansiName, TRUE);
                                wcscpy_s(g_FoundModules[foundCount].Path, MAX_PATH, unicodeName.Buffer);
                                RtlFreeUnicodeString(&unicodeName);

                                // Copy to output buffer if provided and there's space
                                if (OutputBuffer && (foundCount * sizeof(MODULE_INFO)) < OutputBufferLength) {
                                    RtlCopyMemory(&OutputBuffer[foundCount], &g_FoundModules[foundCount], sizeof(MODULE_INFO));
                                }

                                foundCount++;
                            }
                        }
                    }

                    ExFreePoolWithTag(AuxModuleInfo, DRIVER_TAG);
                }
            }
        }

        // Update module count
        g_ModuleCount = foundCount;

        // Mark modules as initialized
        g_ModulesInitialized = TRUE;

        // Report how many were found
        DbgPrint("[elemetry] GetDynamicModules: Found %lu modules\n", foundCount);

        *BytesWrittenOrRequired = foundCount * sizeof(MODULE_INFO);
        ExFreePoolWithTag(ModuleInfo, DRIVER_TAG);
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[elemetry] GetDynamicModules: Exception during module enumeration\n");
        return STATUS_UNSUCCESSFUL;
    }
}

// --- IOCTL Handler for GetModules ---
NTSTATUS HandleGetModulesIOCTL(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    NTSTATUS Status;
    ULONG BytesWrittenOrRequired = 0;
    PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG OutputBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    DbgPrint("[elemetry] HandleGetModulesIOCTL: Received request. Output buffer size: %u\n", OutputBufferLength);

    // Use the GetDynamicModules function
    Status = GetDynamicModules(
        (PMODULE_INFO)OutputBuffer,
        OutputBufferLength,
        &BytesWrittenOrRequired
    );

    if (Status == STATUS_BUFFER_TOO_SMALL) {
        DbgPrint("[elemetry] HandleGetModulesIOCTL: Buffer too small. Required: %u, Provided: %u\n",
                 BytesWrittenOrRequired, OutputBufferLength);
    } else if (!NT_SUCCESS(Status)) {
        DbgPrint("[elemetry] HandleGetModulesIOCTL: GetDynamicModules failed with 0x%X\n", Status);
    } else {
        ULONG ModuleCount = (OutputBufferLength > 0) ? (BytesWrittenOrRequired / sizeof(MODULE_INFO)) : 0;
        DbgPrint("[elemetry] HandleGetModulesIOCTL: Successfully returned %u modules\n", ModuleCount);
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = BytesWrittenOrRequired;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}



// --- IOCTL Handler for LoadImageCallbacks ---
extern "C" NTSTATUS HandleEnumerateLoadImageCallbacksIOCTL(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    DbgPrint("[elemetry] HandleLoadImageCallbacksIOCTL: Request received. Input size: %u, Output size: %u\n",
             inputBufferLength, outputBufferLength);

    // Validate minimum buffer sizes
    if (inputBufferLength < sizeof(CALLBACK_ENUM_REQUEST) ||
        outputBufferLength < sizeof(CALLBACK_ENUM_REQUEST)) {
        DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Buffer too small\n");
        status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = sizeof(CALLBACK_ENUM_REQUEST);
        goto Exit;
    }

    // Get request data from input buffer
    PCALLBACK_ENUM_REQUEST request = (PCALLBACK_ENUM_REQUEST)inputBuffer;
    PCALLBACK_ENUM_REQUEST response = (PCALLBACK_ENUM_REQUEST)outputBuffer;

    // Calculate available space for callbacks
    ULONG maxCallbacks = (outputBufferLength - FIELD_OFFSET(CALLBACK_ENUM_REQUEST, Callbacks)) /
                         sizeof(CALLBACK_INFO_SHARED);

    if (maxCallbacks == 0) {
        DbgPrint("[elemetry] HandleLoadImageCallbacksIOCTL: No space for callbacks\n");
        status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = sizeof(CALLBACK_ENUM_REQUEST) + sizeof(CALLBACK_INFO_SHARED);
        goto Exit;
    }

    // Diagnostics - print info about the address
    DbgPrint("[elemetry] HandleLoadImageCallbacksIOCTL: Table address: %p, Type: %d\n",
             request->TableAddress, request->Type);

    // Verify the callback table address is valid
    UCHAR checkBuffer[16] = {0}; // Read a small amount to validate the address
    SIZE_T bytesRead = 0;
    status = TestReadAddress(request->TableAddress, checkBuffer, sizeof(checkBuffer), &bytesRead);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] HandleLoadImageCallbacksIOCTL: Invalid table address: %p\n", request->TableAddress);
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    ULONG callbacksFound = 0;
    status = EnumerateLoadImageCallbacks(
        request->TableAddress,                 // User-provided address
        response->Callbacks,                   // Output array
        min(maxCallbacks, request->MaxCallbacks), // Limit by both user and buffer
        &callbacksFound                        // Output count
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] HandleLoadImageCallbacksIOCTL: Failed to enumerate callbacks: 0x%X\n", status);
        goto Exit;
    }

    // Set response data
    response->Type = request->Type;
    response->TableAddress = request->TableAddress;
    response->MaxCallbacks = request->MaxCallbacks;
    response->FoundCallbacks = callbacksFound;

    // Calculate bytes to return
    ULONG bytesToReturn = FIELD_OFFSET(CALLBACK_ENUM_REQUEST, Callbacks) +
                          (callbacksFound * sizeof(CALLBACK_INFO_SHARED));
    DbgPrint("[elemetry] HandleLoadImageCallbacksIOCTL: Found %u callbacks, returning %u bytes\n",
             callbacksFound, bytesToReturn);

    Irp->IoStatus.Information = bytesToReturn;

Exit:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// --- IOCTL Handler for EnumCallbacks - Implement updated function ---
extern "C" NTSTATUS HandleEnumerateCallbacksIOCTL(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Request received. Input size: %u, Output size: %u\n",
             inputBufferLength, outputBufferLength);

    // Validate minimum buffer sizes
    if (inputBufferLength < sizeof(CALLBACK_ENUM_REQUEST) ||
        outputBufferLength < sizeof(CALLBACK_ENUM_REQUEST)) {
        DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Buffer too small\n");
        status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = sizeof(CALLBACK_ENUM_REQUEST);
        goto Exit;
    }

    // Get request data from input buffer
    PCALLBACK_ENUM_REQUEST request = (PCALLBACK_ENUM_REQUEST)inputBuffer;
    PCALLBACK_ENUM_REQUEST response = (PCALLBACK_ENUM_REQUEST)outputBuffer;

    // Calculate available space for callbacks
    ULONG maxCallbacks = (outputBufferLength - FIELD_OFFSET(CALLBACK_ENUM_REQUEST, Callbacks)) /
                         sizeof(CALLBACK_INFO_SHARED);

    if (maxCallbacks == 0) {
        DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: No space for callbacks\n");
        status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = sizeof(CALLBACK_ENUM_REQUEST) + sizeof(CALLBACK_INFO_SHARED);
        goto Exit;
    }

    // Diagnostics - print info about the address
    DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Table address: %p, Type: %d\n",
             request->TableAddress, request->Type);

    // Process the request based on callback type
    ULONG callbacksFound = 0;

    // Verify the callback table address is valid - skip for filesystem callbacks
    BOOLEAN validTable = FALSE;
    if (request->Type != CallbackTableFilesystem) {
        UCHAR checkBuffer[16] = {0}; // Read a small amount to validate the address
        SIZE_T bytesRead = 0;

        // First try normal access
        DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Testing memory at %p with normal read\n",
                 request->TableAddress);

        // Check if the IRP has been cancelled
        if (Irp->Cancel) {
            DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: IRP cancelled during table validation\n");
            status = STATUS_CANCELLED;
            goto Exit;
        }

        // Test read to make sure we can access the memory
        status = ReadKernelMemory(request->TableAddress, checkBuffer, sizeof(checkBuffer), &bytesRead);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Normal read failed (0x%X), trying protected read\n", status);

            // Check if the IRP has been cancelled
            if (Irp->Cancel) {
                DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: IRP cancelled during table validation\n");
                status = STATUS_CANCELLED;
                goto Exit;
            }

            status = ReadProtectedKernelMemory(request->TableAddress, checkBuffer, sizeof(checkBuffer), &bytesRead);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Protected read also failed (0x%X)\n", status);
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }
        }

        validTable = TRUE;
        DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Successfully verified table access at %p\n",
                request->TableAddress);
    } else {
        // For filesystem callbacks, we don't need to validate the table address
        validTable = TRUE;
        DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Skipping table validation for filesystem callbacks\n");
    }

    // Check if the IRP has been cancelled
    if (Irp->Cancel) {
        DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: IRP cancelled before callback enumeration\n");
        status = STATUS_CANCELLED;
        goto Exit;
    }

    // Modify the enumeration functions to use our chosen read method
    switch (request->Type) {
    case CallbackTableLoadImage:
        status = EnumerateLoadImageCallbacks(
            request->TableAddress,                 // User-provided address
            response->Callbacks,                   // Output array
            min(maxCallbacks, request->MaxCallbacks), // Limit by both user and buffer
            &callbacksFound                        // Output count
        );
        break;
    case CallbackTableCreateProcess:
        status = EnumerateCreateProcessCallbacks(
            request->TableAddress,                 // User-provided address
            response->Callbacks,                   // Output array
            min(maxCallbacks, request->MaxCallbacks), // Limit by both user and buffer
            &callbacksFound                        // Output count
        );
        break;
    case CallbackTableCreateThread:
        status = EnumerateCreateThreadCallbacks(
            request->TableAddress,                 // User-provided address
            response->Callbacks,                   // Output array
            min(maxCallbacks, request->MaxCallbacks), // Limit by both user and buffer
            &callbacksFound                        // Output count
        );
        break;
    case CallbackTableRegistry:
        status = EnumerateRegistryCallbacks(
            request->TableAddress,                 // User-provided address
            response->Callbacks,                   // Output array
            min(maxCallbacks, request->MaxCallbacks), // Limit by both user and buffer
            &callbacksFound                        // Output count
        );
        break;
    case CallbackTableFilesystem:
        // For filesystem callbacks, we don't need a table address
        // The API lets us enumerate minifilter instances directly
        status = EnumerateFilesystemCallbacks(
            response->Callbacks,                   // Output array
            min(maxCallbacks, request->MaxCallbacks), // Limit by both user and buffer
            &callbacksFound                        // Output count
        );
        break;
    default:
        DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Unsupported callback type: %d\n", request->Type);
        status = STATUS_INVALID_PARAMETER;
        callbacksFound = 0;
        break;
    }

    // Set response data
    response->Type = request->Type;
    response->TableAddress = request->TableAddress;
    response->MaxCallbacks = request->MaxCallbacks;
    response->FoundCallbacks = callbacksFound;

    // Calculate bytes to return
    ULONG bytesToReturn = FIELD_OFFSET(CALLBACK_ENUM_REQUEST, Callbacks) +
                          (callbacksFound * sizeof(CALLBACK_INFO_SHARED));

    DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Found %u callbacks, returning %u bytes\n",
             callbacksFound, bytesToReturn);

    Irp->IoStatus.Information = bytesToReturn;

Exit:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}




