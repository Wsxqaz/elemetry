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

// Define the number of hardcoded modules we are looking for
#define INITIAL_MODULE_BUFFER_SIZE 1024  // Initial buffer size for module enumeration

// Keep const for logic, but use define for array sizes
const ULONG g_ModuleCountMax = INITIAL_MODULE_BUFFER_SIZE;
MODULE_INFO* g_FoundModules = NULL;
ULONG g_ModuleCount = 0;
BOOLEAN g_ModulesInitialized = FALSE;


// Define static buffers
#define SYSTEM_MODULE_BUFFER_SIZE 96000  // Size needed for system module info (increased from 47368)


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
