// Include Windows headers with correct defines
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000000  // Windows 10
#endif

// Disable specific warnings
#pragma warning(disable:4505) // Disable "unreferenced local function has been removed" warning

#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include "Common.h"    // Include Common.h first
#include "callbacks.h"

// Define pool flags if not available in current SDK
#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED  0x0000000000000040ULL
#endif

#ifndef POOL_FLAG_ZERO_ALLOCATION
#define POOL_FLAG_ZERO_ALLOCATION 0x0000000000000100ULL
#endif

// Define DRIVER_TAG for memory allocation
#define DRIVER_TAG 'ELMT'  // Elemetry Driver Tag

// Define SYSTEM_INFORMATION_CLASS
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

// Define SYSTEM_MODULE_INFORMATION structure
typedef struct _SYSTEM_MODULE {
    PVOID Reserved1;
    PVOID Reserved2;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

// Declare ZwQuerySystemInformation
extern "C" {
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);
}

// Global callback tracking array - using the shared struct
CALLBACK_INFO_SHARED g_CallbackInfo[MAX_CALLBACKS_SHARED];
ULONG g_CallbackCount = 0;

// Define the number of hardcoded modules we are looking for
#define HARDCODED_MODULE_COUNT 16 // Moved define earlier

// Internal storage for found module information
static MODULE_INFO g_FoundModules[HARDCODED_MODULE_COUNT]; // Now this should work
static BOOLEAN g_ModulesInitialized = FALSE;

// Keep const for logic, but use define for array sizes
const ULONG g_HardcodedModuleCount = HARDCODED_MODULE_COUNT;

// Define the list of hardcoded module names to search for
static const WCHAR* g_HardcodedModules[HARDCODED_MODULE_COUNT] = { // Use define here
    L"ntoskrnl.exe",
    L"ksecdd.sys",
    L"cng.sys",
    L"tcpip.sys",
    L"dxgkrnl.sys",
    L"peauth.sys",
    L"iorate.sys",
    L"mmcss.sys",
    L"ahcache.sys",
    L"CI.dll",
    L"luafv.sys",
    L"npsvctrig.sys",
    L"Wof.sys",
    L"fileinfo.sys",
    L"wcifs.sys",
    L"bindflt.sys"
};

// Define static buffers
#define MODULE_INFO_BUFFER_SIZE 2144  // Size needed for output modules
#define SYSTEM_MODULE_BUFFER_SIZE 96000  // Size needed for system module info (increased from 47368)
static UCHAR g_ModuleInfoBuffer[MODULE_INFO_BUFFER_SIZE];
static UCHAR g_SystemModuleBuffer[SYSTEM_MODULE_BUFFER_SIZE];

// Helper function to find a module by name
extern "C"
static BOOLEAN FindModuleByName(
    _In_ PSYSTEM_MODULE ModuleInfo,
    _In_ ULONG ModuleCount,
    _In_ PCWSTR ModuleName,
    _Out_ PMODULE_INFO OutputModule
)
{
    BOOLEAN Found = FALSE;
    WCHAR SearchNameOnly[MAX_PATH] = {0};
    WCHAR* LastBackslash = wcsrchr(ModuleName, L'\\');
    PCWSTR FileNameToMatch = LastBackslash ? LastBackslash + 1 : ModuleName;

    // Extract just the filename for matching and convert to lowercase manually
    wcscpy_s(SearchNameOnly, MAX_PATH, FileNameToMatch);
    // Manual lowercase for WCHAR
    for (int k = 0; SearchNameOnly[k]; k++) {
        SearchNameOnly[k] = towlower(SearchNameOnly[k]);
    }
    // _wcslwr(SearchNameOnly); // Removed standard library function

    for (ULONG i = 0; i < ModuleCount; i++) {
        // Convert to lowercase and extract filename for comparison
        CHAR ModuleNameOnlyA[MAX_PATH] = {0};
        CHAR* LastBackslashA = strrchr(ModuleInfo[i].ImageName, '\\\\');
        PCSTR FileNameOnlyA = LastBackslashA ? LastBackslashA + 1 : ModuleInfo[i].ImageName;

        strncpy_s(ModuleNameOnlyA, MAX_PATH, FileNameOnlyA, _TRUNCATE);
        // Manual lowercase for CHAR
        for (int k = 0; ModuleNameOnlyA[k]; k++) {
            ModuleNameOnlyA[k] = (CHAR)tolower((UCHAR)ModuleNameOnlyA[k]);
        }
        // _strlwr_s(ModuleNameOnlyA, MAX_PATH); // Removed standard library function

        // Convert to WCHAR for comparison
        WCHAR ModuleNameOnlyW[MAX_PATH] = {0};
        for (ULONG j = 0; j < strnlen_s(ModuleNameOnlyA, MAX_PATH); j++) {
            ModuleNameOnlyW[j] = (WCHAR)ModuleNameOnlyA[j];
        }

        if (wcscmp(ModuleNameOnlyW, SearchNameOnly) == 0) {
            OutputModule->BaseAddress = ModuleInfo[i].ImageBase;
            OutputModule->Size = ModuleInfo[i].ImageSize;
            OutputModule->Flags = 0;
            wcscpy_s(OutputModule->Path, MAX_PATH, ModuleName);
            Found = TRUE;
            break;
        }
    }

    if (!Found) {
        // Fallback - look for a partial match on the full path
        for (ULONG i = 0; i < ModuleCount; i++) {
            WCHAR TempPath[MAX_PATH] = {0};
            CHAR NameLower[MAX_PATH] = {0};
            strncpy_s(NameLower, MAX_PATH, ModuleInfo[i].ImageName, _TRUNCATE);
            // Manual lowercase for CHAR
            for (int k = 0; NameLower[k]; k++) {
                NameLower[k] = (CHAR)tolower((UCHAR)NameLower[k]);
            }
            // _strlwr_s(NameLower, MAX_PATH); // Removed standard library function

            // Manual conversion from CHAR to WCHAR without using MultiByteToWideChar
            for (ULONG j = 0; j < strnlen_s(NameLower, MAX_PATH); j++) {
                TempPath[j] = (WCHAR)NameLower[j];
            }

            if (wcsstr(TempPath, SearchNameOnly) != NULL) {
                OutputModule->BaseAddress = ModuleInfo[i].ImageBase;
                OutputModule->Size = ModuleInfo[i].ImageSize;
                OutputModule->Flags = 0;
                wcscpy_s(OutputModule->Path, MAX_PATH, ModuleName);
                Found = TRUE;
                break;
            }
        }
    }

    return Found;
}

// Helper function to get base address of a module by name from internal storage
static PVOID GetInternalModuleBase(_In_ PCWSTR ModuleName)
{
    if (!g_ModulesInitialized) {
        DbgPrint("[elemetry] GetInternalModuleBase: Module info not initialized yet!\n");
        return NULL;
    }

    for (ULONG i = 0; i < HARDCODED_MODULE_COUNT; ++i) {
        // Compare the stored path with the requested name (case-insensitive filename only)
        WCHAR StoredNameOnly[MAX_PATH] = {0};
        WCHAR* LastBackslash = wcsrchr(g_FoundModules[i].Path, L'\\');
        PCWSTR FileNameOnly = LastBackslash ? LastBackslash + 1 : g_FoundModules[i].Path;
        wcscpy_s(StoredNameOnly, MAX_PATH, FileNameOnly);
        for (int k = 0; StoredNameOnly[k]; k++) { StoredNameOnly[k] = towlower(StoredNameOnly[k]); } // Manual lowercase

        WCHAR RequestedNameOnly[MAX_PATH] = {0};
        LastBackslash = wcsrchr(ModuleName, L'\\');
        FileNameOnly = LastBackslash ? LastBackslash + 1 : ModuleName;
        wcscpy_s(RequestedNameOnly, MAX_PATH, FileNameOnly);
        for (int k = 0; RequestedNameOnly[k]; k++) { RequestedNameOnly[k] = towlower(RequestedNameOnly[k]); } // Manual lowercase

        if (wcscmp(StoredNameOnly, RequestedNameOnly) == 0) {
            return g_FoundModules[i].BaseAddress;
        }
    }

    DbgPrint("[elemetry] GetInternalModuleBase: Module %S not found in internal list.\n", ModuleName);
    return NULL;
}

// --- Helper to get hardcoded modules ---
NTSTATUS GetHardcodedModules(
    _Out_writes_bytes_opt_(OutputBufferLength) PMODULE_INFO OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWrittenOrRequired
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredSize = HARDCODED_MODULE_COUNT * sizeof(MODULE_INFO);
    ULONG foundCount = 0;

    // Check if we're at PASSIVE_LEVEL
    KIRQL CurrentIrql = KeGetCurrentIrql();
    if (CurrentIrql > PASSIVE_LEVEL) {
        DbgPrint("[elemetry] GetHardcodedModules: Running at IRQL %d, need PASSIVE_LEVEL\n", CurrentIrql);
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (OutputBufferLength < requiredSize) {
        DbgPrint("[elemetry] GetHardcodedModules: Buffer too small. Required: %u, Provided: %u\n",
                 requiredSize, OutputBufferLength);
        *BytesWrittenOrRequired = requiredSize;
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!OutputBuffer) {
        DbgPrint("[elemetry] GetHardcodedModules: Invalid output buffer pointer.\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Report how many target modules we are looking for
    DbgPrint("[elemetry] GetHardcodedModules: Looking for %lu target modules\n", HARDCODED_MODULE_COUNT);

    __try {
        // Use our static buffer for system module information
        RtlZeroMemory(g_SystemModuleBuffer, SYSTEM_MODULE_BUFFER_SIZE);
        ULONG SystemInfoLength = SYSTEM_MODULE_BUFFER_SIZE;

        // Ensure we're still at PASSIVE_LEVEL before calling ZwQuerySystemInformation
        CurrentIrql = KeGetCurrentIrql();
        if (CurrentIrql > PASSIVE_LEVEL) {
            DbgPrint("[elemetry] GetHardcodedModules: IRQL changed to %d, aborting\n", CurrentIrql);
            return STATUS_INVALID_DEVICE_STATE;
        }

        status = ZwQuerySystemInformation(SystemModuleInformation, g_SystemModuleBuffer, SystemInfoLength, &SystemInfoLength);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[elemetry] GetHardcodedModules: Failed to get module information: 0x%X\n", status);
            return status;
        }

        // Process modules from static buffer
        PSYSTEM_MODULE_INFORMATION ModuleInfo = (PSYSTEM_MODULE_INFORMATION)g_SystemModuleBuffer;

        // Zero out the internal storage before populating
        RtlZeroMemory(g_FoundModules, sizeof(g_FoundModules));

        // Iterate through the target module names
        for (ULONG targetIndex = 0; targetIndex < HARDCODED_MODULE_COUNT; ++targetIndex) {
            MODULE_INFO tempModuleInfo = {0}; // Temporary storage for FindModuleByName
            // Compare the current module's name (lowercase) with the target name (lowercase)
            if (FindModuleByName(ModuleInfo->Modules, ModuleInfo->Count, g_HardcodedModules[targetIndex], &tempModuleInfo)) {
                DbgPrint("[elemetry] GetHardcodedModules: Found module %S at %p\n",
                         g_HardcodedModules[targetIndex], tempModuleInfo.BaseAddress);
                // Copy found info to internal storage AND output buffer if provided
                RtlCopyMemory(&g_FoundModules[targetIndex], &tempModuleInfo, sizeof(MODULE_INFO));
                if (OutputBuffer && (foundCount * sizeof(MODULE_INFO)) < OutputBufferLength) {
                    RtlCopyMemory(&OutputBuffer[foundCount], &tempModuleInfo, sizeof(MODULE_INFO));
                }
                foundCount++;
            } else {
                DbgPrint("[elemetry] GetHardcodedModules: Module %S not found\n", g_HardcodedModules[targetIndex]);
                // Still store placeholder info in internal storage
                g_FoundModules[targetIndex].BaseAddress = NULL;
                g_FoundModules[targetIndex].Size = 0;
                g_FoundModules[targetIndex].Flags = 0;
                wcscpy_s(g_FoundModules[targetIndex].Path, MAX_PATH, g_HardcodedModules[targetIndex]);

                // Also copy placeholder to output buffer if provided
                 if (OutputBuffer && (foundCount * sizeof(MODULE_INFO)) < OutputBufferLength) {
                     RtlCopyMemory(&OutputBuffer[foundCount], &g_FoundModules[targetIndex], sizeof(MODULE_INFO));
                 }
                 // Increment foundCount even if not found, as we return placeholders
                 foundCount++;
            }
        }

        // Mark modules as initialized
        g_ModulesInitialized = TRUE;

        // Report how many were found (note: this now reports total attempted, not just successfully found)
        DbgPrint("[elemetry] GetHardcodedModules: Processed %lu of %lu target modules\n", foundCount, HARDCODED_MODULE_COUNT);

        *BytesWrittenOrRequired = foundCount * sizeof(MODULE_INFO); // Return size based on entries processed
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[elemetry] GetHardcodedModules: Exception during module enumeration\n");
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

    // Use the GetHardcodedModules function
    Status = GetHardcodedModules(
        (PMODULE_INFO)OutputBuffer,
        OutputBufferLength,
        &BytesWrittenOrRequired
    );

    if (Status == STATUS_BUFFER_TOO_SMALL) {
        DbgPrint("[elemetry] HandleGetModulesIOCTL: Buffer too small. Required: %u, Provided: %u\n",
                 BytesWrittenOrRequired, OutputBufferLength);
    } else if (!NT_SUCCESS(Status)) {
        DbgPrint("[elemetry] HandleGetModulesIOCTL: GetHardcodedModules failed with 0x%X\n", Status);
    } else {
        ULONG ModuleCount = (OutputBufferLength > 0) ? (BytesWrittenOrRequired / sizeof(MODULE_INFO)) : 0;
        DbgPrint("[elemetry] HandleGetModulesIOCTL: Successfully returned %u modules\n", ModuleCount);
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = BytesWrittenOrRequired;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

// Initialize callback tracking
NTSTATUS InitializeCallbackTracking()
{
    DbgPrint("[elemetry] Initializing callback tracking...\n");

    // Ensure module information is populated first
    if (!g_ModulesInitialized) {
        DbgPrint("[elemetry] InitializeCallbackTracking: Modules not initialized, attempting now...\n");
        ULONG bytesWritten = 0;
        NTSTATUS moduleStatus = GetHardcodedModules(NULL, 0, &bytesWritten); // Call just to populate internal storage
        if (!NT_SUCCESS(moduleStatus) && moduleStatus != STATUS_BUFFER_TOO_SMALL) { // Ignore buffer too small as we didn't provide one
            DbgPrint("[elemetry] InitializeCallbackTracking: Failed to initialize modules: 0x%X\n", moduleStatus);
            // Continue with potentially NULL addresses, or return error?
            // For now, continue.
        } else if (!g_ModulesInitialized) {
             DbgPrint("[elemetry] InitializeCallbackTracking: GetHardcodedModules succeeded but flag not set?!");
             // Proceed cautiously
        } else {
             DbgPrint("[elemetry] InitializeCallbackTracking: Modules initialized successfully.");
        }
    }

    // Zero out the callback array
    RtlZeroMemory(g_CallbackInfo, sizeof(g_CallbackInfo));
    g_CallbackCount = 0;

    // Add some sample callbacks using retrieved module bases + offsets
    /* REMOVED SAMPLE CALLBACK REGISTRATION
    PVOID ntoskrnlBase = GetInternalModuleBase(L"ntoskrnl.exe");
    PVOID tcpipBase = GetInternalModuleBase(L"tcpip.sys");
    PVOID ciBase = GetInternalModuleBase(L"CI.dll"); // Use CI.dll for the third one

    CALLBACK_INFO_SHARED sampleCallback1 = {0};
    sampleCallback1.Type = static_cast<CALLBACK_TYPE>(CALLBACK_TYPE::PsLoadImage);
    sampleCallback1.Address = ntoskrnlBase ? (PVOID)((ULONG_PTR)ntoskrnlBase + 0x1000) : (PVOID)0xFFFFFFFFFFFFFFFF; // Offset or placeholder
    sampleCallback1.Context = 0x12345678;
    RtlCopyMemory(sampleCallback1.CallbackName, "SampleImageLoadCallback", sizeof("SampleImageLoadCallback"));
    RtlCopyMemory(sampleCallback1.ModuleName, "ntoskrnl.exe", sizeof("ntoskrnl.exe"));
    RegisterCallback(&sampleCallback1);

    CALLBACK_INFO_SHARED sampleCallback2 = {0};
    sampleCallback2.Type = static_cast<CALLBACK_TYPE>(CALLBACK_TYPE::PsProcessCreation);
    sampleCallback2.Address = tcpipBase ? (PVOID)((ULONG_PTR)tcpipBase + 0x2000) : (PVOID)0xFFFFFFFFFFFFFFFE; // Offset or placeholder
    sampleCallback2.Context = 0x87654321;
    RtlCopyMemory(sampleCallback2.CallbackName, "SampleProcessCallback", sizeof("SampleProcessCallback"));
    RtlCopyMemory(sampleCallback2.ModuleName, "tcpip.sys", sizeof("tcpip.sys"));
    RegisterCallback(&sampleCallback2);

    CALLBACK_INFO_SHARED sampleCallback3 = {0};
    sampleCallback3.Type = static_cast<CALLBACK_TYPE>(CALLBACK_TYPE::CmRegistry);
    sampleCallback3.Address = ciBase ? (PVOID)((ULONG_PTR)ciBase + 0x3000) : (PVOID)0xFFFFFFFFFFFFFFFD; // Offset or placeholder
    sampleCallback3.Context = 0x11223344;
    RtlCopyMemory(sampleCallback3.CallbackName, "SampleRegistryCallback", sizeof("SampleRegistryCallback"));
    RtlCopyMemory(sampleCallback3.ModuleName, "CI.dll", sizeof("CI.dll"));
    RegisterCallback(&sampleCallback3);
    */

    DbgPrint("[elemetry] Initialization complete. Found %lu modules. Callback registration skipped (using exports now).\n", g_HardcodedModuleCount);
    return STATUS_SUCCESS;
}

// Clean up callback tracking
VOID CleanupCallbackTracking()
{
    DbgPrint("[elemetry] Cleaning up %d callbacks...\n", g_CallbackCount);
    
    // Reset callback count and clear the array
    g_CallbackCount = 0;
    RtlZeroMemory(g_CallbackInfo, sizeof(g_CallbackInfo));
    
    // Clear module information
    DbgPrint("[elemetry] Clearing module information...\n");
    RtlZeroMemory(g_FoundModules, sizeof(g_FoundModules));
    g_ModulesInitialized = FALSE;
    
    // Clear static buffers
    RtlZeroMemory(g_ModuleInfoBuffer, MODULE_INFO_BUFFER_SIZE);
    RtlZeroMemory(g_SystemModuleBuffer, SYSTEM_MODULE_BUFFER_SIZE);
    
    DbgPrint("[elemetry] Callback tracking cleanup complete\n");
}

// Register a new callback
NTSTATUS RegisterCallback(PCALLBACK_INFO_SHARED CallbackInfo) {
    if (g_CallbackCount >= MAX_CALLBACKS_SHARED) {
        DbgPrint("[elemetry] Cannot register callback - maximum limit reached\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!CallbackInfo || !CallbackInfo->CallbackName[0] || !CallbackInfo->Address) {
        DbgPrint("[elemetry] Invalid callback parameters\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Store callback information
    RtlCopyMemory(&g_CallbackInfo[g_CallbackCount], CallbackInfo, sizeof(CALLBACK_INFO_SHARED));
    g_CallbackCount++;

    DbgPrint("[elemetry] Registered callback: %s in %s at %p\n",
             CallbackInfo->CallbackName,
             CallbackInfo->ModuleName,
             CallbackInfo->Address);

    return STATUS_SUCCESS;
}

// Enumerate all registered callbacks
NTSTATUS EnumerateCallbacks(
    _In_ PENUM_CALLBACKS_CALLBACK EnumCallback,
    _In_opt_ PVOID Context
)
{
    DbgPrint("[elemetry] EnumerateCallbacks: Starting enumeration... Count: %u\n", g_CallbackCount);
    if (!EnumCallback) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_SUCCESS;
    for (ULONG i = 0; i < g_CallbackCount; i++) {
        DbgPrint("[elemetry] EnumerateCallbacks: Processing index %u, Address %p\n", i, g_CallbackInfo[i].Address);
        __try {
            NTSTATUS CallbackStatus = EnumCallback(&g_CallbackInfo[i], Context);
            if (!NT_SUCCESS(CallbackStatus)) {
                DbgPrint("[elemetry] EnumerateCallbacks: Callback returned error 0x%X for index %u\n", CallbackStatus, i);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[elemetry] EnumerateCallbacks: Exception while processing callback index %u\n", i);
        }
    }
    DbgPrint("[elemetry] EnumerateCallbacks: Enumeration complete.\n");
    return Status;
}

// Get callback count
ULONG GetCallbackCount() {
    return g_CallbackCount;
}

// Get callback by index
NTSTATUS GetCallbackByIndex(
    _In_ ULONG Index,
    _Out_ PCALLBACK_INFO_SHARED SharedCallbackInfo
)
{
    if (Index >= g_CallbackCount || !SharedCallbackInfo) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlCopyMemory(SharedCallbackInfo, &g_CallbackInfo[Index], sizeof(CALLBACK_INFO_SHARED));
    return STATUS_SUCCESS;
}

// Get callback by name
NTSTATUS GetCallbackByName(
    _In_ PCSTR CallbackName,
    _Out_ PCALLBACK_INFO_SHARED SharedCallbackInfo
) {
    if (!CallbackName || !SharedCallbackInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    for (ULONG i = 0; i < g_CallbackCount; i++) {
        if (strncmp(g_CallbackInfo[i].CallbackName, CallbackName, MAX_PATH - 1) == 0) {
            RtlCopyMemory(SharedCallbackInfo, &g_CallbackInfo[i], sizeof(CALLBACK_INFO_SHARED));
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

// Get callback by address
NTSTATUS GetCallbackByAddress(
    _In_ PVOID CallbackAddress,
    _Out_ PCALLBACK_INFO_SHARED SharedCallbackInfo
) {
    if (!CallbackAddress || !SharedCallbackInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    for (ULONG i = 0; i < g_CallbackCount; i++) {
        if (g_CallbackInfo[i].Address == CallbackAddress) {
            RtlCopyMemory(SharedCallbackInfo, &g_CallbackInfo[i], sizeof(CALLBACK_INFO_SHARED));
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

// --- IOCTL Handler for EnumerateCallbacks (Now Enumerates Exports) ---
NTSTATUS HandleEnumerateCallbacksIOCTL(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG outputBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG requiredSize = 0;
    ULONG totalExportsFound = 0;
    ULONG currentBufferOffset = 0;
    PCALLBACK_INFO_SHARED callbackOutputBuffer = (PCALLBACK_INFO_SHARED)outputBuffer;

    DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL (Export Mode): Request received. Buffer size: %u\n",
             outputBufferLength);

    if (!g_ModulesInitialized) {
         DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Module info not initialized yet!\n");
         status = STATUS_DRIVER_INTERNAL_ERROR;
         Irp->IoStatus.Information = 0;
         goto Exit;
    }

    // --- First Pass: Calculate Required Size ---
    DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Calculating required size...\n");
    for (ULONG i = 0; i < HARDCODED_MODULE_COUNT; ++i) {
        if (g_FoundModules[i].BaseAddress != NULL) {
            // Estimate max exports per module (can be large, be conservative or parse twice)
            // Let's allocate a temporary buffer for parsing this module
            // Max reasonable exports? Let's say 4096 for now.
            const ULONG MAX_EXPORTS_PER_MODULE = 4096;
            PEXPORT_INFO tempExportList = NULL;

            // Allocate temporary space for this module's exports
            tempExportList = (PEXPORT_INFO)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                         MAX_EXPORTS_PER_MODULE * sizeof(EXPORT_INFO),
                                                         'xEpE'); // Pool tag

            if (!tempExportList) {
                DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Failed to allocate temp buffer for module %S\n", g_FoundModules[i].Path);
                // Skip this module, or fail the whole request? Let's skip.
                continue;
            }

            PE_PARSE_CONTEXT parseContext = {0};
            parseContext.ModuleBase = g_FoundModules[i].BaseAddress;
            parseContext.ExportList = tempExportList;
            parseContext.MaxExports = MAX_EXPORTS_PER_MODULE;
            parseContext.FoundExports = 0;

            NTSTATUS parseStatus = ParseModuleExports(&parseContext);

            if (NT_SUCCESS(parseStatus) || parseStatus == STATUS_BUFFER_OVERFLOW) { // Treat overflow as success for size calculation
                DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Module %S has %lu exports (status 0x%X)\n",
                         g_FoundModules[i].Path, parseContext.FoundExports, parseStatus);
                requiredSize += parseContext.FoundExports * sizeof(CALLBACK_INFO_SHARED);
                totalExportsFound += parseContext.FoundExports;
            } else {
                DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Failed to parse exports for %S (status 0x%X)\n",
                         g_FoundModules[i].Path, parseStatus);
            }

            // Free the temporary buffer
            ExFreePoolWithTag(tempExportList, 'xEpE');

        } else {
             // Module base was NULL (not found)
        }
    }
    DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Total required size: %u bytes for %lu exports.\n",
             requiredSize, totalExportsFound);

    Irp->IoStatus.Information = requiredSize; // Always report required size

    // --- Second Pass: Copy Data if Buffer is Sufficient ---
    if (outputBufferLength < requiredSize) {
        DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Buffer too small.\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    } else if (!outputBuffer) {
        DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Invalid output buffer pointer.\n");
        status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        goto Exit;
    }

    DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Populating output buffer...\n");
    RtlZeroMemory(outputBuffer, outputBufferLength); // Zero the user buffer

    for (ULONG i = 0; i < HARDCODED_MODULE_COUNT; ++i) {
        if (g_FoundModules[i].BaseAddress != NULL) {
             // Reparse to get data again (could optimize by storing from first pass if memory allows)
            const ULONG MAX_EXPORTS_PER_MODULE = 4096;
            PEXPORT_INFO tempExportList = NULL;
            tempExportList = (PEXPORT_INFO)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                         MAX_EXPORTS_PER_MODULE * sizeof(EXPORT_INFO),
                                                         'xEpE');
            if (!tempExportList) {
                DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL (Pass 2): Failed alloc for %S\n", g_FoundModules[i].Path);
                continue;
            }

            PE_PARSE_CONTEXT parseContext = {0};
            parseContext.ModuleBase = g_FoundModules[i].BaseAddress;
            parseContext.ExportList = tempExportList;
            parseContext.MaxExports = MAX_EXPORTS_PER_MODULE;
            parseContext.FoundExports = 0;

            NTSTATUS parseStatus = ParseModuleExports(&parseContext);

            if (NT_SUCCESS(parseStatus) || parseStatus == STATUS_BUFFER_OVERFLOW) {
                 // Copy exports to the output buffer as CALLBACK_INFO_SHARED
                 __try {
                     for (ULONG j = 0; j < parseContext.FoundExports; ++j) {
                         if ((currentBufferOffset + sizeof(CALLBACK_INFO_SHARED)) <= outputBufferLength) {
                             PCALLBACK_INFO_SHARED currentCallback = callbackOutputBuffer + (currentBufferOffset / sizeof(CALLBACK_INFO_SHARED));

                             currentCallback->Type = CALLBACK_TYPE::Unknown; // Indicate it's an export
                             currentCallback->Address = parseContext.ExportList[j].Address;
                             currentCallback->Context = 0; // Context not relevant for exports
                             strncpy_s(currentCallback->CallbackName, MAX_CALLBACK_NAME, parseContext.ExportList[j].Name, _TRUNCATE);

                             // Copy module name (filename only)
                             WCHAR ModuleNameOnly[MAX_PATH] = {0};
                             WCHAR* LastBackslash = wcsrchr(g_FoundModules[i].Path, L'\\');
                             PCWSTR FileNameOnly = LastBackslash ? LastBackslash + 1 : g_FoundModules[i].Path;
                             wcscpy_s(ModuleNameOnly, MAX_PATH, FileNameOnly);
                             // Convert WCHAR to CHAR for the shared struct (potential data loss if non-ASCII)
                             for(int k=0; ModuleNameOnly[k] && k < MAX_MODULE_NAME -1; ++k) {
                                 currentCallback->ModuleName[k] = (CHAR)ModuleNameOnly[k];
                             }
                             currentCallback->ModuleName[MAX_MODULE_NAME - 1] = '\0';

                             currentBufferOffset += sizeof(CALLBACK_INFO_SHARED);
                         } else {
                             DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Ran out of buffer space during copy! Should not happen based on size check.\n");
                             status = STATUS_BUFFER_OVERFLOW; // Should have been caught earlier
                             ExFreePoolWithTag(tempExportList, 'xEpE');
                             goto Exit; // Exit loop and function
                         }
                     }
                 } __except (EXCEPTION_EXECUTE_HANDLER) {
                     DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Exception during output buffer copy!\n");
                     status = GetExceptionCode();
                     Irp->IoStatus.Information = 0; // Reset info on error
                     ExFreePoolWithTag(tempExportList, 'xEpE');
                     goto Exit;
                 }
            }

            ExFreePoolWithTag(tempExportList, 'xEpE');
        }
    }

    // Ensure final information reflects actual bytes written
    if (NT_SUCCESS(status)) {
       Irp->IoStatus.Information = currentBufferOffset;
       DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Successfully copied %lu bytes (%lu exports).\n",
                currentBufferOffset, totalExportsFound);
    } else {
       Irp->IoStatus.Information = (status == STATUS_BUFFER_TOO_SMALL) ? requiredSize : 0;
    }

Exit:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Implementation of GetSystemModules using hardcoded modules
NTSTATUS GetSystemModules(
    _Out_writes_bytes_opt_(OutputBufferLength) PMODULE_INFO OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWrittenOrRequired
)
{
    *BytesWrittenOrRequired = 0;

    DbgPrint("[elemetry] GetSystemModules: Using hardcoded modules\n");

    __try {
        // Calculate required size
        ULONG RequiredSize = HARDCODED_MODULE_COUNT * sizeof(MODULE_INFO);
        *BytesWrittenOrRequired = RequiredSize;

        // If no output buffer or buffer too small, just return the size
        if (!OutputBuffer || OutputBufferLength < RequiredSize) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        // Copy hardcoded modules to output buffer
        RtlCopyMemory(OutputBuffer, g_HardcodedModules, RequiredSize);

        // Log the modules
        for (ULONG i = 0; i < HARDCODED_MODULE_COUNT; i++) {
            DbgPrint("[elemetry] Module %u: %ls (Base: %p, Size: 0x%X)\n",
                    i, OutputBuffer[i].Path, OutputBuffer[i].BaseAddress, OutputBuffer[i].Size);
        }

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[elemetry] GetSystemModules: Exception occurred\n");
        return STATUS_UNSUCCESSFUL;
    }
}

// --- PE Parsing Helper ---
NTSTATUS ParseModuleExports(_Inout_ PPE_PARSE_CONTEXT ParseContext)
{
    if (!ParseContext || !ParseContext->ModuleBase || !ParseContext->ExportList || ParseContext->MaxExports == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PUCHAR baseAddress = (PUCHAR)ParseContext->ModuleBase;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS64 ntHeaders = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDir = NULL;
    PULONG nameRvas = NULL;
    PULONG functionRvas = NULL;
    PUSHORT ordinalTable = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    ParseContext->FoundExports = 0;

    __try {
        // Basic validation of DOS header
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            DbgPrint("[elemetry] ParseModuleExports: Invalid DOS signature\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // Get NT Headers
        ntHeaders = (PIMAGE_NT_HEADERS64)(baseAddress + dosHeader->e_lfanew);
        // Basic validation of NT Headers
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            DbgPrint("[elemetry] ParseModuleExports: Invalid NT signature\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
             DbgPrint("[elemetry] ParseModuleExports: Not a 64-bit image\n");
             return STATUS_INVALID_IMAGE_FORMAT; // Only support 64-bit for now
        }

        // Check if export directory exists
        ULONG exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exportDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (exportDirRva == 0 || exportDirSize == 0) {
            DbgPrint("[elemetry] ParseModuleExports: Module has no export directory.\n");
            return STATUS_NOT_FOUND; // No exports is not an error, just nothing to find
        }

        exportDir = (PIMAGE_EXPORT_DIRECTORY)(baseAddress + exportDirRva);
        nameRvas = (PULONG)(baseAddress + exportDir->AddressOfNames);
        functionRvas = (PULONG)(baseAddress + exportDir->AddressOfFunctions);
        ordinalTable = (PUSHORT)(baseAddress + exportDir->AddressOfNameOrdinals);

        // Iterate through the names
        for (ULONG i = 0; i < exportDir->NumberOfNames; ++i) {
            if (ParseContext->FoundExports >= ParseContext->MaxExports) {
                DbgPrint("[elemetry] ParseModuleExports: Reached max export count (%lu)\n", ParseContext->MaxExports);
                status = STATUS_BUFFER_OVERFLOW; // Indicate we truncated
                break;
            }

            // Get export name RVA
            ULONG nameRva = nameRvas[i];
            if (nameRva == 0) continue; // Should not happen but check
            PCHAR exportName = (PCHAR)(baseAddress + nameRva);

            // Get function RVA using the ordinal
            USHORT ordinal = ordinalTable[i];
            if (ordinal >= exportDir->NumberOfFunctions) { // Check ordinal bounds
                 DbgPrint("[elemetry] ParseModuleExports: Invalid ordinal %u for name %hs\n", ordinal, exportName);
                 continue;
            }
            ULONG functionRva = functionRvas[ordinal];
            if (functionRva == 0) continue; // Should not happen but check

            // Calculate absolute address
            PVOID exportAddress = (PVOID)(baseAddress + functionRva);

            // Check for forwarded exports (where RVA points within the export directory itself)
            // These point to a string like "OTHERDLL.OtherFunction"
            if (functionRva >= exportDirRva && functionRva < (exportDirRva + exportDirSize)) {
                DbgPrint("[elemetry] ParseModuleExports: Skipping forwarded export: %hs -> %hs\n", exportName, (PCHAR)exportAddress);
                continue;
            }

            // Store the export info
            strncpy_s(ParseContext->ExportList[ParseContext->FoundExports].Name, MAX_EXPORT_NAME, exportName, _TRUNCATE);
            ParseContext->ExportList[ParseContext->FoundExports].Address = exportAddress;
            ParseContext->FoundExports++;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[elemetry] ParseModuleExports: Exception 0x%X while parsing exports.\n", status);
        ParseContext->FoundExports = 0; // Indicate failure
        return status;
    }

    DbgPrint("[elemetry] ParseModuleExports: Found %lu exports.\n", ParseContext->FoundExports);
    return status; // Return STATUS_SUCCESS or STATUS_BUFFER_OVERFLOW if truncated
}

// More robust kernel memory read function for protected areas
NTSTATUS ReadProtectedKernelMemory(
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

// Enumerate load image notification callbacks
NTSTATUS EnumerateLoadImageCallbacks(
    _In_opt_ PVOID CallbackTable,
    _Out_writes_to_(MaxCallbacks, *FoundCallbacks) PCALLBACK_INFO_SHARED CallbackArray,
    _In_ ULONG MaxCallbacks,
    _Out_ PULONG FoundCallbacks
)
{
    NTSTATUS status = STATUS_SUCCESS;
    *FoundCallbacks = 0;

    // Hard-coded array size based on known Windows internals (typically 8 or 16)
    const ULONG MAX_LOAD_IMAGE_CALLBACKS = 64;

    // If user didn't provide a table address, we can't proceed
    if (!CallbackTable) {
        DbgPrint("[elemetry] EnumerateLoadImageCallbacks: No callback table address provided\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate buffer for callback pointers
    PVOID* callbackPointers = (PVOID*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                     sizeof(PVOID) * MAX_LOAD_IMAGE_CALLBACKS,
                                                     'CBpT');
    if (!callbackPointers) {
        DbgPrint("[elemetry] EnumerateLoadImageCallbacks: Failed to allocate memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(callbackPointers, sizeof(PVOID) * MAX_LOAD_IMAGE_CALLBACKS);

    // Read callback pointers from the table
    SIZE_T bytesRead = 0;

    // First try with standard read
    status = ReadProtectedKernelMemory(
        CallbackTable,
        callbackPointers,
        sizeof(PVOID) * MAX_LOAD_IMAGE_CALLBACKS,
        &bytesRead
    );

    // If standard read fails, try protected read
    if (!NT_SUCCESS(status) || bytesRead < sizeof(PVOID)) {
        DbgPrint("[elemetry] EnumerateLoadImageCallbacks: Normal read failed, trying protected read\n");

        status = ReadProtectedKernelMemory(
            CallbackTable,
            callbackPointers,
            sizeof(PVOID) * MAX_LOAD_IMAGE_CALLBACKS,
            &bytesRead
        );
    }

    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] EnumerateLoadImageCallbacks: Failed to read callback table: 0x%X\n", status);
        ExFreePoolWithTag(callbackPointers, 'CBpT');
        return status;
    }

    // Process each callback pointer
    ULONG count = 0;
    for (ULONG i = 0; i < MAX_LOAD_IMAGE_CALLBACKS && count < MaxCallbacks; i++) {
        if (callbackPointers[i] == NULL || callbackPointers[i] == (PVOID)~0) {
            continue;
        }

        // This is a valid callback, create an entry
        RtlZeroMemory(&CallbackArray[count], sizeof(CALLBACK_INFO_SHARED));

        CallbackArray[count].Type = CALLBACK_TYPE::PsLoadImage;
        CallbackArray[count].Address = callbackPointers[i];

        // Get base address to determine which module this callback belongs to
        ULONG_PTR callbackAddress = (ULONG_PTR)callbackPointers[i];
        BOOLEAN found = FALSE;

        // Try to find which module this callback belongs to
        for (ULONG m = 0; m < HARDCODED_MODULE_COUNT; m++) {
            if (g_FoundModules[m].BaseAddress != NULL) {
                ULONG_PTR moduleBase = (ULONG_PTR)g_FoundModules[m].BaseAddress;
                ULONG_PTR moduleEnd = moduleBase + g_FoundModules[m].Size;

                if (callbackAddress >= moduleBase && callbackAddress < moduleEnd) {
                    // Extract just the filename from the path
                    WCHAR* LastBackslash = wcsrchr(g_FoundModules[m].Path, L'\\');
                    PCWSTR FileNameOnly = LastBackslash ? LastBackslash + 1 : g_FoundModules[m].Path;

                    // Convert wide char to char (ASCII only)
                    for (ULONG c = 0; FileNameOnly[c] && c < MAX_MODULE_NAME - 1; c++) {
                        CallbackArray[count].ModuleName[c] = (CHAR)FileNameOnly[c];
                    }

                    // Set callback name based on offset from module base
                    sprintf_s(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME,
                             "LoadImageCallback+0x%llX", (ULONG_PTR)callbackAddress - moduleBase);

                    found = TRUE;
                    break;
                }
            }
        }

        // If module not found, use generic name
        if (!found) {
            RtlCopyMemory(CallbackArray[count].ModuleName, "Unknown", sizeof("Unknown"));
            sprintf_s(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME,
                     "LoadImageCallback@0x%p", callbackPointers[i]);
        }

        count++;
    }

    *FoundCallbacks = count;
    DbgPrint("[elemetry] EnumerateLoadImageCallbacks: Found %u callbacks\n", count);

    ExFreePoolWithTag(callbackPointers, 'CBpT');
    return status;
}

// Custom implementation that safely handles the missing IoGetCurrentIrp function
PIRP GetCurrentIrpSafe()
{
    // This is a safer implementation that doesn't rely on the missing IoGetCurrentIrp
    // We'll return NULL which means the code will still check for IRP cancellation
    // but won't crash if the function doesn't exist
    return NULL;
}

// --- IOCTL Handler for EnumCallbacks - Implement updated function ---
NTSTATUS HandleEnumCallbacksIOCTL(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: Request received. Input size: %u, Output size: %u\n",
             inputBufferLength, outputBufferLength);

    // Validate minimum buffer sizes
    if (inputBufferLength < sizeof(CALLBACK_ENUM_REQUEST) ||
        outputBufferLength < sizeof(CALLBACK_ENUM_REQUEST)) {
        DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: Buffer too small\n");
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
        DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: No space for callbacks\n");
        status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = sizeof(CALLBACK_ENUM_REQUEST) + sizeof(CALLBACK_INFO_SHARED);
        goto Exit;
    }

    // Diagnostics - print info about the address
    DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: Table address: %p, Type: %d\n",
             request->TableAddress, request->Type);

    // Process the request based on callback type
    ULONG callbacksFound = 0;

    // Verify the callback table address is valid
    BOOLEAN validTable = FALSE;
    UCHAR checkBuffer[16] = {0}; // Read a small amount to validate the address
    SIZE_T bytesRead = 0;

    // First try normal access
    DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: Testing memory at %p with normal read\n",
             request->TableAddress);

    // Check if the IRP has been cancelled
    if (Irp->Cancel) {
        DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: IRP cancelled during table validation\n");
        status = STATUS_CANCELLED;
        goto Exit;
    }

    // Test read to make sure we can access the memory
    status = ReadKernelMemory(request->TableAddress, checkBuffer, sizeof(checkBuffer), &bytesRead);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: Normal read failed (0x%X), trying protected read\n", status);
        
        // Check if the IRP has been cancelled
        if (Irp->Cancel) {
            DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: IRP cancelled during table validation\n");
            status = STATUS_CANCELLED;
            goto Exit;
        }

        status = ReadProtectedKernelMemory(request->TableAddress, checkBuffer, sizeof(checkBuffer), &bytesRead);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: Protected read also failed (0x%X)\n", status);
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }
    }

    validTable = TRUE;
    DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: Successfully verified table access at %p\n",
            request->TableAddress);
    
    // Check if the IRP has been cancelled
    if (Irp->Cancel) {
        DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: IRP cancelled before callback enumeration\n");
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
    default:
        DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: Unsupported callback type: %d\n", request->Type);
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

    DbgPrint("[elemetry] HandleEnumCallbacksIOCTL: Found %u callbacks, returning %u bytes\n",
             callbacksFound, bytesToReturn);

    Irp->IoStatus.Information = bytesToReturn;

Exit:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Implement EnumerateCreateProcessCallbacks function
NTSTATUS EnumerateCreateProcessCallbacks(
    _In_opt_ PVOID CallbackTable,
    _Out_writes_to_(MaxCallbacks, *FoundCallbacks) PCALLBACK_INFO_SHARED CallbackArray,
    _In_ ULONG MaxCallbacks,
    _Out_ PULONG FoundCallbacks
)
{
    NTSTATUS status = STATUS_SUCCESS;
    *FoundCallbacks = 0;

    // Hard-coded array size based on known Windows internals
    const ULONG MAX_PROCESS_CALLBACKS = 64;

    // If user didn't provide a table address, we can't proceed
    if (!CallbackTable) {
        DbgPrint("[elemetry] EnumerateCreateProcessCallbacks: No callback table address provided\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[elemetry] EnumerateCreateProcessCallbacks: Using callback table at %p\n", CallbackTable);

    // Allocate buffer for callback pointers
    PVOID* callbackPointers = (PVOID*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                     sizeof(PVOID) * MAX_PROCESS_CALLBACKS,
                                                     'CBpP');
    if (!callbackPointers) {
        DbgPrint("[elemetry] EnumerateCreateProcessCallbacks: Failed to allocate memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(callbackPointers, sizeof(PVOID) * MAX_PROCESS_CALLBACKS);

    // Read callback pointers from the table
    SIZE_T bytesRead = 0;

    status = ReadProtectedKernelMemory(
        CallbackTable,
        callbackPointers,
        sizeof(PVOID) * MAX_PROCESS_CALLBACKS,
        &bytesRead
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] EnumerateCreateProcessCallbacks: Failed to read callback table: 0x%X\n", status);
        ExFreePoolWithTag(callbackPointers, 'CBpP');
        return status;
    }

    // Process each callback pointer
    ULONG count = 0;
    for (ULONG i = 0; i < MAX_PROCESS_CALLBACKS && count < MaxCallbacks; i++) {
        if (callbackPointers[i] == NULL || callbackPointers[i] == (PVOID)~0) {
            continue;
        }

        // For process callbacks, we need to mask out the low bits and dereference
        PVOID actualCallback = NULL;

        // Process callback pointers have their lowest bit set to indicate Ex version
        // We need to mask this out (0xFFFFFFFFFFFFFFF8) and then dereference
        PVOID maskedPointer = (PVOID)((ULONG_PTR)callbackPointers[i] & 0xFFFFFFFFFFFFFFF8);

        // Read the actual callback function pointer
        SIZE_T bytes = 0;
        NTSTATUS readStatus = ReadProtectedKernelMemory(maskedPointer, &actualCallback, sizeof(PVOID), &bytes);

        if (!NT_SUCCESS(readStatus) || !actualCallback) {
            DbgPrint("[elemetry] EnumerateCreateProcessCallbacks: Failed to read callback at index %u\n", i);
            continue;
        }

        // This is a valid callback, create an entry
        RtlZeroMemory(&CallbackArray[count], sizeof(CALLBACK_INFO_SHARED));

        CallbackArray[count].Type = CALLBACK_TYPE::PsProcessCreation;
        CallbackArray[count].Address = actualCallback;

        // Get base address to determine which module this callback belongs to
        ULONG_PTR callbackAddress = (ULONG_PTR)actualCallback;
        BOOLEAN found = FALSE;

        // Try to find which module this callback belongs to
        for (ULONG m = 0; m < HARDCODED_MODULE_COUNT; m++) {
            if (g_FoundModules[m].BaseAddress != NULL) {
                ULONG_PTR moduleBase = (ULONG_PTR)g_FoundModules[m].BaseAddress;
                ULONG_PTR moduleEnd = moduleBase + g_FoundModules[m].Size;

                if (callbackAddress >= moduleBase && callbackAddress < moduleEnd) {
                    // Extract just the filename from the path
                    WCHAR* LastBackslash = wcsrchr(g_FoundModules[m].Path, L'\\');
                    PCWSTR FileNameOnly = LastBackslash ? LastBackslash + 1 : g_FoundModules[m].Path;

                    // Convert wide char to char (ASCII only)
                    for (ULONG c = 0; FileNameOnly[c] && c < MAX_MODULE_NAME - 1; c++) {
                        CallbackArray[count].ModuleName[c] = (CHAR)FileNameOnly[c];
                    }

                    // Set callback name based on offset from module base
                    sprintf_s(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME,
                             "ProcessCallback+0x%llX", (ULONG_PTR)callbackAddress - moduleBase);

                    found = TRUE;
                    break;
                }
            }
        }

        // If module not found, use generic name
        if (!found) {
            RtlCopyMemory(CallbackArray[count].ModuleName, "Unknown", sizeof("Unknown"));
            sprintf_s(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME,
                     "ProcessCallback@0x%p", actualCallback);
        }

        count++;
    }

    *FoundCallbacks = count;
    DbgPrint("[elemetry] EnumerateCreateProcessCallbacks: Found %u callbacks\n", count);

    ExFreePoolWithTag(callbackPointers, 'CBpP');
    return status;
}

// Implement the missing EnumerateCreateThreadCallbacks function
NTSTATUS EnumerateCreateThreadCallbacks(
    _In_opt_ PVOID CallbackTable,
    _Out_writes_to_(MaxCallbacks, *FoundCallbacks) PCALLBACK_INFO_SHARED CallbackArray,
    _In_ ULONG MaxCallbacks,
    _Out_ PULONG FoundCallbacks
)
{
    NTSTATUS status = STATUS_SUCCESS;
    *FoundCallbacks = 0;

    // Hard-coded array size based on known Windows internals
    const ULONG MAX_THREAD_CALLBACKS = 64;

    // If user didn't provide a table address, we can't proceed
    if (!CallbackTable) {
        DbgPrint("[elemetry] EnumerateCreateThreadCallbacks: No callback table address provided\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[elemetry] EnumerateCreateThreadCallbacks: Using callback table at %p\n", CallbackTable);

    // Allocate buffer for callback pointers
    PVOID* callbackPointers = (PVOID*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                     sizeof(PVOID) * MAX_THREAD_CALLBACKS,
                                                     'CBpT');
    if (!callbackPointers) {
        DbgPrint("[elemetry] EnumerateCreateThreadCallbacks: Failed to allocate memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(callbackPointers, sizeof(PVOID) * MAX_THREAD_CALLBACKS);

    // Read callback pointers from the table
    SIZE_T bytesRead = 0;

    // First try with protected read
    status = ReadProtectedKernelMemory(
        CallbackTable,
        callbackPointers,
        sizeof(PVOID) * MAX_THREAD_CALLBACKS,
        &bytesRead
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] EnumerateCreateThreadCallbacks: Failed to read callback table: 0x%X\n", status);
        ExFreePoolWithTag(callbackPointers, 'CBpT');
        return status;
    }

    // Process each callback pointer
    ULONG count = 0;
    for (ULONG i = 0; i < MAX_THREAD_CALLBACKS && count < MaxCallbacks; i++) {
        if (callbackPointers[i] == NULL || callbackPointers[i] == (PVOID)~0) {
            continue;
        }

        // For thread callbacks, we need to mask out the low bits and dereference (same as process callbacks)
        PVOID actualCallback = NULL;

        // Thread callback pointers have their lowest bit set for some reason
        // We need to mask this out (0xFFFFFFFFFFFFFFF8) and then dereference
        PVOID maskedPointer = (PVOID)((ULONG_PTR)callbackPointers[i] & 0xFFFFFFFFFFFFFFF8);

        // Read the actual callback function pointer
        SIZE_T bytes = 0;
        NTSTATUS readStatus = ReadProtectedKernelMemory(maskedPointer, &actualCallback, sizeof(PVOID), &bytes);

        if (!NT_SUCCESS(readStatus) || !actualCallback) {
            DbgPrint("[elemetry] EnumerateCreateThreadCallbacks: Failed to read callback at index %u\n", i);
            continue;
        }

        // This is a valid callback, create an entry
        RtlZeroMemory(&CallbackArray[count], sizeof(CALLBACK_INFO_SHARED));

        CallbackArray[count].Type = CALLBACK_TYPE::PsThreadCreation;
        CallbackArray[count].Address = actualCallback;

        // Get base address to determine which module this callback belongs to
        ULONG_PTR callbackAddress = (ULONG_PTR)actualCallback;
        BOOLEAN found = FALSE;

        // Try to find which module this callback belongs to
        for (ULONG m = 0; m < HARDCODED_MODULE_COUNT; m++) {
            if (g_FoundModules[m].BaseAddress != NULL) {
                ULONG_PTR moduleBase = (ULONG_PTR)g_FoundModules[m].BaseAddress;
                ULONG_PTR moduleEnd = moduleBase + g_FoundModules[m].Size;

                if (callbackAddress >= moduleBase && callbackAddress < moduleEnd) {
                    // Extract just the filename from the path
                    WCHAR* LastBackslash = wcsrchr(g_FoundModules[m].Path, L'\\');
                    PCWSTR FileNameOnly = LastBackslash ? LastBackslash + 1 : g_FoundModules[m].Path;

                    // Convert wide char to char (ASCII only)
                    for (ULONG c = 0; FileNameOnly[c] && c < MAX_MODULE_NAME - 1; c++) {
                        CallbackArray[count].ModuleName[c] = (CHAR)FileNameOnly[c];
                    }

                    // Set callback name based on offset from module base
                    sprintf_s(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME,
                             "ThreadCallback+0x%llX", (ULONG_PTR)callbackAddress - moduleBase);

                    found = TRUE;
                    break;
                }
            }
        }

        // If module not found, use generic name
        if (!found) {
            RtlCopyMemory(CallbackArray[count].ModuleName, "Unknown", sizeof("Unknown"));
            sprintf_s(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME,
                     "ThreadCallback@0x%p", actualCallback);
        }

        count++;
    }

    *FoundCallbacks = count;
    DbgPrint("[elemetry] EnumerateCreateThreadCallbacks: Found %u callbacks\n", count);

    ExFreePoolWithTag(callbackPointers, 'CBpT');
    return status;
}

// Implement a safer registry callback enumeration function
NTSTATUS EnumerateRegistryCallbacks(
    _In_opt_ PVOID CallbackTable,
    _Out_writes_to_(MaxCallbacks, *FoundCallbacks) PCALLBACK_INFO_SHARED CallbackArray,
    _In_ ULONG MaxCallbacks,
    _Out_ PULONG FoundCallbacks
)
{
    NTSTATUS status = STATUS_SUCCESS;
    *FoundCallbacks = 0;

    // Validate parameters
    if (!CallbackTable || !CallbackArray || !FoundCallbacks || MaxCallbacks == 0) {
        DbgPrint("[elemetry] EnumerateRegistryCallbacks: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[elemetry] EnumerateRegistryCallbacks: Using callback list at %p\n", CallbackTable);

    // Get the current thread's IRP (if there is one)
    PIRP currentIrp = GetCurrentIrpSafe();
    
    // Check if we're executing in an IRP context and if that IRP is cancelable
    if (currentIrp && (currentIrp->Cancel)) {
        DbgPrint("[elemetry] EnumerateRegistryCallbacks: IRP already cancelled before starting\n");
        return STATUS_CANCELLED;
    }

    // Registry callbacks are stored in a linked list, so we need to be careful with traversal
    // First, capture just the list head entry
    LIST_ENTRY listHead = {0};
    SIZE_T bytesRead = 0;

    // Try to read the list head using protected memory access
    status = ReadProtectedKernelMemory(CallbackTable, &listHead, sizeof(LIST_ENTRY), &bytesRead);
    if (!NT_SUCCESS(status) || bytesRead < sizeof(LIST_ENTRY)) {
        DbgPrint("[elemetry] EnumerateRegistryCallbacks: Failed to read list head: 0x%X\n", status);
        return status;
    }

    // Debug the list head values
    DbgPrint("[elemetry] EnumerateRegistryCallbacks: List head values - Flink: %p, Blink: %p\n", 
             listHead.Flink, listHead.Blink);

    // Define the basic registry callback entry structure based on Windows internals
    // This is a simplified version that only captures the fields we need
    typedef struct _CM_CALLBACK_ENTRY {
        LIST_ENTRY ListEntry;     // Linked list pointers
        ULONG Unknown1;           // Reserved fields
        ULONG Unknown2;
        LARGE_INTEGER Cookie;     // Registration cookie
        PVOID Context;            // Optional context passed at registration
        PVOID Function;           // Callback function pointer
    } CM_CALLBACK_ENTRY, *PCM_CALLBACK_ENTRY;

    // Check if list is empty (head points to itself)
    if (listHead.Flink == CallbackTable) {
        DbgPrint("[elemetry] EnumerateRegistryCallbacks: Registry callback list is empty\n");
        return STATUS_SUCCESS;
    }
    
    // Check if Flink or Blink is NULL
    if (listHead.Flink == NULL || listHead.Blink == NULL) {
        DbgPrint("[elemetry] EnumerateRegistryCallbacks: Invalid list head (NULL pointers)\n");
        return STATUS_INVALID_ADDRESS;
    }
    
    // Check for reasonable list head values (must be within kernel space)
    if ((ULONG_PTR)listHead.Flink < (ULONG_PTR)MmSystemRangeStart ||
        (ULONG_PTR)listHead.Blink < (ULONG_PTR)MmSystemRangeStart) {
        DbgPrint("[elemetry] EnumerateRegistryCallbacks: List head contains invalid pointers (outside kernel space)\n");
        return STATUS_INVALID_ADDRESS;
    }

    // Alternative approach - try first check if this is actually the CmpCallbackListLock and the list head might be 16 bytes after
    // Windows Server 2022 appears to have the CmpCallbackListLock at this location and list head 16 bytes later
    PVOID alternateListHead = (PVOID)((ULONG_PTR)CallbackTable + 0x10);
    LIST_ENTRY altListHead = {0};
    
    // Try to read the alternate list head location
    status = ReadProtectedKernelMemory(alternateListHead, &altListHead, sizeof(LIST_ENTRY), &bytesRead);
    if (NT_SUCCESS(status) && bytesRead == sizeof(LIST_ENTRY) && 
        altListHead.Flink != NULL && altListHead.Blink != NULL &&
        (ULONG_PTR)altListHead.Flink >= (ULONG_PTR)MmSystemRangeStart &&
        (ULONG_PTR)altListHead.Blink >= (ULONG_PTR)MmSystemRangeStart) {
        
        DbgPrint("[elemetry] EnumerateRegistryCallbacks: Found valid alternate list head at %p (Flink: %p, Blink: %p)\n",
                 alternateListHead, altListHead.Flink, altListHead.Blink);
        
        // Use the alternate list head instead
        CallbackTable = alternateListHead;
        listHead = altListHead;
    }

    // Safety limits to prevent infinite loops or excessive enumeration
    ULONG maxEntries = min(100, MaxCallbacks);  // Hard cap at 100 entries
    ULONG count = 0;                            // Actual found count
    PVOID currentEntry = listHead.Flink;        // Start with first entry

    // Use a visited list to detect circular references
    PVOID visitedEntries[100] = {0};
    ULONG visitedCount = 0;

    // Add list head to visited list
    visitedEntries[visitedCount++] = CallbackTable;

    // Walk the list safely
    while (currentEntry != NULL && 
           currentEntry != CallbackTable &&  // Stop when we loop back to head
           count < maxEntries && 
           visitedCount < ARRAYSIZE(visitedEntries)) {
        
        // Periodically check if the IRP has been cancelled (every 10 entries)
        if ((visitedCount % 10) == 0 && currentIrp && currentIrp->Cancel) {
            DbgPrint("[elemetry] EnumerateRegistryCallbacks: IRP cancelled during enumeration at entry %d\n", 
                     visitedCount);
            *FoundCallbacks = count; // Return what we have so far
            return STATUS_CANCELLED;
        }
        
        // Check if we've already seen this entry (circular reference)
        BOOLEAN alreadyVisited = FALSE;
        for (ULONG i = 0; i < visitedCount; i++) {
            if (visitedEntries[i] == currentEntry) {
                alreadyVisited = TRUE;
                DbgPrint("[elemetry] EnumerateRegistryCallbacks: Circular reference detected at %p\n", currentEntry);
                break;
            }
        }
        
        if (alreadyVisited) {
            break; // Exit loop if circular reference detected
        }
        
        // Record this entry as visited
        visitedEntries[visitedCount++] = currentEntry;
        
        // Read the callback entry, but be cautious with memory access
        CM_CALLBACK_ENTRY entry = {0};
        status = ReadProtectedKernelMemory(currentEntry, &entry, sizeof(CM_CALLBACK_ENTRY), &bytesRead);
        
        if (!NT_SUCCESS(status) || bytesRead < sizeof(CM_CALLBACK_ENTRY)) {
            DbgPrint("[elemetry] EnumerateRegistryCallbacks: Failed to read entry at %p: 0x%X\n", 
                    currentEntry, status);
            break;
        }
        
        // Validate the callback function pointer
        if (entry.Function == NULL) {
            DbgPrint("[elemetry] EnumerateRegistryCallbacks: Skipping entry with NULL function pointer\n");
            // Move to next entry
            currentEntry = entry.ListEntry.Flink;
            continue;
        }
        
        // Looks like a valid entry, add it to our results
        RtlZeroMemory(&CallbackArray[count], sizeof(CALLBACK_INFO_SHARED));
        
        CallbackArray[count].Type = CALLBACK_TYPE::CmRegistry;
        CallbackArray[count].Address = entry.Function;
        CallbackArray[count].Context = (ULONG)(ULONG_PTR)entry.Context;
        
        // Try to determine which module this callback belongs to
        ULONG_PTR callbackAddress = (ULONG_PTR)entry.Function;
        BOOLEAN found = FALSE;
        
        // Search through our known modules
        for (ULONG m = 0; m < HARDCODED_MODULE_COUNT; m++) {
            if (g_FoundModules[m].BaseAddress != NULL) {
                ULONG_PTR moduleBase = (ULONG_PTR)g_FoundModules[m].BaseAddress;
                ULONG_PTR moduleEnd = moduleBase + g_FoundModules[m].Size;
                
                // Check if callback address is within this module's range
                if (callbackAddress >= moduleBase && callbackAddress < moduleEnd) {
                    // Extract just the filename from path
                    WCHAR* LastBackslash = wcsrchr(g_FoundModules[m].Path, L'\\');
                    PCWSTR FileNameOnly = LastBackslash ? LastBackslash + 1 : g_FoundModules[m].Path;
                    
                    // Convert wide char to char (ASCII only)
                    for (ULONG c = 0; FileNameOnly[c] && c < MAX_MODULE_NAME - 1; c++) {
                        CallbackArray[count].ModuleName[c] = (CHAR)FileNameOnly[c];
                    }
                    
                    // Set name based on offset from module base
                    sprintf_s(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME,
                            "RegistryCallback+0x%llX", (ULONG_PTR)callbackAddress - moduleBase);
                    
                    found = TRUE;
                    break;
                }
            }
        }
        
        // If we couldn't determine the module, use generic naming
        if (!found) {
            RtlCopyMemory(CallbackArray[count].ModuleName, "Unknown", sizeof("Unknown"));
            sprintf_s(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME,
                    "RegistryCallback@0x%p", entry.Function);
        }
        
        // Increment our counter and move to the next entry
        count++;
        
        // Safety check for Flink pointer
        if (entry.ListEntry.Flink == NULL || 
            entry.ListEntry.Flink == currentEntry) {
            DbgPrint("[elemetry] EnumerateRegistryCallbacks: Invalid Flink pointer detected\n");
            break;
        }
        
        // Move to next entry
        currentEntry = entry.ListEntry.Flink;
    }
    
    // Update the caller with how many we found
    *FoundCallbacks = count;
    DbgPrint("[elemetry] EnumerateRegistryCallbacks: Found %u registry callbacks\n", count);
    
    return STATUS_SUCCESS;
}

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

        NTSTATUS status = MmCopyMemory(UserBuffer, sourceAddress, Size, MM_COPY_MEMORY_VIRTUAL, BytesRead);

        if (!NT_SUCCESS(status)) {
            DbgPrint("[elemetry] ReadKernelMemory: MmCopyMemory failed with status 0x%X\n", status);
            *BytesRead = 0;
        }

        return status; // Return the status from MmCopyMemory
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS exceptionStatus = GetExceptionCode();
        DbgPrint("[elemetry] ReadKernelMemory: Exception 0x%X while reading memory at %p\n",
                exceptionStatus, KernelAddress);
        *BytesRead = 0;
        return exceptionStatus;
    }
}

