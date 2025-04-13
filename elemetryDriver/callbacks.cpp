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
#define SYSTEM_MODULE_BUFFER_SIZE 47368  // Size needed for system module info
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
    g_CallbackCount = 0;
    RtlZeroMemory(g_CallbackInfo, sizeof(g_CallbackInfo));
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

// --- Kernel Memory Operations ---

// Safely read kernel memory from any address
NTSTATUS ReadKernelMemory(
    _In_ PVOID KernelAddress,
    _Out_writes_bytes_(Size) PVOID UserBuffer,
    _In_ SIZE_T Size,
    _Out_ PSIZE_T BytesRead
)
{
    NTSTATUS status = STATUS_SUCCESS;
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
        
        status = MmCopyMemory(UserBuffer, sourceAddress, Size, MM_COPY_MEMORY_VIRTUAL, BytesRead);
        
        if (!NT_SUCCESS(status)) {
            DbgPrint("[elemetry] ReadKernelMemory: MmCopyMemory failed with status 0x%X\n", status);
            *BytesRead = 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[elemetry] ReadKernelMemory: Exception 0x%X while reading memory at %p\n", 
                status, KernelAddress);
        *BytesRead = 0;
    }

    return status;
}

// IOCTL handler for reading kernel memory
NTSTATUS HandleReadKernelMemoryIOCTL(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    
    DbgPrint("[elemetry] HandleReadKernelMemoryIOCTL: Request received. Buffer size: %u\n", outputBufferLength);
    
    // Validate buffer sizes
    if (inputBufferLength < sizeof(KERNEL_READ_REQUEST) || 
        outputBufferLength < sizeof(KERNEL_READ_REQUEST)) {
        DbgPrint("[elemetry] HandleReadKernelMemoryIOCTL: Buffer too small\n");
        status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
        goto Exit;
    }
    
    // Get request data from input buffer
    PKERNEL_READ_REQUEST request = (PKERNEL_READ_REQUEST)inputBuffer;
    
    // Allocate temporary buffer in kernel space
    PVOID kernelBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, request->Size, 'RmpT');
    if (!kernelBuffer) {
        DbgPrint("[elemetry] HandleReadKernelMemoryIOCTL: Failed to allocate buffer\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        Irp->IoStatus.Information = 0;
        goto Exit;
    }
    
    // Read from kernel address to our kernel buffer
    SIZE_T bytesRead = 0;
    status = ReadKernelMemory(request->Address, kernelBuffer, request->Size, &bytesRead);
    
    if (NT_SUCCESS(status)) {
        // Now copy from kernel buffer to user buffer
        __try {
            // Validate user buffer
            ProbeForWrite(request->Buffer, request->Size, 1);
            
            // Copy data to user buffer
            RtlCopyMemory(request->Buffer, kernelBuffer, bytesRead);
            request->BytesRead = bytesRead;
            
            DbgPrint("[elemetry] HandleReadKernelMemoryIOCTL: Successfully read %llu bytes from %p\n", 
                    bytesRead, request->Address);
                    
            Irp->IoStatus.Information = sizeof(KERNEL_READ_REQUEST);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            DbgPrint("[elemetry] HandleReadKernelMemoryIOCTL: Exception 0x%X accessing user buffer\n", status);
            Irp->IoStatus.Information = 0;
        }
    } else {
        DbgPrint("[elemetry] HandleReadKernelMemoryIOCTL: ReadKernelMemory failed: 0x%X\n", status);
        Irp->IoStatus.Information = 0;
    }
    
    // Free kernel buffer
    ExFreePoolWithTag(kernelBuffer, 'RmpT');
    
Exit:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// --- Callback Enumeration Functions ---

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
    status = ReadKernelMemory(
        CallbackTable, 
        callbackPointers, 
        sizeof(PVOID) * MAX_LOAD_IMAGE_CALLBACKS, 
        &bytesRead
    );
    
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
        
        // Get base address to determine which module this belongs to
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

// Structures and patterns for memory search
typedef struct _CALLBACK_SEARCH_PATTERN {
    UCHAR* Pattern;      // Pattern bytes to search for
    SIZE_T Size;         // Size of pattern
    LONG Offset;         // Offset from pattern to get to the instruction containing the address
} CALLBACK_SEARCH_PATTERN, *PCALLBACK_SEARCH_PATTERN;

// Byte patterns for different Windows versions
// These are from TelemetrySourcerer and cover most Windows 10 versions
static UCHAR CP_PATTERN_W10_WX[] = { 0x48, 0x8d, 0x0c, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xc0, 0x49, 0x03, 0xcd, 0x48, 0x8b };

// Memory search function similar to TelemetrySourcerer's MemorySearch
NTSTATUS MemorySearch(PCUCHAR StartAddress, PCUCHAR EndAddress, PCUCHAR PatternBuffer, SIZE_T PatternLength, PUCHAR* FoundAddress)
{
    *FoundAddress = (PUCHAR)StartAddress;

    while (*FoundAddress < EndAddress) {
        BOOLEAN match = TRUE;
        for (SIZE_T i = 0; i < PatternLength; i++) {
            if ((*FoundAddress)[i] != PatternBuffer[i]) {
                match = FALSE;
                break;
            }
        }
        
        if (match) {
            return STATUS_SUCCESS;
        }
        
        *FoundAddress += 1;
    }

    return STATUS_NOT_FOUND;
}

// Function to find the kernel address of PspCreateProcessNotifyRoutine
NTSTATUS FindPspCreateProcessNotifyRoutine(PVOID* CallbackTableAddress)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    
    // Initialize to NULL
    *CallbackTableAddress = NULL;
    
    DbgPrint("[elemetry] FindPspCreateProcessNotifyRoutine: Searching for callback table...\n");
    
    // Get ntoskrnl.exe base address
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsSetCreateProcessNotifyRoutine");
    PVOID psSetCreateProcessNotifyRoutine = MmGetSystemRoutineAddress(&routineName);
    
    if (!psSetCreateProcessNotifyRoutine) {
        DbgPrint("[elemetry] FindPspCreateProcessNotifyRoutine: Failed to get PsSetCreateProcessNotifyRoutine address\n");
        return STATUS_NOT_FOUND;
    }
    
    DbgPrint("[elemetry] FindPspCreateProcessNotifyRoutine: PsSetCreateProcessNotifyRoutine at %p\n", psSetCreateProcessNotifyRoutine);
    
    // Define search range - examine 4KB around the routine
    ULONG searchSize = 4096;
    PUCHAR startAddress = (PUCHAR)psSetCreateProcessNotifyRoutine;
    PUCHAR endAddress = startAddress + searchSize;
    
    // Create search pattern object
    CALLBACK_SEARCH_PATTERN pattern;
    pattern.Pattern = CP_PATTERN_W10_WX;
    pattern.Size = sizeof(CP_PATTERN_W10_WX);
    pattern.Offset = -4;  // Offset to the pointer
    
    // Search for the pattern
    PUCHAR foundAddress = NULL;
    status = MemorySearch(startAddress, endAddress, pattern.Pattern, pattern.Size, &foundAddress);
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] FindPspCreateProcessNotifyRoutine: Pattern not found\n");
        return status;
    }
    
    DbgPrint("[elemetry] FindPspCreateProcessNotifyRoutine: Pattern found at %p\n", foundAddress);
    
    // Apply the offset to get to the instruction containing the address
    foundAddress += pattern.Offset;
    
    // Extract the relative offset from the instruction
    // This follows the pattern in TelemetrySourcerer where they do:
    // PspSetCreateProcessNotifyRoutine += *(PLONG)(PspSetCreateProcessNotifyRoutine);
    PLONG relativeOffset = (PLONG)foundAddress;
    
    // Calculate the final address
    // The relative jump is from the *next* instruction, so add sizeof(LONG)
    PUCHAR callbackTable = foundAddress + *relativeOffset + sizeof(LONG);
    
    *CallbackTableAddress = callbackTable;
    
    DbgPrint("[elemetry] FindPspCreateProcessNotifyRoutine: Found callback table at %p\n", *CallbackTableAddress);
    
    return STATUS_SUCCESS;
}

// Enumerate process creation notification callbacks - updated to use auto-detection
NTSTATUS EnumerateCreateProcessCallbacks(
    _In_opt_ PVOID CallbackTable,
    _Out_writes_to_(MaxCallbacks, *FoundCallbacks) PCALLBACK_INFO_SHARED CallbackArray,
    _In_ ULONG MaxCallbacks,
    _Out_ PULONG FoundCallbacks
)
{
    // Implementation similar to EnumerateLoadImageCallbacks, but for process creation
    NTSTATUS status = STATUS_SUCCESS;
    *FoundCallbacks = 0;
    
    // Hard-coded array size based on known Windows internals
    const ULONG MAX_PROCESS_CALLBACKS = 64;
    
    // If user didn't provide a table address, try to find it automatically
    if (!CallbackTable) {
        DbgPrint("[elemetry] EnumerateCreateProcessCallbacks: No callback table provided, searching automatically\n");
        status = FindPspCreateProcessNotifyRoutine(&CallbackTable);
        
        if (!NT_SUCCESS(status) || !CallbackTable) {
            DbgPrint("[elemetry] EnumerateCreateProcessCallbacks: Failed to find callback table: 0x%X\n", status);
            return status == STATUS_SUCCESS ? STATUS_UNSUCCESSFUL : status;
        }
    }
    
    DbgPrint("[elemetry] EnumerateCreateProcessCallbacks: Using callback table at %p\n", CallbackTable);
    
    // Allocate buffer for callback pointers
    PVOID* callbackPointers = (PVOID*)ExAllocatePool2(POOL_FLAG_NON_PAGED, 
                                                     sizeof(PVOID) * MAX_PROCESS_CALLBACKS,
                                                     'CBpT');
    if (!callbackPointers) {
        DbgPrint("[elemetry] EnumerateCreateProcessCallbacks: Failed to allocate memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(callbackPointers, sizeof(PVOID) * MAX_PROCESS_CALLBACKS);
    
    // Read callback pointers from the table
    SIZE_T bytesRead = 0;
    status = ReadKernelMemory(
        CallbackTable, 
        callbackPointers, 
        sizeof(PVOID) * MAX_PROCESS_CALLBACKS, 
        &bytesRead
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] EnumerateCreateProcessCallbacks: Failed to read callback table: 0x%X\n", status);
        ExFreePoolWithTag(callbackPointers, 'CBpT');
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
        
        // Process callback pointers have their lowest bit set for some reason
        // We need to mask this out (0xFFFFFFFFFFFFFFF8) and then dereference
        PVOID maskedPointer = (PVOID)((ULONG_PTR)callbackPointers[i] & 0xFFFFFFFFFFFFFFF8);
        
        // Read the actual callback function pointer
        SIZE_T bytes = 0;
        NTSTATUS readStatus = ReadKernelMemory(maskedPointer, &actualCallback, sizeof(PVOID), &bytes);
        
        if (!NT_SUCCESS(readStatus) || !actualCallback) {
            DbgPrint("[elemetry] EnumerateCreateProcessCallbacks: Failed to read callback at index %u\n", i);
            continue;
        }
        
        // This is a valid callback, create an entry
        RtlZeroMemory(&CallbackArray[count], sizeof(CALLBACK_INFO_SHARED));
        
        CallbackArray[count].Type = CALLBACK_TYPE::PsProcessCreation;
        CallbackArray[count].Address = actualCallback;
        
        // Get base address to determine which module this belongs to
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
    
    ExFreePoolWithTag(callbackPointers, 'CBpT');
    return status;
}

// IOCTL handler for enumerating callbacks
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
    
    // Process the request based on callback type
    ULONG callbacksFound = 0;
    
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
            request->TableAddress,
            response->Callbacks,
            min(maxCallbacks, request->MaxCallbacks),
            &callbacksFound
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