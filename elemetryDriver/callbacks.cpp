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
const ULONG g_HardcodedModuleCount = 16; // Updated count

// Define the list of hardcoded module names to search for
static const WCHAR* g_HardcodedModules[g_HardcodedModuleCount] = {
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

// --- Helper to get hardcoded modules ---
NTSTATUS GetHardcodedModules(
    _Out_writes_bytes_opt_(OutputBufferLength) PMODULE_INFO OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWrittenOrRequired
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredSize = g_HardcodedModuleCount * sizeof(MODULE_INFO);
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
    DbgPrint("[elemetry] GetHardcodedModules: Looking for %lu target modules\n", g_HardcodedModuleCount);

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

        // Iterate through the target module names
        for (ULONG targetIndex = 0; targetIndex < g_HardcodedModuleCount; ++targetIndex) {
            // Compare the current module's name (lowercase) with the target name (lowercase)
            if (FindModuleByName(ModuleInfo->Modules, ModuleInfo->Count, g_HardcodedModules[targetIndex], &OutputBuffer[targetIndex])) {
                DbgPrint("[elemetry] GetHardcodedModules: Found module %S at %p\n", 
                         g_HardcodedModules[targetIndex], OutputBuffer[targetIndex].BaseAddress);
                foundCount++;
            } else {
                DbgPrint("[elemetry] GetHardcodedModules: Module %S not found\n", g_HardcodedModules[targetIndex]);
                OutputBuffer[targetIndex].BaseAddress = NULL;
                OutputBuffer[targetIndex].Size = 0;
                OutputBuffer[targetIndex].Flags = 0;
                wcscpy_s(OutputBuffer[targetIndex].Path, MAX_PATH, g_HardcodedModules[targetIndex]);
            }
        }

        // Report how many were found
        DbgPrint("[elemetry] GetHardcodedModules: Found %lu of %lu target modules\n", foundCount, g_HardcodedModuleCount);

        *BytesWrittenOrRequired = foundCount * sizeof(MODULE_INFO);
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
    
    // Zero out the callback array
    RtlZeroMemory(g_CallbackInfo, sizeof(g_CallbackInfo));
    g_CallbackCount = 0;
    
    // Add some sample callbacks for demonstration
    CALLBACK_INFO_SHARED sampleCallback1 = {0};
    sampleCallback1.Type = static_cast<CALLBACK_TYPE>(CALLBACK_TYPE::PsLoadImage);
    sampleCallback1.Address = (PVOID)0xFFFF8000DEADBEEF;
    sampleCallback1.Context = 0x12345678;
    RtlCopyMemory(sampleCallback1.CallbackName, "SampleImageLoadCallback", sizeof("SampleImageLoadCallback"));
    RtlCopyMemory(sampleCallback1.ModuleName, "ntoskrnl.exe", sizeof("ntoskrnl.exe"));
    RegisterCallback(&sampleCallback1);
    
    CALLBACK_INFO_SHARED sampleCallback2 = {0};
    sampleCallback2.Type = static_cast<CALLBACK_TYPE>(CALLBACK_TYPE::PsProcessCreation);
    sampleCallback2.Address = (PVOID)0xFFFF8000ABCDEF12;
    sampleCallback2.Context = 0x87654321;
    RtlCopyMemory(sampleCallback2.CallbackName, "SampleProcessCallback", sizeof("SampleProcessCallback"));
    RtlCopyMemory(sampleCallback2.ModuleName, "Sample.sys", sizeof("Sample.sys"));
    RegisterCallback(&sampleCallback2);
    
    CALLBACK_INFO_SHARED sampleCallback3 = {0};
    sampleCallback3.Type = static_cast<CALLBACK_TYPE>(CALLBACK_TYPE::CmRegistry);
    sampleCallback3.Address = (PVOID)0xFFFF800012345678;
    sampleCallback3.Context = 0x11223344;
    RtlCopyMemory(sampleCallback3.CallbackName, "SampleRegistryCallback", sizeof("SampleRegistryCallback"));
    RtlCopyMemory(sampleCallback3.ModuleName, "Win32k.sys", sizeof("Win32k.sys"));
    RegisterCallback(&sampleCallback3);

    DbgPrint("[elemetry] Initialization complete. Added %d sample callbacks.\n", g_CallbackCount);
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

// IOCTL Handler for EnumerateCallbacks
NTSTATUS HandleEnumerateCallbacksIOCTL(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG OutputBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG RequiredSize = g_CallbackCount * sizeof(CALLBACK_INFO_SHARED);
    
    DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Request received. Buffer size: %u, Required: %u\n", 
             OutputBufferLength, RequiredSize);
    
    if (OutputBufferLength < RequiredSize) {
        DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Buffer too small\n");
        Status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = RequiredSize;
    } else if (!OutputBuffer) {
        DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Invalid buffer\n");
        Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
    } else {
        __try {
            RtlCopyMemory(OutputBuffer, g_CallbackInfo, RequiredSize);
            DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Copied %u callbacks\n", g_CallbackCount);
            Irp->IoStatus.Information = RequiredSize;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[elemetry] HandleEnumerateCallbacksIOCTL: Exception during copy\n");
            Status = STATUS_ACCESS_VIOLATION;
            Irp->IoStatus.Information = 0;
        }
    }
    
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
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
        ULONG RequiredSize = g_HardcodedModuleCount * sizeof(MODULE_INFO);
        *BytesWrittenOrRequired = RequiredSize;
        
        // If no output buffer or buffer too small, just return the size
        if (!OutputBuffer || OutputBufferLength < RequiredSize) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        
        // Copy hardcoded modules to output buffer
        RtlCopyMemory(OutputBuffer, g_HardcodedModules, RequiredSize);
        
        // Log the modules
        for (ULONG i = 0; i < g_HardcodedModuleCount; i++) {
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