#include "DbgHelpCallbacks.h"
#include <ntddk.h>
#include <fltKernel.h>

// Helper function for string formatting in kernel mode
NTSTATUS KernelFormatString(PCHAR Buffer, SIZE_T BufferSize, PCSTR Format, ...) {
    if (!Buffer || !Format || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    va_list Args;
    va_start(Args, Format);
    NTSTATUS status = RtlStringCbVPrintfA(Buffer, BufferSize, Format, Args);
    va_end(Args);
    return status;
}

// Global callback storage
static CALLBACK_INFO g_Callbacks[MAX_CALLBACKS] = {
    { CallbackTypeLoadImage, NULL, "", "", "" }
};
static ULONG g_CallbackCount = 0;

// Initialize callback tracking
NTSTATUS InitializeCallbackTracking() {
    RtlZeroMemory(g_Callbacks, sizeof(g_Callbacks));
    for (ULONG i = 0; i < MAX_CALLBACKS; i++) {
        g_Callbacks[i].Type = CallbackTypeLoadImage;
    }
    g_CallbackCount = 0;
    return STATUS_SUCCESS;
}

// Cleanup callback tracking
void CleanupCallbackTracking() {
    RtlZeroMemory(g_Callbacks, sizeof(g_Callbacks));
    g_CallbackCount = 0;
}

// Register a new callback
NTSTATUS RegisterCallback(PCALLBACK_INFO CallbackInfo) {
    if (g_CallbackCount >= MAX_CALLBACKS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!CallbackInfo || !CallbackInfo->CallbackName || !CallbackInfo->Address) {
        return STATUS_INVALID_PARAMETER;
    }

    // Store callback information
    RtlCopyMemory(&g_Callbacks[g_CallbackCount], CallbackInfo, sizeof(CALLBACK_INFO));
    g_CallbackCount++;

    return STATUS_SUCCESS;
}

// Enumerate all registered callbacks
NTSTATUS EnumerateCallbacks(PENUM_CALLBACKS_CALLBACK EnumCallback, PVOID Context) {
    if (!EnumCallback) {
        return STATUS_INVALID_PARAMETER;
    }

    for (ULONG i = 0; i < g_CallbackCount; i++) {
        NTSTATUS status = EnumCallback(&g_Callbacks[i], Context);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return STATUS_SUCCESS;
}

// Get callback count
ULONG GetCallbackCount() {
    return g_CallbackCount;
}

// Get callback by index
NTSTATUS GetCallbackByIndex(ULONG Index, PCALLBACK_INFO CallbackInfo) {
    if (Index >= g_CallbackCount || !CallbackInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(CallbackInfo, &g_Callbacks[Index], sizeof(CALLBACK_INFO));
    return STATUS_SUCCESS;
}

// Get callback by name
NTSTATUS GetCallbackByName(PCSTR CallbackName, PCALLBACK_INFO CallbackInfo) {
    if (!CallbackName || !CallbackInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    for (ULONG i = 0; i < g_CallbackCount; i++) {
        if (RtlCompareMemory(g_Callbacks[i].CallbackName, CallbackName, strlen(CallbackName)) == strlen(CallbackName)) {
            RtlCopyMemory(CallbackInfo, &g_Callbacks[i], sizeof(CALLBACK_INFO));
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

// Get callback by address
NTSTATUS GetCallbackByAddress(PVOID CallbackAddress, PCALLBACK_INFO CallbackInfo) {
    if (!CallbackAddress || !CallbackInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    for (ULONG i = 0; i < g_CallbackCount; i++) {
        if (g_Callbacks[i].Address == CallbackAddress) {
            RtlCopyMemory(CallbackInfo, &g_Callbacks[i], sizeof(CALLBACK_INFO));
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

// Helper function to safely read memory from kernel addresses
static BOOLEAN SafeReadMemory(PVOID Address, PVOID Buffer, SIZE_T Size)
{
    if (!Address || !Buffer || !Size)
        return FALSE;

    SIZE_T BytesRead = 0;
    MM_COPY_ADDRESS SourceAddress;
    SourceAddress.VirtualAddress = Address;
    
    NTSTATUS Status = MmCopyMemory(Buffer, SourceAddress, Size, MM_COPY_MEMORY_VIRTUAL, &BytesRead);
    
    return NT_SUCCESS(Status) && (BytesRead == Size);
}

// Helper function to get symbol information using kernel-mode methods
NTSTATUS GetSymbolFromAddress(PVOID Address, OUT PCHAR SymbolName, OUT PCHAR ModuleName)
{
    if (!Address || !SymbolName || !ModuleName)
        return STATUS_INVALID_PARAMETER;

    // Initialize output buffers
    RtlZeroMemory(SymbolName, 256);
    RtlZeroMemory(ModuleName, 256);

    // Get module information using kernel-mode methods
    PLDR_DATA_TABLE_ENTRY ModuleEntry = NULL;
    PLIST_ENTRY ModuleList = &PsLoadedModuleList;
    PLIST_ENTRY ModuleEntryList = ModuleList->Flink;

    while (ModuleEntryList != ModuleList)
    {
        ModuleEntry = CONTAINING_RECORD(ModuleEntryList, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        
        if (Address >= ModuleEntry->DllBase && 
            Address < (PVOID)((ULONG_PTR)ModuleEntry->DllBase + ModuleEntry->SizeOfImage))
        {
            // Found the module, copy its name
            RtlCopyMemory(ModuleName, ModuleEntry->BaseDllName.Buffer, ModuleEntry->BaseDllName.Length);
            ModuleName[ModuleEntry->BaseDllName.Length / sizeof(WCHAR)] = '\0';
            
            // For symbol name, we'll use the offset from module base
            ULONG_PTR Offset = (ULONG_PTR)Address - (ULONG_PTR)ModuleEntry->DllBase;
            KernelFormatString(SymbolName, 256, "Offset_%p", Offset);
            
            return STATUS_SUCCESS;
        }
        
        ModuleEntryList = ModuleEntryList->Flink;
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS EnumerateLoadImageCallbacks(OUT PCALLBACK_INFO CallbackArray, OUT PULONG CallbackCount)
{
    if (!CallbackArray || !CallbackCount)
        return STATUS_INVALID_PARAMETER;

    *CallbackCount = 0;

    // Find the PspLoadImageNotifyRoutine array
    PVOID PspLoadImageNotifyRoutine = NULL;
    if (!SafeReadMemory((PVOID)&PspLoadImageNotifyRoutine, &PspLoadImageNotifyRoutine, sizeof(PVOID)))
        return STATUS_UNSUCCESSFUL;

    // Read the array of callbacks
    for (ULONG i = 0; i < MAX_CALLBACKS; i++)
    {
        PVOID CallbackPtr = NULL;
        if (!SafeReadMemory((PVOID)((ULONG_PTR)PspLoadImageNotifyRoutine + i * sizeof(PVOID)), &CallbackPtr, sizeof(PVOID)))
            break;

        if (!CallbackPtr)
            break;

        // Get the actual callback address
        PVOID CallbackAddress = NULL;
        if (!SafeReadMemory(CallbackPtr, &CallbackAddress, sizeof(PVOID)))
            continue;

        if (!CallbackAddress)
            continue;

        // Store the callback information
        CallbackArray[*CallbackCount].Type = CallbackTypeLoadImage;
        CallbackArray[*CallbackCount].Address = CallbackAddress;

        // Get symbol information
        GetSymbolFromAddress(CallbackAddress, 
                            CallbackArray[*CallbackCount].SymbolName, 
                            CallbackArray[*CallbackCount].ModuleName);

        (*CallbackCount)++;
    }

    return STATUS_SUCCESS;
}

NTSTATUS EnumerateCreateProcessCallbacks(OUT PCALLBACK_INFO CallbackArray, OUT PULONG CallbackCount)
{
    if (!CallbackArray || !CallbackCount)
        return STATUS_INVALID_PARAMETER;

    *CallbackCount = 0;

    // Find the PspCreateProcessNotifyRoutine array
    PVOID PspCreateProcessNotifyRoutine = NULL;
    if (!SafeReadMemory((PVOID)&PspCreateProcessNotifyRoutine, &PspCreateProcessNotifyRoutine, sizeof(PVOID)))
        return STATUS_UNSUCCESSFUL;

    // Read the array of callbacks
    for (ULONG i = 0; i < MAX_CALLBACKS; i++)
    {
        PVOID CallbackPtr = NULL;
        if (!SafeReadMemory((PVOID)((ULONG_PTR)PspCreateProcessNotifyRoutine + i * sizeof(PVOID)), &CallbackPtr, sizeof(PVOID)))
            break;

        if (!CallbackPtr)
            break;

        // Get the actual callback address
        PVOID CallbackAddress = NULL;
        if (!SafeReadMemory(CallbackPtr, &CallbackAddress, sizeof(PVOID)))
            continue;

        if (!CallbackAddress)
            continue;

        // Store the callback information
        CallbackArray[*CallbackCount].Type = CallbackTypeCreateProcess;
        CallbackArray[*CallbackCount].Address = CallbackAddress;

        // Get symbol information
        GetSymbolFromAddress(CallbackAddress, 
                            CallbackArray[*CallbackCount].SymbolName, 
                            CallbackArray[*CallbackCount].ModuleName);

        (*CallbackCount)++;
    }

    return STATUS_SUCCESS;
}

NTSTATUS EnumerateCreateThreadCallbacks(OUT PCALLBACK_INFO CallbackArray, OUT PULONG CallbackCount)
{
    if (!CallbackArray || !CallbackCount)
        return STATUS_INVALID_PARAMETER;

    *CallbackCount = 0;

    // Find the PspCreateThreadNotifyRoutine array
    PVOID PspCreateThreadNotifyRoutine = NULL;
    if (!SafeReadMemory((PVOID)&PspCreateThreadNotifyRoutine, &PspCreateThreadNotifyRoutine, sizeof(PVOID)))
        return STATUS_UNSUCCESSFUL;

    // Read the array of callbacks
    for (ULONG i = 0; i < MAX_CALLBACKS; i++)
    {
        PVOID CallbackPtr = NULL;
        if (!SafeReadMemory((PVOID)((ULONG_PTR)PspCreateThreadNotifyRoutine + i * sizeof(PVOID)), &CallbackPtr, sizeof(PVOID)))
            break;

        if (!CallbackPtr)
            break;

        // Get the actual callback address
        PVOID CallbackAddress = NULL;
        if (!SafeReadMemory(CallbackPtr, &CallbackAddress, sizeof(PVOID)))
            continue;

        if (!CallbackAddress)
            continue;

        // Store the callback information
        CallbackArray[*CallbackCount].Type = CallbackTypeCreateThread;
        CallbackArray[*CallbackCount].Address = CallbackAddress;

        // Get symbol information
        GetSymbolFromAddress(CallbackAddress, 
                            CallbackArray[*CallbackCount].SymbolName, 
                            CallbackArray[*CallbackCount].ModuleName);

        (*CallbackCount)++;
    }

    return STATUS_SUCCESS;
}

NTSTATUS EnumerateRegistryCallbacks(OUT PCALLBACK_INFO CallbackArray, OUT PULONG CallbackCount)
{
    if (!CallbackArray || !CallbackCount)
        return STATUS_INVALID_PARAMETER;

    *CallbackCount = 0;

    // Find the CmCallbackListHead
    PVOID CmCallbackListHead = NULL;
    if (!SafeReadMemory((PVOID)&CmCallbackListHead, &CmCallbackListHead, sizeof(PVOID)))
        return STATUS_UNSUCCESSFUL;

    // Traverse the callback list
    PLIST_ENTRY CurrentEntry = (PLIST_ENTRY)CmCallbackListHead;
    PLIST_ENTRY ListHead = CurrentEntry;

    do
    {
        // Get the callback structure
        struct _CM_CALLBACK_ENTRY {
            LIST_ENTRY ListEntry;
            PVOID Callback;
            // ... other fields
        } CallbackEntry;

        if (!SafeReadMemory(CONTAINING_RECORD(CurrentEntry, struct _CM_CALLBACK_ENTRY, ListEntry), 
                           &CallbackEntry, sizeof(CallbackEntry)))
        {
            CurrentEntry = CurrentEntry->Flink;
            continue;
        }

        if (CallbackEntry.Callback)
        {
            // Store the callback information
            CallbackArray[*CallbackCount].Type = CallbackTypeRegistry;
            CallbackArray[*CallbackCount].Address = CallbackEntry.Callback;

            // Get symbol information
            GetSymbolFromAddress(CallbackEntry.Callback, 
                                CallbackArray[*CallbackCount].SymbolName, 
                                CallbackArray[*CallbackCount].ModuleName);

            (*CallbackCount)++;
        }

        CurrentEntry = CurrentEntry->Flink;
    } while (CurrentEntry != ListHead);

    return STATUS_SUCCESS;
}

NTSTATUS EnumerateObjectCallbacks(OUT PCALLBACK_INFO CallbackArray, OUT PULONG CallbackCount)
{
    if (!CallbackArray || !CallbackCount)
        return STATUS_INVALID_PARAMETER;

    *CallbackCount = 0;

    // Find the ObpCallPreOperationCallbacks array
    PVOID ObpCallPreOperationCallbacks = NULL;
    if (!SafeReadMemory((PVOID)&ObpCallPreOperationCallbacks, &ObpCallPreOperationCallbacks, sizeof(PVOID)))
        return STATUS_UNSUCCESSFUL;

    // Read the array of callbacks
    for (ULONG i = 0; i < MAX_CALLBACKS; i++)
    {
        PVOID CallbackPtr = NULL;
        if (!SafeReadMemory((PVOID)((ULONG_PTR)ObpCallPreOperationCallbacks + i * sizeof(PVOID)), &CallbackPtr, sizeof(PVOID)))
            break;

        if (!CallbackPtr)
            break;

        // Get the actual callback address
        PVOID CallbackAddress = NULL;
        if (!SafeReadMemory(CallbackPtr, &CallbackAddress, sizeof(PVOID)))
            continue;

        if (!CallbackAddress)
            continue;

        // Store the callback information
        CallbackArray[*CallbackCount].Type = CallbackTypeObject;
        CallbackArray[*CallbackCount].Address = CallbackAddress;

        // Get symbol information
        GetSymbolFromAddress(CallbackAddress, 
                            CallbackArray[*CallbackCount].SymbolName, 
                            CallbackArray[*CallbackCount].ModuleName);

        (*CallbackCount)++;
    }

    return STATUS_SUCCESS;
}

NTSTATUS EnumerateMinifilterCallbacks(OUT PCALLBACK_INFO CallbackArray, OUT PULONG CallbackCount)
{
    if (!CallbackArray || !CallbackCount)
        return STATUS_INVALID_PARAMETER;

    *CallbackCount = 0;

    // Find the FltGlobals structure
    PVOID FltGlobals = NULL;
    if (!SafeReadMemory((PVOID)&FltGlobals, &FltGlobals, sizeof(PVOID)))
        return STATUS_UNSUCCESSFUL;

    // Read the FltGlobals structure
    struct _FLT_GLOBALS {
        LIST_ENTRY FilterList;
        // ... other fields
    } FltGlobalsData;

    if (!SafeReadMemory(FltGlobals, &FltGlobalsData, sizeof(FltGlobalsData)))
        return STATUS_UNSUCCESSFUL;

    // Traverse the filter list
    PLIST_ENTRY CurrentEntry = FltGlobalsData.FilterList.Flink;
    PLIST_ENTRY ListHead = &FltGlobalsData.FilterList;

    while (CurrentEntry != ListHead)
    {
        // Read the filter structure
        struct _FLT_FILTER {
            LIST_ENTRY FilterList;
            // ... other fields
            PVOID PreOpCallback;
            PVOID PostOpCallback;
        } FltFilterData;

        if (!SafeReadMemory(CONTAINING_RECORD(CurrentEntry, struct _FLT_FILTER, FilterList), 
                           &FltFilterData, sizeof(FltFilterData)))
        {
            CurrentEntry = CurrentEntry->Flink;
            continue;
        }

        // Add pre-operation callback if it exists
        if (FltFilterData.PreOpCallback)
        {
            CallbackArray[*CallbackCount].Type = CallbackTypeMinifilter;
            CallbackArray[*CallbackCount].Address = FltFilterData.PreOpCallback;

            // Get symbol information
            GetSymbolFromAddress(FltFilterData.PreOpCallback, 
                                CallbackArray[*CallbackCount].SymbolName, 
                                CallbackArray[*CallbackCount].ModuleName);

            (*CallbackCount)++;
        }

        // Add post-operation callback if it exists
        if (FltFilterData.PostOpCallback)
        {
            CallbackArray[*CallbackCount].Type = CallbackTypeMinifilter;
            CallbackArray[*CallbackCount].Address = FltFilterData.PostOpCallback;

            // Get symbol information
            GetSymbolFromAddress(FltFilterData.PostOpCallback, 
                                CallbackArray[*CallbackCount].SymbolName, 
                                CallbackArray[*CallbackCount].ModuleName);

            (*CallbackCount)++;
        }

        // Move to the next filter
        CurrentEntry = CurrentEntry->Flink;
    }

    return STATUS_SUCCESS;
} 