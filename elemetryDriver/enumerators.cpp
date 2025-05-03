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
#include "enumerators.h" // Function prototypes for enumerators
#include "memory.h" // Memory read/write functions

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

// Enumerate load image notification callbacks
extern "C" NTSTATUS EnumerateLoadImageCallbacks(
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

    // Process each callback pointer
    ULONG count = 0;
    for (ULONG i = 0; i < MAX_LOAD_IMAGE_CALLBACKS && count < MaxCallbacks; i++) {
        // Read the pointer to the callback structure
        PVOID pointerToCallback = NULL;
        SIZE_T bytesRead = 0;

        status = ReadProtectedKernelMemory(
            (PVOID)((ULONG_PTR)CallbackTable + i * sizeof(PVOID)),
            &pointerToCallback,
            sizeof(PVOID),
            &bytesRead
        );

        if (!NT_SUCCESS(status) || pointerToCallback == NULL) {
            continue;
        }

        // Mask the lower bits and read the actual callback address
        ULONG_PTR maskedPointer = (ULONG_PTR)pointerToCallback & 0xFFFFFFFFFFFFFFF8;
        PVOID actualCallback = NULL;

        status = ReadProtectedKernelMemory(
            (PVOID)maskedPointer,
            &actualCallback,
            sizeof(PVOID),
            &bytesRead
        );

        if (!NT_SUCCESS(status) || actualCallback == NULL) {
            DbgPrint("[elemetry] EnumerateLoadImageCallbacks: Failed to read callback function pointer at %p\n", maskedPointer);
            continue;
        }

        // This is a valid callback, create an entry
        RtlZeroMemory(&CallbackArray[count], sizeof(CALLBACK_INFO_SHARED));

        CallbackArray[count].Type = static_cast<CALLBACK_TYPE>(CALLBACK_TYPE::PsLoadImage);
        CallbackArray[count].Address = actualCallback;

        // Get base address to determine which module this callback belongs to
        ULONG_PTR callbackAddress = (ULONG_PTR)actualCallback;
        BOOLEAN found = FALSE;

        DbgPrint("[elemetry] g_ModuleCount: %u\n", g_ModuleCount);
        // Try to find which module this callback belongs to
        for (ULONG m = 0; m < g_ModuleCount; m++) {
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
                             "LoadImageCallback+0x%llX", callbackAddress - moduleBase);

                    found = TRUE;
                    break;
                }
            }
        }

        // If module not found, use generic name
        if (!found) {
            RtlCopyMemory(CallbackArray[count].ModuleName, "Unknown", sizeof("Unknown"));
            sprintf_s(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME,
                     "LoadImageCallback@0x%p", actualCallback);
        }

        count++;
    }

    *FoundCallbacks = count;
    DbgPrint("[elemetry] EnumerateLoadImageCallbacks: Found %u callbacks\n", count);

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

        CallbackArray[count].Type = static_cast<CALLBACK_TYPE>(CALLBACK_TYPE::PsProcessCreation);
        CallbackArray[count].Address = actualCallback;

        // Get base address to determine which module this callback belongs to
        ULONG_PTR callbackAddress = (ULONG_PTR)actualCallback;
        BOOLEAN found = FALSE;

        // Try to find which module this callback belongs to
        for (ULONG m = 0; m < g_ModuleCount; m++) {
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

        CallbackArray[count].Type = static_cast<CALLBACK_TYPE>(CALLBACK_TYPE::PsThreadCreation);
        CallbackArray[count].Address = actualCallback;

        // Get base address to determine which module this callback belongs to
        ULONG_PTR callbackAddress = (ULONG_PTR)actualCallback;
        BOOLEAN found = FALSE;

        // Try to find which module this callback belongs to
        for (ULONG m = 0; m < g_ModuleCount; m++) {
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
        if ((visitedCount % 10) == 0) {
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

        CallbackArray[count].Type = static_cast<CALLBACK_TYPE>(CALLBACK_TYPE::CmRegistry);
        CallbackArray[count].Address = entry.Function;
        CallbackArray[count].Context = (ULONG)(ULONG_PTR)entry.Context;

        // Try to determine which module this callback belongs to
        ULONG_PTR callbackAddress = (ULONG_PTR)entry.Function;
        BOOLEAN found = FALSE;

        // Search through our known modules
        for (ULONG m = 0; m < g_ModuleCount; m++) {
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

// Function to enumerate filesystem minifilter callbacks
NTSTATUS EnumerateFilesystemCallbacks(
    _Out_writes_to_(MaxCallbacks, *FoundCallbacks) PCALLBACK_INFO_SHARED CallbackArray,
    _In_ ULONG MaxCallbacks,
    _Out_ PULONG FoundCallbacks
)
{
    *FoundCallbacks = 0;

    // Validate parameters
    if (!CallbackArray || MaxCallbacks == 0) {
        DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Beginning minifilter enumeration\n");

    NTSTATUS Status = STATUS_SUCCESS;
    ULONG NumberFiltersReturned = 0;
    ULONG count = 0;

    // First get the number of filters
    Status = FltEnumerateFilters(nullptr, 0, &NumberFiltersReturned);
    if (Status != STATUS_BUFFER_TOO_SMALL) {
        DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Failed to get filter count: 0x%X\n", Status);
        return Status;
    }

    // Allocate buffer for filters
    SIZE_T BufferSize = sizeof(PFLT_FILTER) * NumberFiltersReturned;
    PFLT_FILTER* FilterList = (PFLT_FILTER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, BufferSize, DRIVER_TAG);
    if (!FilterList) {
        DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Failed to allocate filter list\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Get the actual filters
    Status = FltEnumerateFilters(FilterList, (ULONG)BufferSize, &NumberFiltersReturned);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Failed to enumerate filters: 0x%X\n", Status);
        ExFreePoolWithTag(FilterList, DRIVER_TAG);
        return Status;
    }

    // Process each filter
    for (ULONG i = 0; i < NumberFiltersReturned && count < MaxCallbacks; i++) {
        // Get filter information
        ULONG BytesReturned = 0;
        Status = FltGetFilterInformation(FilterList[i], FilterFullInformation, nullptr, 0, &BytesReturned);
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Failed to get filter info size: 0x%X\n", Status);
            continue;
        }

        PFILTER_FULL_INFORMATION FullFilterInfo = (PFILTER_FULL_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, BytesReturned, DRIVER_TAG);
        if (!FullFilterInfo) {
            DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Failed to allocate filter info\n");
            continue;
        }

        Status = FltGetFilterInformation(FilterList[i], FilterFullInformation, FullFilterInfo, BytesReturned, &BytesReturned);
        if (!NT_SUCCESS(Status)) {
            DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Failed to get filter info: 0x%X\n", Status);
            ExFreePoolWithTag(FullFilterInfo, DRIVER_TAG);
            continue;
        }

        // Get the full module path from the filter information
        // Correctly access the FilterNameBuffer within the struct
        WCHAR* modulePath = FullFilterInfo->FilterNameBuffer;
        CHAR modulePathA[MAX_PATH] = { 0 };

        // Convert Unicode to ANSI properly, using FilterNameLength (in bytes)
        ULONG bytesConverted = 0;
        NTSTATUS convertStatus = RtlUnicodeToMultiByteN(
            modulePathA,
            MAX_PATH - 1, // Leave space for null terminator
            &bytesConverted,
            modulePath,
            FullFilterInfo->FilterNameLength // Input length in bytes
        );

        if (!NT_SUCCESS(convertStatus)) {
            DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Failed to convert module path to ANSI: 0x%X\n", convertStatus);
            RtlStringCbCopyA(modulePathA, MAX_PATH, "Unknown"); // Fallback
            bytesConverted = (ULONG)strlen("Unknown"); // Update bytesConverted for fallback
        }
        // Explicitly null-terminate the ANSI buffer after conversion
        // bytesConverted holds the number of non-null bytes written by RtlUnicodeToMultiByteN
        // Ensure we don't write past the buffer boundary defined by MAX_PATH
        if (bytesConverted < MAX_PATH) {
            modulePathA[bytesConverted] = '\0';
        } else {
             modulePathA[MAX_PATH - 1] = '\0'; // Ensure null termination even if conversion filled the buffer
        }

        // Extract just the filename from the path
        CHAR* LastBackslash = strrchr(modulePathA, '\\');
        PCSTR FileNameOnly = LastBackslash ? LastBackslash + 1 : modulePathA;

        // --- Debug Print Raw ANSI Buffer ---
        DbgPrint("[elemetry] Debug: Converted Module Raw: '%hs' (len=%lu), Filename: '%hs'\n",
                 modulePathA, bytesConverted, FileNameOnly);
        // --- End Debug ---

        // Get filter instances
        ULONG NumberInstancesReturned = 0;
        Status = FltEnumerateInstances(nullptr, FilterList[i], nullptr, 0, &NumberInstancesReturned);
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Failed to get instance count: 0x%X\n", Status);
            ExFreePoolWithTag(FullFilterInfo, DRIVER_TAG);
            continue;
        }

        // Calculate required size as ULONG, checking for overflow
        ULONG InstanceListSizeUL = 0;
        // Perform calculation using SIZE_T first to detect potential overflow
        SIZE_T InstanceListSizeSZ = (SIZE_T)sizeof(PFLT_INSTANCE) * NumberInstancesReturned;

        // Check if the SIZE_T result fits within a ULONG
        if (InstanceListSizeSZ > MAXULONG) {
            DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Instance list size exceeds ULONG_MAX (%llu bytes)\n", InstanceListSizeSZ);
            ExFreePoolWithTag(FullFilterInfo, DRIVER_TAG);
            // Treat overflow as insufficient resources or a specific error
            Status = STATUS_INSUFFICIENT_RESOURCES;
            continue; // Skip this filter if size is too large
        } else {
            // Safe to cast to ULONG now
            InstanceListSizeUL = (ULONG)InstanceListSizeSZ;
        }

        // Allocate memory using the original SIZE_T calculation (or InstanceListSizeUL, promotion is safe)
        PFLT_INSTANCE* InstanceList = (PFLT_INSTANCE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, InstanceListSizeSZ, DRIVER_TAG);
        if (!InstanceList) {
            DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Failed to allocate instance list (%lu bytes)\n", InstanceListSizeUL);
            ExFreePoolWithTag(FullFilterInfo, DRIVER_TAG);
            // Allocation failed, insufficient resources is implied, just continue
            continue;
        }

        // Get the actual instances using the validated ULONG size
        Status = FltEnumerateInstances(nullptr, FilterList[i], InstanceList, InstanceListSizeUL, &NumberInstancesReturned);
        if (!NT_SUCCESS(Status)) {
            DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Failed to enumerate instances: 0x%X\n", Status);
            ExFreePoolWithTag(InstanceList, DRIVER_TAG);
            ExFreePoolWithTag(FullFilterInfo, DRIVER_TAG);
            continue;
        }

        if (!NumberInstancesReturned) {
            ExFreePoolWithTag(InstanceList, DRIVER_TAG);
            ExFreePoolWithTag(FullFilterInfo, DRIVER_TAG);
            continue;
        }

        // Process callbacks using the safer approach
        for (ULONG j = 0x16; j < 0x32 && count < MaxCallbacks; j++) {
            // Get callback from instance structure
            PVOID Callback = (PVOID)*(PULONG_PTR)((((ULONG_PTR)InstanceList[0]) + 0x90) + sizeof(PVOID) * j);

            if (Callback) {
                // Get pre and post operation callbacks
                PVOID PreCallback = (PVOID)*(PULONG_PTR)(((ULONG_PTR)Callback) + 0x18);
                PVOID PostCallback = (PVOID)*(PULONG_PTR)(((ULONG_PTR)Callback) + 0x20);

                if (PreCallback) {
                    CallbackArray[count].Type = static_cast<CALLBACK_TYPE>((j - 0x16) * 2 + 11);
                    CallbackArray[count].Address = PreCallback;

                    // --- Start Debug ---
                    DbgPrint("[elemetry] Debug: PreCallback Module Raw: '%hs', Bytes Converted: %lu\n",
                             modulePathA, bytesConverted);
                    CHAR tempCallbackName[MAX_PATH] = {0};
                    NTSTATUS formatStatus = RtlStringCbPrintfA(tempCallbackName, MAX_PATH,
                                                               "PreOperation_%u", j - 0x16);
                    DbgPrint("[elemetry] Debug: PreCallback Name Format Status: 0x%X, Name: '%hs'\n",
                             formatStatus, tempCallbackName);
                    // --- End Debug ---

                    // Copy the module name properly
                    RtlZeroMemory(CallbackArray[count].ModuleName, MAX_MODULE_NAME);
                    RtlStringCbCopyA(CallbackArray[count].ModuleName, MAX_MODULE_NAME, FileNameOnly);

                    // Format the callback name
                    RtlZeroMemory(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME);
                    RtlStringCbCopyA(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME, tempCallbackName);
                    // RtlStringCbPrintfA(CallbackArray[count].CallbackName, MAX_PATH,
                    //                  "PreOperation_%u", j - 0x16);
                    count++;
                }

                if (PostCallback) {
                    CallbackArray[count].Type = static_cast<CALLBACK_TYPE>((j - 0x16) * 2 + 12);
                    CallbackArray[count].Address = PostCallback;

                    // --- Start Debug ---
                    DbgPrint("[elemetry] Debug: PostCallback Module Raw: '%hs', Bytes Converted: %lu\n",
                             modulePathA, bytesConverted);
                    CHAR tempCallbackName[MAX_PATH] = {0};
                    NTSTATUS formatStatus = RtlStringCbPrintfA(tempCallbackName, MAX_PATH,
                                                               "PostOperation_%u", j - 0x16);
                    DbgPrint("[elemetry] Debug: PostCallback Name Format Status: 0x%X, Name: '%hs'\n",
                             formatStatus, tempCallbackName);
                     // --- End Debug ---

                    // Copy the module name properly
                    RtlZeroMemory(CallbackArray[count].ModuleName, MAX_MODULE_NAME);
                    RtlStringCbCopyA(CallbackArray[count].ModuleName, MAX_MODULE_NAME, FileNameOnly);

                    // Format the callback name
                    RtlZeroMemory(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME);
                    RtlStringCbCopyA(CallbackArray[count].CallbackName, MAX_CALLBACK_NAME, tempCallbackName);
                    // RtlStringCbPrintfA(CallbackArray[count].CallbackName, MAX_PATH,
                    //                  "PostOperation_%u", j - 0x16);
                    count++;
                }
            }
        }

        ExFreePoolWithTag(InstanceList, DRIVER_TAG);
        ExFreePoolWithTag(FullFilterInfo, DRIVER_TAG);
    }

    ExFreePoolWithTag(FilterList, DRIVER_TAG);
    *FoundCallbacks = count;

    DbgPrint("[elemetry] EnumerateFilesystemCallbacks: Found %u minifilter callbacks\n", count);
    return STATUS_SUCCESS;
}

