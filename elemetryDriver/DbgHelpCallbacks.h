#pragma once

#include <ntddk.h>
#include <fltKernel.h>
#include <ntstrsafe.h>

// Define kernel-mode types that might be missing
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... other fields
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// Declare external kernel variables
extern LIST_ENTRY PsLoadedModuleList;

#define MAX_CALLBACKS 64
#define MAX_CALLBACK_NAME 256
#define MAX_MODULE_NAME 256
#define MAX_SYMBOL_NAME 256

// Callback types
typedef enum _CALLBACK_TYPE {
    CallbackTypeLoadImage = 0,
    CallbackTypeCreateProcess = 1,
    CallbackTypeCreateThread = 2,
    CallbackTypeRegistry = 3,
    CallbackTypeObject = 4,
    CallbackTypeMinifilter = 5
} CALLBACK_TYPE, *PCALLBACK_TYPE;

// Structure to store callback information
typedef struct _CALLBACK_INFO {
    CALLBACK_TYPE Type;
    PVOID Address;
    CHAR CallbackName[MAX_CALLBACK_NAME];
    CHAR ModuleName[MAX_MODULE_NAME];
    CHAR SymbolName[MAX_SYMBOL_NAME];
} CALLBACK_INFO, *PCALLBACK_INFO;

typedef NTSTATUS (*PENUM_CALLBACKS_CALLBACK)(
    _In_ PCALLBACK_INFO CallbackInfo,
    _In_ PVOID Context
);

// Function prototypes
NTSTATUS KernelFormatString(
    _Out_writes_bytes_(BufferSize) PCHAR Buffer,
    _In_ SIZE_T BufferSize,
    _In_ PCSTR Format,
    ...
);

NTSTATUS InitializeCallbackTracking();

void CleanupCallbackTracking();

NTSTATUS RegisterCallback(
    _In_ PCALLBACK_INFO CallbackInfo
);

NTSTATUS EnumerateCallbacks(
    _In_ PENUM_CALLBACKS_CALLBACK EnumCallback,
    _In_ PVOID Context
);

ULONG GetCallbackCount();

NTSTATUS GetCallbackByIndex(
    _In_ ULONG Index,
    _Out_ PCALLBACK_INFO CallbackInfo
);

NTSTATUS GetCallbackByName(
    _In_ PCSTR CallbackName,
    _Out_ PCALLBACK_INFO CallbackInfo
);

NTSTATUS GetCallbackByAddress(
    _In_ PVOID CallbackAddress,
    _Out_ PCALLBACK_INFO CallbackInfo
);

// Individual callback enumeration functions
NTSTATUS EnumerateLoadImageCallbacks(OUT PCALLBACK_INFO CallbackArray, OUT PULONG CallbackCount);
NTSTATUS EnumerateCreateProcessCallbacks(OUT PCALLBACK_INFO CallbackArray, OUT PULONG CallbackCount);
NTSTATUS EnumerateCreateThreadCallbacks(OUT PCALLBACK_INFO CallbackArray, OUT PULONG CallbackCount);
NTSTATUS EnumerateRegistryCallbacks(OUT PCALLBACK_INFO CallbackArray, OUT PULONG CallbackCount);
NTSTATUS EnumerateObjectCallbacks(OUT PCALLBACK_INFO CallbackArray, OUT PULONG CallbackCount);
NTSTATUS EnumerateMinifilterCallbacks(OUT PCALLBACK_INFO CallbackArray, OUT PULONG CallbackCount);

// Helper functions
NTSTATUS GetSymbolFromAddress(PVOID Address, OUT PCHAR SymbolName, OUT PCHAR ModuleName); 