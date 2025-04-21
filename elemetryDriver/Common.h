#pragma once

#include <ntdef.h>
#include <ntddk.h>
#include <wdm.h>
#include "../elemetryClient/SharedDefs.h"

// System Information Class definitions
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

// System module structures
typedef struct _SYSTEM_MODULE {
    ULONG_PTR Reserved[2];
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG_PTR ulModuleCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

// Function declaration for ZwQuerySystemInformation with extern "C"
extern "C" {
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);
}

// Define constants
#define MAX_PATH 260
#define MAX_CALLBACKS_SHARED 64
#define MAX_MODULE_NAME 256
#define MAX_CALLBACK_NAME 256

// Define IOCTL codes
#define IOCTL_GET_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SUPPRESS_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REVERT_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_KERNEL_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Define callback types
enum class CALLBACK_TYPE
{
    Unknown = 0,
    PsLoadImage = 1,
    PsProcessCreation = 2,
    PsThreadCreation = 3,
    CmRegistry = 4,
    ObProcessHandlePre = 5,
    ObProcessHandlePost = 6,
    ObThreadHandlePre = 7,
    ObThreadHandlePost = 8,
    FsPreCreate = 9,
    FsPostCreate = 10,
    FsPreClose = 11,
    FsPostClose = 12,
    FsPreRead = 13,
    FsPostRead = 14,
    FsPreWrite = 15,
    FsPostWrite = 16,
    FsPreQueryInfo = 17,
    FsPostQueryInfo = 18,
    FsPreSetInfo = 19,
    FsPostSetInfo = 20,
    FsPreDirCtrl = 21,
    FsPostDirCtrl = 22,
    FsPreFsCtrl = 23,
    FsPostFsCtrl = 24
    // Add more as needed
};

// Define module information structure
typedef struct _MODULE_INFO
{
    PVOID BaseAddress;
    ULONG Size;
    ULONG Flags;
    WCHAR Path[MAX_PATH];
} MODULE_INFO, *PMODULE_INFO;

// Define shared callback information structure
typedef struct _CALLBACK_INFO_SHARED
{
    CALLBACK_TYPE Type;
    PVOID Address;
    ULONG Context;
    CHAR CallbackName[MAX_CALLBACK_NAME];
    CHAR ModuleName[MAX_MODULE_NAME];
} CALLBACK_INFO_SHARED, *PCALLBACK_INFO_SHARED;

// Define structure for export information (simplified)
#define MAX_EXPORT_NAME 256
typedef struct _EXPORT_INFO {
    CHAR Name[MAX_EXPORT_NAME];
    PVOID Address; // Absolute address
} EXPORT_INFO, *PEXPORT_INFO;

// Define structure for PE parsing input/output
typedef struct _PE_PARSE_CONTEXT {
    PVOID ModuleBase;
    PEXPORT_INFO ExportList;
    ULONG MaxExports;
    ULONG FoundExports;
} PE_PARSE_CONTEXT, *PPE_PARSE_CONTEXT;

// Define structures for memory reading operations
typedef struct _KERNEL_READ_REQUEST {
    PVOID Address;       // Kernel address to read from
    PVOID Buffer;        // Output buffer (usermode)
    SIZE_T Size;         // Size to read
    SIZE_T BytesRead;    // Bytes actually read
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

// Define structures for callback enumeration
typedef enum _CALLBACK_TABLE_TYPE {
    CallbackTableLoadImage = 0,
    CallbackTableCreateProcess,
    CallbackTableCreateThread,
    CallbackTableRegistry,
    CallbackTableFilesystem,
    CallbackTableMax
} CALLBACK_TABLE_TYPE;

typedef struct _CALLBACK_ENUM_REQUEST {
    CALLBACK_TABLE_TYPE Type;         // Type of callback to enumerate
    PVOID TableAddress;               // Supplied by usermode from symbols (optional)
    ULONG MaxCallbacks;               // Max callbacks to retrieve
    ULONG FoundCallbacks;             // Number of callbacks found
    CALLBACK_INFO_SHARED Callbacks[1]; // Variable-sized array
} CALLBACK_ENUM_REQUEST, *PCALLBACK_ENUM_REQUEST;

// Define callback function prototype
typedef NTSTATUS (*PENUM_CALLBACKS_CALLBACK)(
    _In_ PCALLBACK_INFO_SHARED CallbackInfo,
    _In_opt_ PVOID Context
);

// Function declarations for kernel-mode operations
NTSTATUS GetModuleInformation(PSYSTEM_MODULE_INFORMATION* SystemModuleInfo);
NTSTATUS GetCallbackTable(CALLBACK_TABLE_TYPE Type, PVOID* Table);
NTSTATUS EnumerateCallbacks(PCALLBACK_ENUM_REQUEST Request);

// Kernel-mode specific callback structures
typedef struct _CALLBACK_NODE {
    LIST_ENTRY Entry;
    CALLBACK_TYPE Type;
    PVOID Callback;
    PVOID Context;
    BOOLEAN Suppressed;
} CALLBACK_NODE, *PCALLBACK_NODE;

typedef struct _CALLBACK_TABLE {
    KSPIN_LOCK Lock;
    LIST_ENTRY Head;
} CALLBACK_TABLE, *PCALLBACK_TABLE; 