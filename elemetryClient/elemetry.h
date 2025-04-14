#pragma once

#include <Windows.h>

// IOCTL codes for communication with the driver
#define IOCTL_GET_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SUPPRESS_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REVERT_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_KERNEL_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Maximum number of modules and callbacks
#define MAX_MODULES 64
#define MAX_CALLBACKS 64
#define MAX_PATH 260
#define MAX_MODULE_NAME 256
#define MAX_CALLBACK_NAME 256

// Define callback types - must match driver's definition
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

// Define module information structure - must match driver's definition
typedef struct _MODULE_INFO
{
    PVOID BaseAddress;
    ULONG Size;
    ULONG Flags;
    WCHAR Path[MAX_PATH];
} MODULE_INFO, *PMODULE_INFO;

// Define shared callback information structure - must match driver's definition
typedef struct _CALLBACK_INFO_SHARED
{
    CALLBACK_TYPE Type;
    PVOID Address;
    ULONG Context;
    CHAR CallbackName[MAX_CALLBACK_NAME];
    CHAR ModuleName[MAX_MODULE_NAME];
} CALLBACK_INFO_SHARED, *PCALLBACK_INFO_SHARED;

// Define user-mode callback information structure
typedef struct _CALLBACK_INFO
{
    CALLBACK_TYPE Type;
    PVOID Address;
    ULONG Context;
    CHAR Name[MAX_CALLBACK_NAME];
    CHAR ModuleName[MAX_MODULE_NAME];
    BOOLEAN Suppressed;
} CALLBACK_INFO, *PCALLBACK_INFO;

// Define CALLBACK_ENTRY structure for UI
typedef struct _CALLBACK_ENTRY_UI
{
    CALLBACK_TYPE Type;
    PVOID Address;
    CHAR Name[MAX_CALLBACK_NAME];
    CHAR ModuleName[MAX_MODULE_NAME];
    BOOLEAN Suppressed;
} CALLBACK_ENTRY_UI, *PCALLBACK_ENTRY_UI;

// Define structures for kernel memory reading operations
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
    CallbackTableFilesystem, // Minifilter callbacks
    CallbackTableMax
} CALLBACK_TABLE_TYPE;

typedef struct _CALLBACK_ENUM_REQUEST {
    CALLBACK_TABLE_TYPE Type;         // Type of callback to enumerate
    PVOID TableAddress;               // Supplied by usermode from symbols
    ULONG MaxCallbacks;               // Max callbacks to retrieve
    ULONG FoundCallbacks;             // Number of callbacks found
    CALLBACK_INFO_SHARED Callbacks[1]; // Variable-sized array
} CALLBACK_ENUM_REQUEST, *PCALLBACK_ENUM_REQUEST; 