#pragma once

// Add structure packing directive
#pragma pack(push, 8)

// Define constants
#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifndef MAX_CALLBACKS_SHARED
#define MAX_CALLBACKS_SHARED 64
#endif

#ifndef MAX_MODULE_NAME
#define MAX_MODULE_NAME 256
#endif

#ifndef MAX_CALLBACK_NAME
#define MAX_CALLBACK_NAME 256
#endif

// Define IOCTL codes
#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x22
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

// Custom IOCTL codes
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
    void* BaseAddress;
    unsigned long Size;
    unsigned long Flags;
    wchar_t Path[MAX_PATH];
} MODULE_INFO, *PMODULE_INFO;

// Define shared callback information structure
typedef struct _CALLBACK_INFO_SHARED
{
    CALLBACK_TYPE Type;
    void* Address;
    unsigned long Context;
    char CallbackName[MAX_CALLBACK_NAME];
    char ModuleName[MAX_MODULE_NAME];
} CALLBACK_INFO_SHARED, *PCALLBACK_INFO_SHARED;

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
    void* TableAddress;               // Supplied by usermode from symbols (optional)
    unsigned long MaxCallbacks;       // Max callbacks to retrieve
    unsigned long FoundCallbacks;     // Number of callbacks found
    CALLBACK_INFO_SHARED Callbacks[1]; // Variable-sized array
} CALLBACK_ENUM_REQUEST, *PCALLBACK_ENUM_REQUEST;

// Restore previous packing
#pragma pack(pop) 