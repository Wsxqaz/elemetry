#pragma once

#include <Windows.h>

// IOCTL codes for communication with the driver
#define IOCTL_GET_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SUPPRESS_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REVERT_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_KERNEL_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUMERATE_LOAD_IMAGE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Maximum number of modules and callbacks
#define CLIENT_MAX_MODULES 256
#define MAX_MODULES 64
#define MAX_CALLBACKS 64
#define MAX_CALLBACKS_SHARED 64
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
    FsPreCreate = 9,          // Corresponds to MfCreatePre
    FsPostCreate = 10,        // Corresponds to MfCreatePost
    FsPreClose = 11,          // Corresponds to MfClosePre
    FsPostClose = 12,         // Corresponds to MfClosePost
    FsPreRead = 13,           // Corresponds to MfReadPre
    FsPostRead = 14,          // Corresponds to MfReadPost
    FsPreWrite = 15,          // Corresponds to MfWritePre
    FsPostWrite = 16,         // Corresponds to MfWritePost
    FsPreQueryInfo = 17,      // Corresponds to MfQueryInformationPre
    FsPostQueryInfo = 18,     // Corresponds to MfQueryInformationPost
    FsPreSetInfo = 19,        // Corresponds to MfSetInformationPre
    FsPostSetInfo = 20,       // Corresponds to MfSetInformationPost
    FsPreDirCtrl = 21,        // Corresponds to MfDirectoryControlPre
    FsPostDirCtrl = 22,       // Corresponds to MfDirectoryControlPost
    FsPreFsCtrl = 23,         // Corresponds to MfFileSystemControlPre
    FsPostFsCtrl = 24         // Corresponds to MfFileSystemControlPost
    // Add more as needed from MINIFILTER_CALLBACK_TYPE if driver populates them
};

// Define module information structure - must match driver's definition
typedef struct _MODULE_INFO
{
    PVOID BaseAddress;
    ULONG Size;
    ULONG Flags;
    WCHAR Path[MAX_PATH];
} MODULE_INFO, *PMODULE_INFO;

// Define structures for kernel memory reading operations
typedef struct _KERNEL_READ_REQUEST {
    PVOID Address;       // Kernel address to read from
    PVOID Buffer;        // Output buffer (usermode)
    SIZE_T Size;         // Size to read
    SIZE_T BytesRead;    // Bytes actually read
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

// Define structures for callback enumeration
typedef enum _CALLBACK_TABLE_TYPE {
    CallbackTableLoadImage,
    CallbackTableCreateProcess,
    CallbackTableCreateThread,
    CallbackTableRegistry,
    CallbackTableMinifilter,
    CallbackTableFilesystem
} CALLBACK_TABLE_TYPE;

// Minifilter callback types
typedef enum _MINIFILTER_CALLBACK_TYPE {
    MfUnknown = 0,
    MfCreatePre,
    MfCreatePost,
    MfCreateNamedPipePre,
    MfCreateNamedPipePost,
    MfClosePre,
    MfClosePost,
    MfReadPre,
    MfReadPost,
    MfWritePre,
    MfWritePost,
    MfQueryInformationPre,
    MfQueryInformationPost,
    MfSetInformationPre,
    MfSetInformationPost,
    MfQueryEaPre,
    MfQueryEaPost,
    MfSetEaPre,
    MfSetEaPost,
    MfFlushBuffersPre,
    MfFlushBuffersPost,
    MfQueryVolumeInformationPre,
    MfQueryVolumeInformationPost,
    MfSetVolumeInformationPre,
    MfSetVolumeInformationPost,
    MfDirectoryControlPre,
    MfDirectoryControlPost,
    MfFileSystemControlPre,
    MfFileSystemControlPost,
    MfDeviceControlPre,
    MfDeviceControlPost,
    MfInternalDeviceControlPre,
    MfInternalDeviceControlPost,
    MfShutdownPre,
    MfShutdownPost,
    MfLockControlPre,
    MfLockControlPost,
    MfCleanupPre,
    MfCleanupPost,
    MfCreateMailslotPre,
    MfCreateMailslotPost,
    MfQuerySecurityPre,
    MfQuerySecurityPost,
    MfSetSecurityPre,
    MfSetSecurityPost,
    MfPowerPre,
    MfPowerPost,
    MfSystemControlPre,
    MfSystemControlPost,
    MfDeviceChangePre,
    MfDeviceChangePost,
    MfQueryQuotaPre,
    MfQueryQuotaPost,
    MfSetQuotaPre,
    MfSetQuotaPost,
    MfPnpPre,
    MfPnpPost
} MINIFILTER_CALLBACK_TYPE;

// Callback information structure
typedef struct _CALLBACK_INFO_SHARED {
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

// Update CALLBACK_ENUM_REQUEST to use the corrected CALLBACK_INFO_SHARED
typedef struct _CALLBACK_ENUM_REQUEST {
    CALLBACK_TABLE_TYPE Type;         // Type of callback to enumerate
    PVOID TableAddress;               // Supplied by usermode from symbols
    ULONG MaxCallbacks;               // Max callbacks to retrieve
    ULONG FoundCallbacks;             // Number of callbacks found
    CALLBACK_INFO_SHARED Callbacks[1]; // Variable-sized array using CORRECT definition
} CALLBACK_ENUM_REQUEST, *PCALLBACK_ENUM_REQUEST;

