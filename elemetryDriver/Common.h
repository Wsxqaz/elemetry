#pragma once

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

// Define callback types
enum CALLBACK_TYPE
{
    Unknown,
    PsLoadImage,
    PsProcessCreation,
    PsThreadCreation,
    CmRegistry,
    ObProcessHandlePre,
    ObProcessHandlePost,
    ObThreadHandlePre,
    ObThreadHandlePost,
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

// Define callback function prototype
typedef NTSTATUS (*PENUM_CALLBACKS_CALLBACK)(
    _In_ PCALLBACK_INFO_SHARED CallbackInfo,
    _In_opt_ PVOID Context
); 