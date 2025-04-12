#pragma once

#include <Windows.h>

// IOCTL codes for communication with the driver
#define IOCTL_GET_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SUPPRESS_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REVERT_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
    PsLoadImage,
    PsProcessCreation,
    PsThreadCreation,
    CmRegistry,
    ObProcessHandlePre,
    ObProcessHandlePost,
    ObThreadHandlePre,
    ObThreadHandlePost
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