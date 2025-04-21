#pragma once

#include <Windows.h>
#include "SharedDefs.h"

// Additional structures specific to the client application
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

// Minifilter callback types (only used in client)
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