#include "testDriver.h"

// Global variables for callbacks
BOOLEAN g_ImageLoadCallbackRegistered = FALSE;
BOOLEAN g_ProcessCallbackRegistered = FALSE;
BOOLEAN g_ThreadCallbackRegistered = FALSE;
// Registry callback temporarily disabled
// BOOLEAN g_RegistryCallbackRegistered = FALSE;
// LARGE_INTEGER g_RegistryCookie = { 0 };

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    // Set up driver unload routine
    DriverObject->DriverUnload = DriverUnload;

    // Initialize callbacks
    status = InitializeCallbacks();
    if (!NT_SUCCESS(status)) {
        KdPrint(("InitializeCallbacks failed with status 0x%x\n", status));
        DriverUnload(DriverObject);
        return status;
    }

    KdPrint(("Driver loaded successfully\n"));
    return STATUS_SUCCESS;
}

VOID OnImageLoadCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    __try {
        if (FullImageName && ImageInfo) {
            KdPrint(("Image Load: %wZ, ProcessId: %d, ImageBase: 0x%p\n",
                FullImageName,
                HandleToUlong(ProcessId),
                ImageInfo->ImageBase));
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("Exception in OnImageLoadCallback\n"));
    }
}

VOID OnProcessCreateCallback(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
)
{
    __try {
        KdPrint(("Process %s: ParentId: %d, ProcessId: %d\n",
            Create ? "Create" : "Terminate",
            HandleToUlong(ParentId),
            HandleToUlong(ProcessId)));
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("Exception in OnProcessCreateCallback\n"));
    }
}

VOID OnThreadCreateCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
)
{
    __try {
        KdPrint(("Thread %s: ProcessId: %d, ThreadId: %d\n",
            Create ? "Create" : "Terminate",
            HandleToUlong(ProcessId),
            HandleToUlong(ThreadId)));
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("Exception in OnThreadCreateCallback\n"));
    }
}

NTSTATUS OnRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument2);

    __try {
        if (Argument1) {
            REG_NOTIFY_CLASS Operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
            KdPrint(("Registry Operation: %d\n", Operation));
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("Exception in OnRegistryCallback\n"));
    }

    return STATUS_SUCCESS;
}

NTSTATUS InitializeCallbacks()
{
    NTSTATUS status;

    // Register image load callback first
    status = PsSetLoadImageNotifyRoutine(OnImageLoadCallback);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to register image load callback: 0x%x\n", status));
        return status;
    }
    g_ImageLoadCallbackRegistered = TRUE;

    // Register process callback
    status = PsSetCreateProcessNotifyRoutine(OnProcessCreateCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to register process callback: 0x%x\n", status));
        return status;
    }
    g_ProcessCallbackRegistered = TRUE;

    // Register thread callback
    status = PsSetCreateThreadNotifyRoutine(OnThreadCreateCallback);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to register thread callback: 0x%x\n", status));
        return status;
    }
    g_ThreadCallbackRegistered = TRUE;

    // Registry callback temporarily disabled
    KdPrint(("All callbacks registered successfully (registry callback disabled)\n"));
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // Unregister callbacks in reverse order of registration
    // Registry callback temporarily disabled
    // if (g_RegistryCallbackRegistered) {
    //     if (CmUnRegisterCallback) {
    //         CmUnRegisterCallback(g_RegistryCookie);
    //     }
    //     g_RegistryCallbackRegistered = FALSE;
    // }

    if (g_ThreadCallbackRegistered) {
        PsRemoveCreateThreadNotifyRoutine(OnThreadCreateCallback);
        g_ThreadCallbackRegistered = FALSE;
    }

    if (g_ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutine(OnProcessCreateCallback, TRUE);
        g_ProcessCallbackRegistered = FALSE;
    }

    if (g_ImageLoadCallbackRegistered) {
        PsRemoveLoadImageNotifyRoutine(OnImageLoadCallback);
        g_ImageLoadCallbackRegistered = FALSE;
    }

    KdPrint(("Driver unloaded successfully\n"));
} 