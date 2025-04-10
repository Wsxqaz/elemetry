#include <ntddk.h>
#include <fltKernel.h>
#include "DbgHelpCallbacks.h"

// Callback function to process each callback
NTSTATUS ProcessCallback(PCALLBACK_INFO CallbackInfo, PVOID Context) {
    UNREFERENCED_PARAMETER(Context);
    
    if (!CallbackInfo) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("Callback:\n");
    DbgPrint("  Type: %d\n", CallbackInfo->Type);
    DbgPrint("  Address: %p\n", CallbackInfo->Address);
    DbgPrint("  Symbol: %s\n", CallbackInfo->SymbolName);
    DbgPrint("  Module: %s\n", CallbackInfo->ModuleName);
    
    return STATUS_SUCCESS;
}

// Driver entry point
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    // Initialize callback tracking
    NTSTATUS Status = InitializeCallbackTracking();
    if (!NT_SUCCESS(Status)) {
        DbgPrint("Failed to initialize callback tracking: 0x%X\n", Status);
        return Status;
    }

    // Enumerate callbacks
    Status = EnumerateCallbacks(ProcessCallback, NULL);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("Failed to enumerate callbacks: 0x%X\n", Status);
        CleanupCallbackTracking();
        return Status;
    }

    // Set up driver unload routine
    DriverObject->DriverUnload = [](PDRIVER_OBJECT DriverObject)
    {
        UNREFERENCED_PARAMETER(DriverObject);
        CleanupCallbackTracking();
        DbgPrint("Driver unloaded\n");
    };

    return STATUS_SUCCESS;
} 