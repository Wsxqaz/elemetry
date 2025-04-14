#include <ntddk.h>
#include "Common.h"
#include "callbacks.h"

// Define a version check for ExAllocatePool2 support
#ifndef NTDDI_WIN10_VB
#define NTDDI_WIN10_VB 0x0A000008  // Windows 10 2004 (20H1/Vibranium)
#endif

// Define pool flags if not available in current SDK
#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED  0x0000000000000040ULL
#endif

#ifndef POOL_FLAG_ZERO_ALLOCATION
#define POOL_FLAG_ZERO_ALLOCATION 0x0000000000000100ULL
#endif

// Define device name and symbolic link
#define DEVICE_NAME L"\\Device\\ElemetryDevice"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\elemetry"

// Global variables
PDEVICE_OBJECT g_DeviceObject = NULL;

// Static buffer for modules (needs space for 16 modules)
// MODULE_INFO size is roughly 528 bytes (PVOID + 2*ULONG + WCHAR[260])
// 16 * 528 = 8448 bytes
#define MODULE_BUFFER_SIZE 8448 // Increased size
static UCHAR g_ModuleBuffer[MODULE_BUFFER_SIZE];

// Forward Declarations for Dispatch Routines
DRIVER_DISPATCH DispatchCreateClose;
DRIVER_DISPATCH DispatchDeviceControl;
DRIVER_UNLOAD DriverUnload;

// Callback function for enumeration
NTSTATUS EnumCallbackHandler(
    _In_ PCALLBACK_INFO_SHARED SharedCallbackInfo,
    _In_opt_ PVOID Context
)
{
    UNREFERENCED_PARAMETER(Context);
    if (!SharedCallbackInfo) return STATUS_INVALID_PARAMETER;

    // Access members from the shared structure
    DbgPrint("[elemetry] EnumCallbackHandler: Type=%d, Addr=0x%p, Name='%hs', Module='%hs'\n",
             (int)SharedCallbackInfo->Type, // Cast enum class for printing
             SharedCallbackInfo->Address,
             SharedCallbackInfo->CallbackName, // Use %hs for CHAR array
             SharedCallbackInfo->ModuleName // Use %hs for CHAR array
    );
    return STATUS_SUCCESS;
}

// DispatchCreateClose Routine
NTSTATUS DispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrint("[elemetry] DispatchCreateClose called\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

// DispatchDeviceControl Routine
NTSTATUS DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    DbgPrint("[elemetry] DispatchDeviceControl called with code 0x%X\n", controlCode);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (controlCode)
    {
        case IOCTL_GET_MODULES:
            status = HandleGetModulesIOCTL(Irp, stack);
            break;

        case IOCTL_GET_CALLBACKS:
            status = HandleEnumerateCallbacksIOCTL(Irp, stack);
            break;

        case IOCTL_ENUM_CALLBACKS:
            status = HandleEnumCallbacksIOCTL(Irp, stack);
            break;

        default:
            DbgPrint("[elemetry] Unknown IOCTL code: 0x%X\n", controlCode);
            Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            status = STATUS_INVALID_DEVICE_REQUEST;
    }

    return status;
}

// Driver entry point
extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status = STATUS_SUCCESS;

    DbgPrint("[elemetry] Driver loading...\n");

    // Check if we're at PASSIVE_LEVEL
    KIRQL CurrentIrql = KeGetCurrentIrql();
    if (CurrentIrql > PASSIVE_LEVEL) {
        DbgPrint("[elemetry] DriverEntry: Running at IRQL %d, need PASSIVE_LEVEL\n", CurrentIrql);
        return STATUS_INVALID_DEVICE_STATE;
    }

    // Initialize system module information early
    ULONG bytesWritten = 0;
    NTSTATUS moduleStatus = GetHardcodedModules(NULL, 0, &bytesWritten); // Call to populate internal g_FoundModules
    if (!NT_SUCCESS(moduleStatus) && moduleStatus != STATUS_BUFFER_TOO_SMALL) {
        DbgPrint("[elemetry] DriverEntry: Failed to pre-initialize modules: 0x%X\n", moduleStatus);
        // Proceed anyway, InitializeCallbackTracking will handle NULL bases
    } else {
        DbgPrint("[elemetry] DriverEntry: Pre-initialized module information.\n");
    }

    // Set up driver unload routine
    DriverObject->DriverUnload = DriverUnload;

    // Initialize callback tracking
    status = InitializeCallbackTracking();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] DriverEntry: Failed to initialize callback tracking: 0x%X\n", status);
        return status;
    }

    // Create device object
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] Failed to create device object: 0x%X\n", status);
        return status;
    }

    // Create symbolic link
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] Failed to create symbolic link: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Set up dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    // Set flags for direct I/O
    g_DeviceObject->Flags |= DO_DIRECT_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[elemetry] Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

// Driver unload routine
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[elemetry] Driver unloading...\n");

    // Delete symbolic link
    UNICODE_STRING symbolicLinkName;
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);
    IoDeleteSymbolicLink(&symbolicLinkName);

    // Delete device object
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    // Clean up callback tracking
    CleanupCallbackTracking();

    DbgPrint("[elemetry] Driver unloaded successfully.\n");
}
