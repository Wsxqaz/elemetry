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
DRIVER_CANCEL CancelDispatchRoutine;

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

// Cancel routine for IRPs
VOID CancelDispatchRoutine(
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    // Get the current stack location
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

    DbgPrint("[elemetry] CancelDispatchRoutine: Cancelling IRP %p with IOCTL 0x%X\n", Irp, ioControlCode);

    // Release the cancel spin lock (acquired by the I/O manager before calling)
    IoReleaseCancelSpinLock(Irp->CancelIrql);

    // Mark the IRP as cancelled
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;

    // Complete the IRP
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    DbgPrint("[elemetry] CancelDispatchRoutine: IRP completed with STATUS_CANCELLED\n");
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

    // Check if IRP has been cancelled
    if (Irp->Cancel) {
        DbgPrint("[elemetry] IRP was cancelled\n");
        Irp->IoStatus.Status = STATUS_CANCELLED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_CANCELLED;
    }

    // For registry callback operations, set a cancel routine in case operation takes time
    if (controlCode == IOCTL_ENUM_CALLBACKS) {
        PCALLBACK_ENUM_REQUEST request = (PCALLBACK_ENUM_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        if (request && request->Type == CallbackTableRegistry) {
            // Register a cancel routine
            KIRQL oldIrql;
            IoAcquireCancelSpinLock(&oldIrql);
            if (Irp->Cancel) {
                // Already cancelled between our check and acquiring the lock
                IoReleaseCancelSpinLock(oldIrql);
                Irp->IoStatus.Status = STATUS_CANCELLED;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return STATUS_CANCELLED;
            }

            IoSetCancelRoutine(Irp, CancelDispatchRoutine);
            IoReleaseCancelSpinLock(oldIrql);

            DbgPrint("[elemetry] Set cancel routine for registry callback enumeration\n");
        }
    }

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (controlCode)
    {
        case IOCTL_GET_MODULES:
            status = HandleGetModulesIOCTL(Irp, stack);
            break;

        case IOCTL_ENUM_CALLBACKS:
            status = HandleEnumerateCallbacksIOCTL(Irp, stack);
            break;

        default:
            DbgPrint("[elemetry] Unknown IOCTL code: 0x%X\n", controlCode);
            Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            status = STATUS_INVALID_DEVICE_REQUEST;
    }

    // For registry callback operations, we manually ensure any cancel routine is cleared
    // without relying on the IoGetCancelRoutine API which is missing in some WDK versions
    if (controlCode == IOCTL_ENUM_CALLBACKS) {
        // Acquire the cancel spin lock and reset the cancel routine directly
        KIRQL oldIrql;
        IoAcquireCancelSpinLock(&oldIrql);
        // Set the cancel routine to NULL (safer than checking it first)
        IoSetCancelRoutine(Irp, NULL);
        IoReleaseCancelSpinLock(oldIrql);
        DbgPrint("[elemetry] Cleared cancel routine after registry callback enumeration\n");
    }

    return status;
}

// Driver entry point
extern "C"
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[elemetry] DriverEntry: Starting initialization\n");

    // Set up driver object
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    // Create device object
    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] DriverEntry: Failed to create device object: 0x%X\n", status);
        return status;
    }

    // Set device flags
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    // Create symbolic link
    UNICODE_STRING symbolicLinkName;
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);

    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[elemetry] DriverEntry: Failed to create symbolic link: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DbgPrint("[elemetry] DriverEntry: Initialization complete\n");
    return status;
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
    DbgPrint("[elemetry] Deleted symbolic link\n");

    // Delete device object
    if (g_DeviceObject) {
        // Delete the device object
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        DbgPrint("[elemetry] Deleted device object\n");
    }

    // Clear static buffers
    RtlZeroMemory(g_ModuleBuffer, MODULE_BUFFER_SIZE);
    DbgPrint("[elemetry] Cleared module buffer\n");

    // Clear all major function pointers
    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = NULL;
    }

    DbgPrint("[elemetry] Driver unload complete\n");
}
