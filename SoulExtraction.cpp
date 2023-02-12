#include <fltKernel.h>

#include "Lib-SoulExtraction/Lib.SoulExtraction.h"

#define dprintf(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)

void
DriverUnLoad(_In_ struct _DRIVER_OBJECT *DriverObject)
{
    dprintf("free world\n");
}

EXTERN_C
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    dprintf("new world\n");
    DriverObject->DriverUnload = DriverUnLoad;

    return STATUS_SUCCESS;
}
