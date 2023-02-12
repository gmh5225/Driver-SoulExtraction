#include <fltKernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>

#include "File.h"
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

    // maplestory
    void *pf = NULL_CONTEXT;
    void *pbuf = NULL;
    do
    {
        pf = fopen2("\\??\\C:\\Windows\\System32\\ntoskrnl.exe", "rb");
        if (!pf)
        {
            break;
        }

        if (0 != fseek2(pf, 0, SEEK_END))
        {
            break;
        }

        auto file_size = ftell2(pf);
        if (0 != fseek2(pf, 0, SEEK_SET))
        {
            break;
        }

        auto pbuf = ExAllocatePoolWithTag(NonPagedPool, file_size + 10, 'soul');
        if (!pbuf)
        {
            break;
        }

        RtlSecureZeroMemory(pbuf, file_size + 10);

        fread2(pbuf, file_size, 1, pf);

        char main_cert_name[_MAX_PATH + 1];
        RtlSecureZeroMemory(main_cert_name, sizeof(main_cert_name));

        unsigned long long ValidFromTime = 0;
        unsigned long long ValidToTime = 0;
        auto bret = LibSoulExtraction::GetMainCertInfo(
            pbuf, file_size, main_cert_name, _MAX_PATH, &ValidFromTime, &ValidToTime);
        if (bret)
        {
            dprintf("soul: cert=%s, ValidFromTime=%lld, ValidToTime=%lld\n", main_cert_name, ValidFromTime, ValidToTime);
        }

    } while (0);

    if (pbuf)
    {
        ExFreePoolWithTag(pbuf, 'soul');
    }

    if (pf)
    {
        fclose2(pf);
    }

    return STATUS_SUCCESS;
}
