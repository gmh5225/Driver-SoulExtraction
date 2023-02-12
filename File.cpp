#include "File.h"
#include <intrin.h>

typedef struct _iobuf
{
    void *_Placeholder;
} FILE;

#define SEEK_CUR 1
#define SEEK_END 2
#define SEEK_SET 0
#define EIO 5

#define FILE_POOL_DEFAULT_TAG 'file'

typedef struct _FILE_CONTROL_BLOCK
{
    HANDLE hFile;
    NTSTATUS err;
} FILE_CONTROL_BLOCK;

FILE_CONTROL_BLOCK *
fget_core(FILE *f)
{
    return (FILE_CONTROL_BLOCK *)f->_Placeholder;
}

void
fset_core(FILE *f, FILE_CONTROL_BLOCK *fcb)
{
    f->_Placeholder = fcb;
}

void *__cdecl fopen2(char const *_FileName, char const *_Mode)
{
    NTSTATUS st;
    HANDLE hFile;
    char *path = NULL;
    IO_STATUS_BLOCK isb;
    OBJECT_ATTRIBUTES oa;
    ANSI_STRING FileNameA;
    UNICODE_STRING FileNameW;

    ULONG AccessMask = 0;
    ULONG ShareAccess = 0;
    ULONG CreateOptions = 0;
    ULONG CreateDisposition = 0;
    {
        char c_r[] = {'r', 0};
        char c_rb[] = {'r', 'b', 0};
        char c_w[] = {'w', 0};
        char c_wb[] = {'w', 'b', 0};
        char c_rw[] = {'r', 'w', 0};
        char c_rwb[] = {'r', 'w', 'b', 0};
        char c_ajia[] = {'a', '+', 0};
        char c_ajiab[] = {'a', '+', 'b', 0};
        char c_abjia[] = {'a', 'b', '+', 0};

        const char *mode = _Mode;

        if (!strcmp(mode, c_r) || !strcmp(mode, c_rb))
        {
            AccessMask = FILE_READ_DATA | FILE_READ_ATTRIBUTES;
            CreateDisposition = FILE_OPEN;
        }
        else if (!strcmp(mode, c_w) || !strcmp(mode, c_wb))
        {
            AccessMask = FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES;
            CreateDisposition = FILE_SUPERSEDE;
        }
        else if (!strcmp(mode, c_rw) || !strcmp(mode, c_rwb))
        {
            AccessMask = FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES;
            CreateDisposition = FILE_OPEN_IF;
        }
        else if (!strcmp(mode, c_ajia) || !strcmp(mode, c_ajiab) || !strcmp(mode, c_abjia))
        {
            AccessMask =
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_APPEND_DATA;
            CreateDisposition = FILE_OPEN_IF;
        }
        else
        {
            return NULL;
        }

        AccessMask |= SYNCHRONIZE;
        ShareAccess = FILE_SHARE_READ;
        CreateOptions = FILE_SYNCHRONOUS_IO_NONALERT;
    }

    path = (char *)ExAllocatePoolWithTag(PagedPool, 512, FILE_POOL_DEFAULT_TAG);
    if (!path)
        return NULL;
    RtlSecureZeroMemory(path, 512);

    RtlCopyMemory(path, _FileName, min(512, strlen(_FileName)));

    RtlInitAnsiString(&FileNameA, path);
    if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&FileNameW, &FileNameA, TRUE)))
    {
        ExFreePoolWithTag(path, FILE_POOL_DEFAULT_TAG);
        return NULL;
    }

    InitializeObjectAttributes(&oa, &FileNameW, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = ZwCreateFile(
        &hFile,
        AccessMask,
        &oa,
        &isb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        NULL,
        0);
    ExFreePoolWithTag(path, FILE_POOL_DEFAULT_TAG);
    path = NULL;
    RtlFreeUnicodeString(&FileNameW);

    if (!NT_SUCCESS(st))
        return NULL;

    FILE *f = (FILE *)ExAllocatePoolWithTag(PagedPool, sizeof(FILE), FILE_POOL_DEFAULT_TAG);
    FILE_CONTROL_BLOCK *fcb =
        (FILE_CONTROL_BLOCK *)ExAllocatePoolWithTag(PagedPool, sizeof(FILE_CONTROL_BLOCK), FILE_POOL_DEFAULT_TAG);
    fcb->err = 0;
    fcb->hFile = hFile;
    fset_core(f, fcb);

    return (void *)f;
}

__int64 __cdecl _ftelli64_2(FILE *_Stream)
{
    IO_STATUS_BLOCK isb;
    FILE_POSITION_INFORMATION fpi;
    FILE_CONTROL_BLOCK *fcb = fget_core(_Stream);

    fcb->err = ZwQueryInformationFile(fcb->hFile, &isb, &fpi, sizeof(fpi), FilePositionInformation);
    if (NT_SUCCESS(fcb->err))
    {
        return fpi.CurrentByteOffset.QuadPart;
    }
    else
    {
        return -1;
    }
}

int __cdecl _fseeki64_2(FILE *_Stream, __int64 _Offset, int _Origin)
{
    IO_STATUS_BLOCK isb;
    FILE_POSITION_INFORMATION fpi;
    FILE_CONTROL_BLOCK *fcb = fget_core(_Stream);

    switch (_Origin)
    {
    case SEEK_CUR: {
        long cur_pos = ftell2(_Stream);

        if (cur_pos >= 0)
        {
            fpi.CurrentByteOffset.QuadPart = cur_pos + _Offset;
            fcb->err = ZwSetInformationFile(fcb->hFile, &isb, &fpi, sizeof(fpi), FilePositionInformation);
            if (NT_SUCCESS(fcb->err))
            {
                return 0;
            }
        }
    }
    break;
    case SEEK_END: {
        FILE_STANDARD_INFORMATION fsi;

        fcb->err = ZwQueryInformationFile(fcb->hFile, &isb, &fsi, sizeof(fsi), FileStandardInformation);
        if (NT_SUCCESS(fcb->err))
        {
            fpi.CurrentByteOffset.QuadPart = fsi.EndOfFile.QuadPart + _Offset;

            fcb->err = ZwSetInformationFile(fcb->hFile, &isb, &fpi, sizeof(fpi), FilePositionInformation);
            if (NT_SUCCESS(fcb->err))
            {
                return 0;
            }
        }
    }
    break;
    case SEEK_SET: {
        fpi.CurrentByteOffset.QuadPart = _Offset;
        fcb->err = ZwSetInformationFile(fcb->hFile, &isb, &fpi, sizeof(fpi), FilePositionInformation);
        if (NT_SUCCESS(fcb->err))
        {
            return 0;
        }
    }
    break;
    default:
        break;
    }

    return EIO;
}

int __cdecl fseek2(void *_Stream, long _Offset, int _Origin)
{
    return _fseeki64_2((FILE *)_Stream, _Offset, _Origin);
}

long __cdecl ftell2(void *f)
{
    return (long)_ftelli64_2((FILE *)f);
}

int __cdecl fclose2(void *f)
{
    FILE_CONTROL_BLOCK *fcb = fget_core((FILE *)f);

    ZwClose(fcb->hFile);
    ExFreePoolWithTag(fcb, FILE_POOL_DEFAULT_TAG);
    ExFreePoolWithTag(f, FILE_POOL_DEFAULT_TAG);

    return 0;
}

size_t __cdecl fread2(void *Buffer, size_t ElementSize, size_t ElementCount, void *f)
{
    IO_STATUS_BLOCK isb;
    FILE_CONTROL_BLOCK *fcb = fget_core((FILE *)f);
    size_t rd_size = ElementSize * ElementCount;

    RtlSecureZeroMemory(&isb, sizeof(isb));
    fcb->err = ZwReadFile(fcb->hFile, NULL, NULL, NULL, &isb, Buffer, (ULONG)rd_size, NULL, NULL);
    return isb.Information;
}

size_t __cdecl fwrite2(void const *Buffer, size_t ElementSize, size_t ElementCount, void *f)
{
    IO_STATUS_BLOCK isb;
    FILE_CONTROL_BLOCK *fcb = fget_core((FILE *)f);
    size_t wt_size = ElementSize * ElementCount;

    RtlSecureZeroMemory(&isb, sizeof(isb));
    fcb->err = ZwWriteFile(fcb->hFile, NULL, NULL, NULL, &isb, (PVOID)Buffer, (ULONG)wt_size, NULL, NULL);
    return isb.Information;
}