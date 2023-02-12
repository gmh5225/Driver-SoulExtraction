#include "Lib.SoulExtraction.rewrite.h"
#include <stdarg.h>

#define SOUL_POOL_TAG 'SOUL'

typedef int(__cdecl *pfn_vsnprintf)(
    char *const _Buffer,
    size_t const _BufferCount,
    char const *const _Format,
    va_list _ArgList);

pfn_vsnprintf g_vsnprintf2 = NULL;

void *
kmalloc(size_t size, ULONG flags)
{
    void *p = ExAllocatePoolWithTag(NonPagedPool, size, SOUL_POOL_TAG);
    if (p)
    {
        RtlSecureZeroMemory(p, size);
    }

    return p;
}

void *
kzalloc(size_t size, ULONG flags)
{
    return kmalloc(size, flags);
}

void *
kmemdup(const void *src, size_t len, ULONG gfp)
{
    void *p = ExAllocatePoolWithTag(NonPagedPool, len + 1, SOUL_POOL_TAG);
    if (p)
    {
        RtlSecureZeroMemory(p, len + 1);
        if (src)
        {
            memcpy(p, src, len);
        }
    }

    return p;
}

void
kfree(const void *block)
{
    if (!block)
    {
        return;
    }

    ExFreePoolWithTag((void *)block, SOUL_POOL_TAG);
}

void
kzfree(const void *p)
{
    kfree(p);
}

int __cdecl kmysnprintf(char *s, size_t const sz, char const *const f, ...)
{
    int n = 0;

    va_list arg_list;

    if (g_vsnprintf2 == NULL)
    {
        UNICODE_STRING us;

        wchar_t wfunc[] = {//_vsnprintf
                           L'_',
                           L'v',
                           L's',
                           L'n',
                           L'p',
                           L'r',
                           L'i',
                           L'n',
                           L't',
                           L'f',
                           0,
                           0};

        RtlInitUnicodeString(&us, wfunc);
        g_vsnprintf2 = (pfn_vsnprintf)(MmGetSystemRoutineAddress(&us));
    }

    va_start(arg_list, f);

    if (g_vsnprintf2)
    {
        n = g_vsnprintf2(s, sz, f, arg_list);
    }

    va_end(arg_list);
    return n;
}

long long
mktime64(
    const unsigned int year0,
    const unsigned int mon0,
    const unsigned int day,
    const unsigned int hour,
    const unsigned int min,
    const unsigned int sec)
{
    unsigned int mon = mon0, year = year0;

    /* 1..12 -> 11,12,1..10 */
    if (0 >= (int)(mon -= 2))
    {
        mon += 12; /* Puts Feb last since it has leap day */
        year -= 1;
    }

    return ((((long long)(year / 4 - year / 100 + year / 400 + 367 * mon / 12 + day) + year * 365 - 719499) * 24 +
             hour /* now have hours - midnight tomorrow handled here */
             ) * 60 +
            min /* now have minutes */
            ) * 60 +
           sec; /* finally seconds */
}

// unsigned char y = (X) - '0'; if (y > 9) goto invalid_time;
unsigned char
dec2bin(unsigned char X)
{
    char y = (X) - '0';

    if (y > 9)
    {
        return -1;
    }

    return y;
}

// DD2bin(P) ({ unsigned x = dec2bin(P[0]) * 10 + dec2bin(P[1]); P += 2; })
unsigned
DD2bin(unsigned char **P)
{
    unsigned char a0 = dec2bin((*P)[0]);
    unsigned char a1 = dec2bin((*P)[1]);
    unsigned x = -1;

    if (a0 == -1 || a1 == -1)
    {
        goto _exit;
    }

    x = (unsigned)(a0 * 10 + a1);

    (*P) += 2;

_exit:
    return x;
}

int
__test_and_set_bit(unsigned long nr, volatile void *addr)
{
    unsigned long mask = 1 << (nr & 0x1f);
    int *m = ((int *)addr) + (nr >> 5);
    int old = *m;

    *m = old | mask;
    return (old & mask) != 0;
}

int
test_bit(int nr, const volatile void *addr)
{
    return (1UL & (((const int *)addr)[nr >> 5] >> (nr & 31))) != 0UL;
}