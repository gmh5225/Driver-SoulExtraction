#pragma once

#include <fltKernel.h>

void *
kzalloc(size_t size, ULONG flags);
void *
kmalloc(size_t size, ULONG flags);

void *
kmemdup(const void *src, size_t len, ULONG gfp);

void
kfree(const void *block);
void
kzfree(const void *p);

int __cdecl kmysnprintf(char *s, size_t const sz, char const *const f, ...);

long long
mktime64(
    const unsigned int year0,
    const unsigned int mon0,
    const unsigned int day,
    const unsigned int hour,
    const unsigned int min,
    const unsigned int sec);

// unsigned char y = (X) - '0'; if (y > 9) goto invalid_time;
unsigned char
dec2bin(unsigned char X);

// DD2bin(P) ({ unsigned x = dec2bin(P[0]) * 10 + dec2bin(P[1]); P += 2; })
unsigned
DD2bin(unsigned char **P);

int
__test_and_set_bit(unsigned long nr, volatile void *addr);

int
test_bit(int nr, const volatile void *addr);
