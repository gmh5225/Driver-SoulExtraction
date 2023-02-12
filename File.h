#pragma once
#include <fltKernel.h>

void *__cdecl fopen2(char const *_FileName, char const *_Mode);

int __cdecl fseek2(void *_Stream, long _Offset, int _Origin);

long __cdecl ftell2(void *f);

int __cdecl fclose2(void *f);

size_t __cdecl fread2(void *Buffer, size_t ElementSize, size_t ElementCount, void *f);

size_t __cdecl fwrite2(void const *Buffer, size_t ElementSize, size_t ElementCount, void *f);
