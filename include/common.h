#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <winnt.h>
#include <string.h>

#define INFO(MSG, ...) printf("[+] "               MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[!] "      MSG "\n", ##__VA_ARGS__)

typedef struct _PE_CONTEXT {
    BYTE *base;
    SIZE_T size;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sections;
    DWORD oep;
} PE_CONTEXT;

typedef void (*ORIGINAL_ENTRY_POINT)(void);

typedef struct {
    BYTE* address;
    DWORD size;
} SECTION_DATA;

#endif