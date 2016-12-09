#pragma once

#include <Windows.h>
#include <array>
#include <vector>

////////////////////////////////////////////////////////////////////////////////
//
// constants
//

const DWORD PEHEADER_SIZE = 0x1000;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

typedef struct _PEHeader64 {
    BYTE rawData[PEHEADER_SIZE];
    ULONG_PTR baseAddress = 0;
    PIMAGE_DOS_HEADER dosHeader = nullptr;
    PIMAGE_NT_HEADERS64 ntHeader = nullptr;
    PIMAGE_FILE_HEADER fileHeader = nullptr;
    PIMAGE_OPTIONAL_HEADER64 optionalHeader = nullptr;
    std::array<PIMAGE_DATA_DIRECTORY, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> dataDirectory;
    std::vector<PIMAGE_SECTION_HEADER> sectionHeaders;
} PEHeader64, *PPEHeader64;

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

// round address up by alignment
ULONG_PTR AlignAddress(ULONG_PTR Address, ULONG_PTR Alignment);

BOOL IsValidPEHeader(ULONG_PTR BaseAddress);

BOOL BuildPEHeader64(ULONG_PTR BaseAddress, OUT PEHeader64& PEHeader);
