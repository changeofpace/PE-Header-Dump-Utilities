#include "pe_header.h"
#include "pluginsdk/bridgemain.h"

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

ULONG_PTR AlignAddress(ULONG_PTR Address, ULONG_PTR Alignment)
{
    return Address + Alignment - (Address % Alignment);
}

BOOL IsValidPEHeader(ULONG_PTR BaseAddress)
{
    if (!BaseAddress) return FALSE;
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(BaseAddress);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS64 ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(BaseAddress + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    PIMAGE_OPTIONAL_HEADER64 optionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&ntHeader->OptionalHeader);
    if (optionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return FALSE;
    return TRUE;
}

BOOL BuildPEHeader64(ULONG_PTR BaseAddress, OUT PEHeader64& PEHeader)
{
    ZeroMemory(PEHeader.rawData, PEHEADER_SIZE);
    if (!DbgMemRead(BaseAddress, PEHeader.rawData, PEHEADER_SIZE))
        return FALSE;
    if (!IsValidPEHeader(reinterpret_cast<ULONG_PTR>(&PEHeader.rawData)))
        return FALSE;
    PEHeader.baseAddress = BaseAddress;
    PEHeader.dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(&PEHeader.rawData);
    PEHeader.ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<ULONG_PTR>(PEHeader.dosHeader)+ PEHeader.dosHeader->e_lfanew);
    PEHeader.fileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(&PEHeader.ntHeader->FileHeader);
    PEHeader.optionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&PEHeader.ntHeader->OptionalHeader);
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
        PEHeader.dataDirectory[i] = &PEHeader.ntHeader->OptionalHeader.DataDirectory[i];
    ULONG_PTR firstSectionHeader = reinterpret_cast<ULONG_PTR>(IMAGE_FIRST_SECTION(PEHeader.ntHeader));
    for (int i = 0; i < PEHeader.fileHeader->NumberOfSections; i++)
        PEHeader.sectionHeaders.push_back(reinterpret_cast<PIMAGE_SECTION_HEADER>(i * sizeof(IMAGE_SECTION_HEADER) + firstSectionHeader));
    return TRUE;
}