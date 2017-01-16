#include "pe_header.h"
#include "pluginsdk/bridgemain.h"

BOOL FillPEHeaderData(ULONG_PTR BaseAddress, OUT REMOTE_PE_HEADER_DATA& PEHeader)
{
    ZeroMemory(PEHeader.rawData, PE_HEADER_SIZE);
    if (!DbgMemRead(BaseAddress, PEHeader.rawData, PE_HEADER_SIZE))
        return FALSE;
    if (!IsValidPEHeader(ULONG_PTR(&PEHeader.rawData)))
        return FALSE;
    PEHeader.baseAddress = BaseAddress;
    PEHeader.dosHeader = PIMAGE_DOS_HEADER(&PEHeader.rawData);
    PEHeader.ntHeader = PIMAGE_NT_HEADERS(ULONG_PTR(PEHeader.dosHeader) + PEHeader.dosHeader->e_lfanew);
    PEHeader.fileHeader = PIMAGE_FILE_HEADER(&PEHeader.ntHeader->FileHeader);
    PEHeader.optionalHeader = PIMAGE_OPTIONAL_HEADER(&PEHeader.ntHeader->OptionalHeader);
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
        PEHeader.dataDirectory[i] = &PEHeader.ntHeader->OptionalHeader.DataDirectory[i];
    const ULONG_PTR firstSectionHeader = ULONG_PTR(IMAGE_FIRST_SECTION(PEHeader.ntHeader));
    for (int i = 0; i < PEHeader.fileHeader->NumberOfSections; i++)
        PEHeader.sectionHeaders.push_back(PIMAGE_SECTION_HEADER(i * sizeof(IMAGE_SECTION_HEADER) + firstSectionHeader));
    return TRUE;
}

BOOL IsValidPEHeader(ULONG_PTR BaseAddress)
{
    if (!BaseAddress) return FALSE;
    PIMAGE_DOS_HEADER dosHeader = PIMAGE_DOS_HEADER(BaseAddress);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS ntHeader = PIMAGE_NT_HEADERS(BaseAddress + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    PIMAGE_OPTIONAL_HEADER optionalHeader = PIMAGE_OPTIONAL_HEADER(&ntHeader->OptionalHeader);
    if (optionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return FALSE;
    return TRUE;
}