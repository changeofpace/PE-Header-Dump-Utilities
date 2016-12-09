#include "plugin.h"
#include "pe_header.h"
#include <time.h>

////////////////////////////////////////////////////////////////////////////////
//
// constants
//

static const char* delimMajor = "===============================================================================\n";
static const char* delimMinor = "-------------------------------------------------------------------------------\n";

static const char* unknownDataString = "(UNKNOWN)";
static const char* invalidDataString = "(INVALID)";

// exported command strings
static const char* cmdDumpPEHeader = "pedumpHeader";
static const char* cmdDumpNTHeaders = "pedumpNTHeaders";
static const char* cmdDumpDataDirectories = "pedumpDataDirectories";
static const char* cmdDumpSections = "pedumpSections";

////////////////////////////////////////////////////////////////////////////////
//
// types
//

enum {
    PLUGIN_MENU_ABOUT,
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

// required x64dbg plugin funcs
bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();

// added commands
PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info);

// added commands
bool cbDumpPEHeader(int argc, char* argv[]);
bool cbDumpNTHeaders(int argc, char* argv[]);
bool cbDumpDataDirectories(int argc, char* argv[]);
bool cbDumpSections(int argc, char* argv[]);

// dump
void DumpPEHeader(const PEHeader64& PEHeader);
void DumpNTHeaders(const PEHeader64& PEHeader);
void DumpDataDirectories(const PEHeader64& PEHeader);
void DumpSections(const PEHeader64& PEHeader);

// utils
duint GetSelectedAddress();
duint GetActiveModuleImageBase();
duint GetEffectiveBaseAddress();
bool ConvertEpochToLocalTimeString(DWORD TimeDateStamp, char* LocalTimeString, SIZE_T BufferSize);

// data to string
const char* MachineArchitectureToString(WORD MachineCode);
const char* OptionalHeaderMagicToString(WORD Magic);
const char* OptionalHeaderSubsystemToString(WORD Subsystem);
const char* DataDirectoryEntryToString(WORD DataDirectoryEntry);

// enumerate flags
void PrintImageFileCharacteristics(WORD Characteristics);
void PrintImageDllCharacteristics(WORD DllCharacteristics);
void PrintImageSectionCharacteristics(DWORD Characteristics);

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

////////////////////////////////////////////////////////////////////////////////
//
// required x64dbg plugin funcs
//

bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    typedef bool CommandCallback_t(int, char**);

    auto RegisterRequiredCommand = [](const char* CommandString, CommandCallback_t CommandCallback)
    {
        if (!_plugin_registercommand(pluginHandle, CommandString, CommandCallback, true))
        {
            plog("[" PLUGIN_NAME "]  failed to register command %s.\n", CommandString);
            return false;
        }
        return true;
    };

    if (!RegisterRequiredCommand(cmdDumpPEHeader, cbDumpPEHeader)) return false;
    if (!RegisterRequiredCommand(cmdDumpNTHeaders, cbDumpNTHeaders)) return false;
    if (!RegisterRequiredCommand(cmdDumpDataDirectories, cbDumpDataDirectories)) return false;
    if (!RegisterRequiredCommand(cmdDumpSections, cbDumpSections)) return false;

    return true;
}

bool pluginStop()
{
    _plugin_menuclear(hMenu);
    _plugin_unregistercommand(pluginHandle, cmdDumpPEHeader);
    _plugin_unregistercommand(pluginHandle, cmdDumpNTHeaders);
    _plugin_unregistercommand(pluginHandle, cmdDumpDataDirectories);
    _plugin_unregistercommand(pluginHandle, cmdDumpSections);
    return true;
}

void pluginSetup()
{
    _plugin_menuaddentry(hMenu, PLUGIN_MENU_ABOUT, "&About");
}

////////////////////////////////////////////////////////////////////////////////
//
// plugin exports
//

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch (info->hEntry)
    {
    case PLUGIN_MENU_ABOUT:
        MessageBoxA(hwndDlg,
            "author:  changeofpace.\n\nsource code:  https://github.com/changeofpace/PE-Header-Dump-Utilities.",
            "About",
            0);
        break;
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// added commands
//

// dump entire PE header
bool cbDumpPEHeader(int argc, char* argv[])
{
    if (argc > 2)
    {
        plog("[" PLUGIN_NAME "]  USAGE:  %s [base address].\n", cmdDumpPEHeader);
        return false;
    }

    PEHeader64 pe;
    duint ea = argc == 2 ? DbgValFromString(argv[1]) : GetEffectiveBaseAddress();
    if (!BuildPEHeader64(ea, pe))
    {
        plog("[" PLUGIN_NAME "]  %p does not point to a valid PE header.\n", ea);
        return false;
    }
    plog("[" PLUGIN_NAME "]  dumping PE header at %p.\n", ea);
    DumpPEHeader(pe);
    return true;
}

// dump file and optional headers
bool cbDumpNTHeaders(int argc, char* argv[])
{
    if (argc > 2)
    {
        plog("[" PLUGIN_NAME "]  USAGE:  %s [base address].\n", cmdDumpNTHeaders);
        return false;
    }

    PEHeader64 pe;
    duint ea = argc == 2 ? DbgValFromString(argv[1]) : GetEffectiveBaseAddress();
    if (!BuildPEHeader64(ea, pe))
    {
        plog("[" PLUGIN_NAME "]  %p does not point to a valid PE header.\n", ea);
        return false;
    }
    plog("[" PLUGIN_NAME "]  dumping NT headers at %p.\n", ea);
    DumpNTHeaders(pe);
    return true;
}

bool cbDumpDataDirectories(int argc, char* argv[])
{
    if (argc > 2)
    {
        plog("[" PLUGIN_NAME "]  USAGE:  %s [base address].\n", cmdDumpDataDirectories);
        return false;
    }

    PEHeader64 pe;
    duint ea = argc == 2 ? DbgValFromString(argv[1]) : GetEffectiveBaseAddress();
    if (!BuildPEHeader64(ea, pe))
    {
        plog("[" PLUGIN_NAME "]  %p does not point to a valid PE header.\n", ea);
        return false;
    }
    plog("[" PLUGIN_NAME "]  dumping data directories at %p.\n", ea);
    DumpDataDirectories(pe);
    return true;
}

bool cbDumpSections(int argc, char* argv[])
{
    if (argc > 2)
    {
        plog("[" PLUGIN_NAME "]  USAGE:  %s [base address].\n", cmdDumpSections);
        return false;
    }

    PEHeader64 pe;
    duint ea = argc == 2 ? DbgValFromString(argv[1]) : GetEffectiveBaseAddress();
    if (!BuildPEHeader64(ea, pe))
    {
        plog("[" PLUGIN_NAME "]  %p does not point to a valid PE header.\n", ea);
        return false;
    }
    plog("[" PLUGIN_NAME "]  dumping sections at %p.\n", ea);
    DumpSections(pe);
    return true;
}

////////////////////////////////////////////////////////////////////////////////
//
// dump
//

void DumpPEHeader(const PEHeader64& PEHeader)
{
    DumpNTHeaders(PEHeader);
    DumpDataDirectories(PEHeader);
    DumpSections(PEHeader);
}

void DumpNTHeaders(const PEHeader64& PEHeader)
{
    CHAR localTime[80] = {0};
    ConvertEpochToLocalTimeString(PEHeader.fileHeader->TimeDateStamp, localTime, sizeof(localTime));

    plog(delimMajor);
    plog("FILE HEADER\n");
    plog(delimMajor);
    plog("  Machine:                    %16X  %s\n", PEHeader.fileHeader->Machine, MachineArchitectureToString(PEHeader.fileHeader->Machine));
    plog("  NumberOfSections:           %16X\n", PEHeader.fileHeader->NumberOfSections);
    plog("  TimeDateStamp:              %16X  %s", PEHeader.fileHeader->TimeDateStamp, localTime);
    plog("  PointerToSymbolTable:       %16p\n", PEHeader.fileHeader->PointerToSymbolTable);
    plog("  NumberOfSymbols:            %16X\n", PEHeader.fileHeader->NumberOfSymbols);
    plog("  SizeOfOptionalHeader:       %16X\n", PEHeader.fileHeader->SizeOfOptionalHeader);
    plog("  Characteristics:            %16X", PEHeader.fileHeader->Characteristics);
    PrintImageFileCharacteristics(PEHeader.fileHeader->Characteristics);

    plog(delimMajor);
    plog("OPTIONAL HEADER\n");
    plog(delimMajor);
    plog("  Magic:                      %16X  %s\n", PEHeader.optionalHeader->Magic, OptionalHeaderMagicToString(PEHeader.optionalHeader->Magic));
    plog("  MajorLinkerVersion:         %16X\n", PEHeader.optionalHeader->MajorLinkerVersion);
    plog("  MinorLinkerVersion:         %16X\n", PEHeader.optionalHeader->MinorLinkerVersion);
    plog("  SizeOfCode:                 %16X\n", PEHeader.optionalHeader->SizeOfCode);
    plog("  SizeOfInitializedData:      %16X\n", PEHeader.optionalHeader->SizeOfInitializedData);
    plog("  SizeOfUninitializedData:    %16X\n", PEHeader.optionalHeader->SizeOfUninitializedData);
    plog("  AddressOfEntryPoint:        %16X\n", PEHeader.optionalHeader->AddressOfEntryPoint);
    plog("  BaseOfCode:                 %16X\n", PEHeader.optionalHeader->BaseOfCode);
    plog("  ImageBase:                  %16p\n", PEHeader.optionalHeader->ImageBase);
    plog("  SectionAlignment:           %16X\n", PEHeader.optionalHeader->SectionAlignment);
    plog("  FileAlignment:              %16X\n", PEHeader.optionalHeader->FileAlignment);
    plog("  MajorOperatingSystemVersion:%16X\n", PEHeader.optionalHeader->MajorOperatingSystemVersion);
    plog("  MinorOperatingSystemVersion:%16X\n", PEHeader.optionalHeader->MinorOperatingSystemVersion);
    plog("  MajorImageVersion:          %16X\n", PEHeader.optionalHeader->MajorImageVersion);
    plog("  MinorImageVersion:          %16X\n", PEHeader.optionalHeader->MinorImageVersion);
    plog("  MajorSubsystemVersion:      %16X\n", PEHeader.optionalHeader->MajorSubsystemVersion);
    plog("  MinorSubsystemVersion:      %16X\n", PEHeader.optionalHeader->MinorSubsystemVersion);
    plog("  Win32VersionValue:          %16X\n", PEHeader.optionalHeader->Win32VersionValue);
    plog("  SizeOfImage:                %16X\n", PEHeader.optionalHeader->SizeOfImage);
    plog("  SizeOfHeaders:              %16X\n", PEHeader.optionalHeader->SizeOfHeaders);
    plog("  CheckSum:                   %16X\n", PEHeader.optionalHeader->CheckSum);
    plog("  Subsystem:                  %16X  %s\n", PEHeader.optionalHeader->Subsystem, OptionalHeaderSubsystemToString(PEHeader.optionalHeader->Subsystem));
    plog("  DllCharacteristics:         %16X", PEHeader.optionalHeader->DllCharacteristics);
    PrintImageDllCharacteristics(PEHeader.optionalHeader->DllCharacteristics);
    plog("  SizeOfStackReserve:         %16llX\n", PEHeader.optionalHeader->SizeOfStackReserve);
    plog("  SizeOfStackCommit:          %16llX\n", PEHeader.optionalHeader->SizeOfStackCommit);
    plog("  SizeOfHeapReserve:          %16llX\n", PEHeader.optionalHeader->SizeOfHeapReserve);
    plog("  SizeOfHeapCommit:           %16llX\n", PEHeader.optionalHeader->SizeOfHeapCommit);
    plog("  LoaderFlags:                %16X\n", PEHeader.optionalHeader->LoaderFlags);
    plog("  NumberOfRvaAndSizes:        %16X\n", PEHeader.optionalHeader->NumberOfRvaAndSizes);
}

void DumpDataDirectories(const PEHeader64& PEHeader)
{
    plog(delimMajor);
    plog("DATA DIRECTORIES\n");
    plog(delimMajor);
    for (int i = 0; i < PEHeader.dataDirectory.size() - 1; i++)
    {
        PIMAGE_DATA_DIRECTORY dataDirectory = PEHeader.dataDirectory[i];
        plog("%s\n", DataDirectoryEntryToString(i));
        plog("  VirtualAddress:                     %8X", dataDirectory->VirtualAddress);
        if (dataDirectory->VirtualAddress > 0)
            plog("  %p", RVA_TO_ADDR(PEHeader.baseAddress, dataDirectory->VirtualAddress));
        plog("\n");
        plog("  Size:                               %8X\n", dataDirectory->Size);
    }
}

void DumpSections(const PEHeader64& PEHeader)
{
    plog(delimMajor);
    plog("SECTIONS\n");
    plog(delimMajor);
    for (auto sectionHeader : PEHeader.sectionHeaders)
    {
        plog("%.8s\n", sectionHeader->Name);
        plog("  VirtualSize:                        %8X  %X\n", sectionHeader->Misc.VirtualSize, AlignAddress(sectionHeader->Misc.VirtualSize, PEHeader.optionalHeader->SectionAlignment));
        plog("  VirtualAddress:                     %8X  %p\n", sectionHeader->VirtualAddress, RVA_TO_ADDR(PEHeader.baseAddress, sectionHeader->VirtualAddress));
        plog("  SizeOfRawData:                      %8X\n", sectionHeader->SizeOfRawData);
        plog("  PointerToRawData:                   %8X\n", sectionHeader->PointerToRawData);
        plog("  PointerToRelocations:               %8X\n", sectionHeader->PointerToRelocations);
        plog("  PointerToLinenumbers:               %8X\n", sectionHeader->PointerToLinenumbers);
        plog("  NumberOfRelocations:                %8X\n", sectionHeader->NumberOfRelocations);
        plog("  NumberOfLinenumbers:                %8X\n", sectionHeader->NumberOfLinenumbers);
        plog("  Characteristics:                    %8X", sectionHeader->Characteristics);
        PrintImageSectionCharacteristics(sectionHeader->Characteristics);
        plog(delimMinor);
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// utils
//

duint GetSelectedAddress()
{
    SELECTIONDATA selection;
    if (GuiSelectionGet(GUI_DISASSEMBLY, &selection))
        return selection.start;
    return 0;
}

// if ea (highlighted address) is contained in a valid module, return the module's base address.
duint GetActiveModuleImageBase()
{
    return DbgValFromString(":0");
}

// if ea (highlighted address) is contained in a valid module, return the module's base address.
// else return the base address for the memory region which contains ea.
duint GetEffectiveBaseAddress()
{
    char moduleName[MAX_MODULE_SIZE] = {0};
    const duint ea = GetSelectedAddress();
    if (DbgGetModuleAt(ea, moduleName))
        return GetActiveModuleImageBase();
    return DbgMemFindBaseAddr(ea, nullptr);
}

bool ConvertEpochToLocalTimeString(DWORD TimeDateStamp, char* LocalTimeString, SIZE_T BufferSize)
{
    struct tm newTime;
    __time64_t timeDateStamp = (__time64_t)TimeDateStamp;
    errno_t err = _localtime64_s(&newTime, &timeDateStamp);
    if (err)
    {
        _snprintf_s(LocalTimeString, BufferSize, _TRUNCATE, invalidDataString);
        return false;
    }
    asctime_s(LocalTimeString, BufferSize, &newTime);
    return true;
}

////////////////////////////////////////////////////////////////////////////////
//
// data to string
//

const char* MachineArchitectureToString(WORD MachineCode)
{
    switch (MachineCode)
    {
    case 0x014C: return "I386";
    case 0x0200: return "IA64";
    case 0x8664: return "AMD64";
    }
    return unknownDataString;
}

const char* OptionalHeaderMagicToString(WORD Magic)
{
    switch (Magic)
    {
    case 0x10B: return "HDR32";
    case 0x20B: return "HDR64";
    case 0x107: return "ROM";
    }
    return unknownDataString;
}

const char* OptionalHeaderSubsystemToString(WORD Subsystem)
{
    switch (Subsystem)
    {
    case 0:  return "UNKNOWN";
    case 1:  return "NATIVE";
    case 2:  return "WINDOWS_GUI";
    case 3:  return "WINDOWS_CUI";
    case 5:  return "OS2_CUI";
    case 7:  return "POSIX_CUI";
    case 9:  return "WINDOWS_CE_GUI";
    case 10: return "EFI_APPLICATION";
    case 11: return "EFI_BOOT_SERVICE_DRIVER";
    case 12: return "EFI_RUNTIME_DRIVER";
    case 13: return "EFI_ROM";
    case 14: return "XBOX";
    case 16: return "WINDOWS_BOOT_APPLICATION";
    }
    return unknownDataString;
}

const char* DataDirectoryEntryToString(WORD DataDirectoryEntry)
{
    switch (DataDirectoryEntry)
    {
    case  0: return "EXPORT";
    case  1: return "IMPORT";
    case  2: return "RESOURCE";
    case  3: return "EXCEPTION";
    case  4: return "SECURITY";
    case  5: return "BASERELOC";
    case  6: return "DEBUG";
    //case  7: return "COPYRIGHT";
    case  7: return "ARCHITECTURE";
    case  8: return "GLOBALPTR";
    case  9: return "TLS";
    case 10: return "LOAD_CONFIG";
    case 11: return "BOUND_IMPORT";
    case 12: return "IAT";
    case 13: return "DELAY_IMPORT";
    case 14: return "COM_DESCRIPTOR";
    }
    return unknownDataString;
}

////////////////////////////////////////////////////////////////////////////////
//
// enumerate flags
//

void PrintImageFileCharacteristics(WORD Characteristics)
{
    if ((Characteristics & 0x0001) != 0) plog("  RELOCS_STRIPPED");
    if ((Characteristics & 0x0002) != 0) plog("  EXECUTABLE_IMAGE");
    if ((Characteristics & 0x0004) != 0) plog("  LINE_NUMS_STRIPPED");
    if ((Characteristics & 0x0008) != 0) plog("  LOCAL_SYMS_STRIPPED");
    if ((Characteristics & 0x0010) != 0) plog("  AGGRESIVE_WS_TRIM");
    if ((Characteristics & 0x0020) != 0) plog("  LARGE_ADDRESS_AWARE");
    if ((Characteristics & 0x0080) != 0) plog("  BYTES_REVERSED_LO");
    if ((Characteristics & 0x0100) != 0) plog("  32BIT_MACHINE");
    if ((Characteristics & 0x0200) != 0) plog("  DEBUG_STRIPPED");
    if ((Characteristics & 0x0400) != 0) plog("  REMOVABLE_RUN_FROM_SWAP");
    if ((Characteristics & 0x0800) != 0) plog("  NET_RUN_FROM_SWAP");
    if ((Characteristics & 0x1000) != 0) plog("  SYSTEM");
    if ((Characteristics & 0x2000) != 0) plog("  DLL");
    if ((Characteristics & 0x4000) != 0) plog("  UP_SYSTEM_ONLY");
    if ((Characteristics & 0x8000) != 0) plog("  BYTES_REVERSED_HI");
    plog("\n");
}

void PrintImageDllCharacteristics(WORD DllCharacteristics)
{
    if ((DllCharacteristics & 0x0040) != 0) plog("  DYNAMIC_BASE");
    if ((DllCharacteristics & 0x0080) != 0) plog("  FORCE_INTEGRITY");
    if ((DllCharacteristics & 0x0100) != 0) plog("  NX_COMPAT");
    if ((DllCharacteristics & 0x0200) != 0) plog("  NO_ISOLATION");
    if ((DllCharacteristics & 0x0400) != 0) plog("  NO_SEH");
    if ((DllCharacteristics & 0x0800) != 0) plog("  NO_BIND");
    if ((DllCharacteristics & 0x2000) != 0) plog("  WDM_DRIVER");
    if ((DllCharacteristics & 0x8000) != 0) plog("  TERMINAL_SERVER_AWARE");
    plog("\n");
}

void PrintImageSectionCharacteristics(DWORD Characteristics)
{
    if ((Characteristics & 0x00000008) != 0) plog("  TYPE_NO_PAD");
    if ((Characteristics & 0x00000020) != 0) plog("  CNT_CODE");
    if ((Characteristics & 0x00000040) != 0) plog("  CNT_INITIALIZED_DATA");
    if ((Characteristics & 0x00000080) != 0) plog("  CNT_UNINITIALIZED_DATA");
    if ((Characteristics & 0x00000100) != 0) plog("  LNK_OTHER");
    if ((Characteristics & 0x00000200) != 0) plog("  LNK_INFO");
    if ((Characteristics & 0x00000800) != 0) plog("  LNK_REMOVE");
    if ((Characteristics & 0x00001000) != 0) plog("  LNK_COMDAT");
    if ((Characteristics & 0x00004000) != 0) plog("  NO_DEFER_SPEC_EXC");
    if ((Characteristics & 0x00008000) != 0) plog("  GPREL");
    if ((Characteristics & 0x00008000) != 0) plog("  MEM_FARDATA");
    if ((Characteristics & 0x00020000) != 0) plog("  MEM_PURGEABLE");
    if ((Characteristics & 0x00020000) != 0) plog("  MEM_16BIT");
    if ((Characteristics & 0x00040000) != 0) plog("  MEM_LOCKED");
    if ((Characteristics & 0x00080000) != 0) plog("  MEM_PRELOAD");
    if ((Characteristics & 0x00100000) != 0) plog("  ALIGN_1BYTES");
    if ((Characteristics & 0x00200000) != 0) plog("  ALIGN_2BYTES");
    if ((Characteristics & 0x00300000) != 0) plog("  ALIGN_4BYTES");
    if ((Characteristics & 0x00400000) != 0) plog("  ALIGN_8BYTES");
    if ((Characteristics & 0x00500000) != 0) plog("  ALIGN_16BYTES");
    if ((Characteristics & 0x00600000) != 0) plog("  ALIGN_32BYTES");
    if ((Characteristics & 0x00700000) != 0) plog("  ALIGN_64BYTES");
    if ((Characteristics & 0x00800000) != 0) plog("  ALIGN_128BYTES");
    if ((Characteristics & 0x00900000) != 0) plog("  ALIGN_256BYTES");
    if ((Characteristics & 0x00A00000) != 0) plog("  ALIGN_512BYTES");
    if ((Characteristics & 0x00B00000) != 0) plog("  ALIGN_1024BYTES");
    if ((Characteristics & 0x00C00000) != 0) plog("  ALIGN_2048BYTES");
    if ((Characteristics & 0x00D00000) != 0) plog("  ALIGN_4096BYTES");
    if ((Characteristics & 0x00E00000) != 0) plog("  ALIGN_8192BYTES");
    if ((Characteristics & 0x00F00000) != 0) plog("  ALIGN_MASK");
    if ((Characteristics & 0x01000000) != 0) plog("  LNK_NRELOC_OVFL");
    if ((Characteristics & 0x02000000) != 0) plog("  MEM_DISCARDABLE");
    if ((Characteristics & 0x04000000) != 0) plog("  MEM_NOT_CACHED");
    if ((Characteristics & 0x08000000) != 0) plog("  MEM_NOT_PAGED");
    if ((Characteristics & 0x10000000) != 0) plog("  MEM_SHARED");
    if ((Characteristics & 0x20000000) != 0) plog("  MEM_EXECUTE");
    if ((Characteristics & 0x40000000) != 0) plog("  MEM_READ");
    if ((Characteristics & 0x80000000) != 0) plog("  MEM_WRITE");
    plog("\n");
}
