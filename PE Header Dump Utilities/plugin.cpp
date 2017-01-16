#include "plugin.h"
#include "pe_header.h"
#include <time.h>

////////////////////////////////////////////////////////////////////////////////
// constants

// exported command strings
static const char* cmdDumpPEHeader = "pedumpHeader";
static const char* cmdDumpNTHeaders = "pedumpNTHeaders";
static const char* cmdDumpDataDirectories = "pedumpDataDirectories";
static const char* cmdDumpSections = "pedumpSections";

static const char* delimMajor = "===============================================================================\n";
static const char* delimMinor = "-------------------------------------------------------------------------------\n";

static const char* unknownDataString = "(UNKNOWN)";
static const char* invalidDataString = "(INVALID)";

////////////////////////////////////////////////////////////////////////////////
// types

enum 
{
    PLUGIN_MENU_ABOUT,
};

////////////////////////////////////////////////////////////////////////////////
// prototypes

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
void DumpPEHeader(const REMOTE_PE_HEADER_DATA& PEHeader);
void DumpNTHeaders(const REMOTE_PE_HEADER_DATA& PEHeader);
void DumpDataDirectories(const REMOTE_PE_HEADER_DATA& PEHeader);
void DumpSections(const REMOTE_PE_HEADER_DATA& PEHeader);

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
// required x64dbg plugin funcs

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
// plugin exports

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
// added commands

// dump entire PE header
bool cbDumpPEHeader(int argc, char* argv[])
{
    if (argc > 2)
    {
        plog("[" PLUGIN_NAME "]  USAGE:  %s [base address].\n", cmdDumpPEHeader);
        return false;
    }

    REMOTE_PE_HEADER_DATA pe;
    duint ea = argc == 2 ? DbgValFromString(argv[1]) : GetEffectiveBaseAddress();
    if (!FillPEHeaderData(ea, pe))
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

    REMOTE_PE_HEADER_DATA pe;
    duint ea = argc == 2 ? DbgValFromString(argv[1]) : GetEffectiveBaseAddress();
    if (!FillPEHeaderData(ea, pe))
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

    REMOTE_PE_HEADER_DATA pe;
    duint ea = argc == 2 ? DbgValFromString(argv[1]) : GetEffectiveBaseAddress();
    if (!FillPEHeaderData(ea, pe))
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

    REMOTE_PE_HEADER_DATA pe;
    duint ea = argc == 2 ? DbgValFromString(argv[1]) : GetEffectiveBaseAddress();
    if (!FillPEHeaderData(ea, pe))
    {
        plog("[" PLUGIN_NAME "]  %p does not point to a valid PE header.\n", ea);
        return false;
    }
    plog("[" PLUGIN_NAME "]  dumping sections at %p.\n", ea);
    DumpSections(pe);
    return true;
}

////////////////////////////////////////////////////////////////////////////////
// dump

void DumpPEHeader(const REMOTE_PE_HEADER_DATA& PEHeader)
{
    DumpNTHeaders(PEHeader);
    DumpDataDirectories(PEHeader);
    DumpSections(PEHeader);
}

void DumpNTHeaders(const REMOTE_PE_HEADER_DATA& PEHeader)
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
#ifdef _WIN64
    plog("  SizeOfStackReserve:         %16llX\n", PEHeader.optionalHeader->SizeOfStackReserve);
    plog("  SizeOfStackCommit:          %16llX\n", PEHeader.optionalHeader->SizeOfStackCommit);
    plog("  SizeOfHeapReserve:          %16llX\n", PEHeader.optionalHeader->SizeOfHeapReserve);
    plog("  SizeOfHeapCommit:           %16llX\n", PEHeader.optionalHeader->SizeOfHeapCommit);
#else
    plog("  SizeOfStackReserve:         %16X\n", PEHeader.optionalHeader->SizeOfStackReserve);
    plog("  SizeOfStackCommit:          %16X\n", PEHeader.optionalHeader->SizeOfStackCommit);
    plog("  SizeOfHeapReserve:          %16X\n", PEHeader.optionalHeader->SizeOfHeapReserve);
    plog("  SizeOfHeapCommit:           %16X\n", PEHeader.optionalHeader->SizeOfHeapCommit);
#endif
    plog("  LoaderFlags:                %16X\n", PEHeader.optionalHeader->LoaderFlags);
    plog("  NumberOfRvaAndSizes:        %16X\n", PEHeader.optionalHeader->NumberOfRvaAndSizes);
}

void DumpDataDirectories(const REMOTE_PE_HEADER_DATA& PEHeader)
{
    plog(delimMajor);
    plog("DATA DIRECTORIES\n");
    plog(delimMajor);
    for (unsigned int i = 0; i < PEHeader.dataDirectory.size() - 1; i++)
    {
        PIMAGE_DATA_DIRECTORY dataDirectory = PEHeader.dataDirectory[i];
        plog("%s\n", DataDirectoryEntryToString(i));
        if (dataDirectory->VirtualAddress > 0)
#ifdef _WIN64
            plog("  VirtualAddress:             %p  %X\n", RVA_TO_ADDR(PEHeader.baseAddress, dataDirectory->VirtualAddress), dataDirectory->VirtualAddress);
        else
            plog("  VirtualAddress:             %16X\n", 0);
#else
            plog("  VirtualAddress:                     %p  %X\n", RVA_TO_ADDR(PEHeader.baseAddress, dataDirectory->VirtualAddress), dataDirectory->VirtualAddress);
        else
            plog("  VirtualAddress:                     %8X\n", 0);
#endif
        plog("  Size:                               %8X\n", dataDirectory->Size);
    }
}

void DumpSections(const REMOTE_PE_HEADER_DATA& PEHeader)
{
    plog(delimMajor);
    plog("SECTIONS\n");
    plog(delimMajor);
    for (auto sectionHeader : PEHeader.sectionHeaders)
    {
        plog("%.8s\n", sectionHeader->Name);
        plog("  VirtualSize:                        %8X  %X\n", sectionHeader->Misc.VirtualSize, ULONG_PTR(PAGE_ALIGN(sectionHeader->Misc.VirtualSize)) + PAGE_SIZE);
#ifdef _WIN64
        plog("  VirtualAddress:             %p  %X\n", RVA_TO_ADDR(PEHeader.baseAddress, sectionHeader->VirtualAddress), sectionHeader->VirtualAddress);
#else
        plog("  VirtualAddress:                     %p  %X\n", RVA_TO_ADDR(PEHeader.baseAddress, sectionHeader->VirtualAddress), sectionHeader->VirtualAddress);
#endif
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
// utils

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
// data to string

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
// enumerate flags

void PrintImageFileCharacteristics(WORD Characteristics)
{
    if ((Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0)        plog("  RELOCS_STRIPPED");
    if ((Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0)       plog("  EXECUTABLE_IMAGE");
    if ((Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED) != 0)     plog("  LINE_NUMS_STRIPPED");
    if ((Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) != 0)    plog("  LOCAL_SYMS_STRIPPED");
    if ((Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM) != 0)      plog("  AGGRESIVE_WS_TRIM");
    if ((Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0)    plog("  LARGE_ADDRESS_AWARE");
    if ((Characteristics & IMAGE_FILE_BYTES_REVERSED_LO) != 0)      plog("  BYTES_REVERSED_LO");
    if ((Characteristics & IMAGE_FILE_32BIT_MACHINE) != 0)          plog("  32BIT_MACHINE");
    if ((Characteristics & IMAGE_FILE_DEBUG_STRIPPED) != 0)         plog("  DEBUG_STRIPPED");
    if ((Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) != 0) plog("  REMOVABLE_RUN_FROM_SWAP");
    if ((Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) != 0)      plog("  NET_RUN_FROM_SWAP");
    if ((Characteristics & IMAGE_FILE_SYSTEM) != 0)                 plog("  SYSTEM");
    if ((Characteristics & IMAGE_FILE_DLL) != 0)                    plog("  DLL");
    if ((Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) != 0)         plog("  UP_SYSTEM_ONLY");
    if ((Characteristics & IMAGE_FILE_BYTES_REVERSED_HI) != 0)      plog("  BYTES_REVERSED_HI");
    plog("\n");
}

void PrintImageDllCharacteristics(WORD DllCharacteristics)
{
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0)          plog("  DYNAMIC_BASE");
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0)       plog("  FORCE_INTEGRITY");
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0)             plog("  NX_COMPAT");
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0)          plog("  NO_ISOLATION");
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0)                plog("  NO_SEH");
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND) != 0)               plog("  NO_BIND");
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) != 0)            plog("  WDM_DRIVER");
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) != 0) plog("  TERMINAL_SERVER_AWARE");
    plog("\n");
}

void PrintImageSectionCharacteristics(DWORD Characteristics)
{
    if ((Characteristics & IMAGE_SCN_TYPE_NO_PAD) != 0)             plog("  TYPE_NO_PAD");
    if ((Characteristics & IMAGE_SCN_CNT_CODE) != 0)                plog("  CNT_CODE");
    if ((Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0)    plog("  CNT_INITIALIZED_DATA");
    if ((Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)  plog("  CNT_UNINITIALIZED_DATA");
    if ((Characteristics & IMAGE_SCN_LNK_OTHER) != 0)               plog("  LNK_OTHER");
    if ((Characteristics & IMAGE_SCN_LNK_INFO) != 0)                plog("  LNK_INFO");
    if ((Characteristics & IMAGE_SCN_LNK_REMOVE) != 0)              plog("  LNK_REMOVE");
    if ((Characteristics & IMAGE_SCN_LNK_COMDAT) != 0)              plog("  LNK_COMDAT");
    if ((Characteristics & IMAGE_SCN_NO_DEFER_SPEC_EXC) != 0)       plog("  NO_DEFER_SPEC_EXC");
    if ((Characteristics & IMAGE_SCN_GPREL) != 0)                   plog("  GPREL");
    if ((Characteristics & IMAGE_SCN_MEM_FARDATA) != 0)             plog("  MEM_FARDATA");
    if ((Characteristics & IMAGE_SCN_MEM_PURGEABLE) != 0)           plog("  MEM_PURGEABLE");
    if ((Characteristics & IMAGE_SCN_MEM_16BIT) != 0)               plog("  MEM_16BIT");
    if ((Characteristics & IMAGE_SCN_MEM_LOCKED) != 0)              plog("  MEM_LOCKED");
    if ((Characteristics & IMAGE_SCN_MEM_PRELOAD) != 0)             plog("  MEM_PRELOAD");
    if ((Characteristics & IMAGE_SCN_ALIGN_1BYTES) != 0)            plog("  ALIGN_1BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_2BYTES) != 0)            plog("  ALIGN_2BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_4BYTES) != 0)            plog("  ALIGN_4BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_8BYTES) != 0)            plog("  ALIGN_8BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_16BYTES) != 0)           plog("  ALIGN_16BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_32BYTES) != 0)           plog("  ALIGN_32BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_64BYTES) != 0)           plog("  ALIGN_64BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_128BYTES) != 0)          plog("  ALIGN_128BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_256BYTES) != 0)          plog("  ALIGN_256BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_512BYTES) != 0)          plog("  ALIGN_512BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_1024BYTES) != 0)         plog("  ALIGN_1024BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_2048BYTES) != 0)         plog("  ALIGN_2048BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_4096BYTES) != 0)         plog("  ALIGN_4096BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_8192BYTES) != 0)         plog("  ALIGN_8192BYTES");
    if ((Characteristics & IMAGE_SCN_ALIGN_MASK) != 0)              plog("  ALIGN_MASK");
    if ((Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) != 0)         plog("  LNK_NRELOC_OVFL");
    if ((Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)         plog("  MEM_DISCARDABLE");
    if ((Characteristics & IMAGE_SCN_MEM_NOT_CACHED) != 0)          plog("  MEM_NOT_CACHED");
    if ((Characteristics & IMAGE_SCN_MEM_NOT_PAGED) != 0)           plog("  MEM_NOT_PAGED");
    if ((Characteristics & IMAGE_SCN_MEM_SHARED) != 0)              plog("  MEM_SHARED");
    if ((Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)             plog("  MEM_EXECUTE");
    if ((Characteristics & IMAGE_SCN_MEM_READ) != 0)                plog("  MEM_READ");
    if ((Characteristics & IMAGE_SCN_MEM_WRITE) != 0)               plog("  MEM_WRITE");
    plog("\n");
}
