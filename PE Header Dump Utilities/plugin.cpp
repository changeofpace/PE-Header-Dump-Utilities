#include "plugin.h"
#include "pe_header.h"
#include "pe_data_to_string.h"
#include "utils.h"

#define PLOG(Format, ...)                   _plugin_logprintf(Format, __VA_ARGS__)
#define RVA_TO_ADDR_OR_ZERO(Mapping,Rva)    (Rva > 0) ? (RVA_TO_ADDR(Mapping,Rva)) : (0)

namespace {
////////////////////////////////////////////////////////////////////////////////
// constants

// exported command strings
const char* cmdDumpPEHeader =        "pedumpPEHeader";
const char* cmdDumpDOSHeader =       "pedumpDOSHeader";
const char* cmdDumpNTHeaders =       "pedumpNTHeaders";
const char* cmdDumpFileHeader =      "pedumpFileHeader";
const char* cmdDumpOptionalHeader =  "pedumpOptionalHeader";
const char* cmdDumpDataDirectories = "pedumpDataDirectories";
const char* cmdDumpSections =        "pedumpSections";

// separators
const char* delimMajor = "===============================================================================\n";
const char* delimMinor = "-------------------------------------------------------------------------------\n";

////////////////////////////////////////////////////////////////////////////////
// types / enums

typedef void(DUMP_PROC)(const REMOTE_PE_HEADER_DATA&);

enum { PLUGIN_MENU_ABOUT };

////////////////////////////////////////////////////////////////////////////////
// internal prototypes

// added command callbacks
bool cbDumpPEHeader(int argc, char* argv[]);
bool cbDumpDOSHeader(int argc, char* argv[]);
bool cbDumpNTHeaders(int argc, char* argv[]);
bool cbDumpFileHeader(int argc, char* argv[]);
bool cbDumpOptionalHeader(int argc, char* argv[]);
bool cbDumpDataDirectories(int argc, char* argv[]);
bool cbDumpSections(int argc, char* argv[]);

// command dispatcher
bool DumpDispatch(int argc, char* argv[], DUMP_PROC DumpProcedure);

// added commands
void DumpPEHeader(const REMOTE_PE_HEADER_DATA& PEHeader);
void DumpDOSHeader(const REMOTE_PE_HEADER_DATA& PEHeader);
void DumpNTHeaders(const REMOTE_PE_HEADER_DATA& PEHeader);
void DumpFileHeader(const REMOTE_PE_HEADER_DATA& PEHeader);
void DumpOptionalHeader(const REMOTE_PE_HEADER_DATA& PEHeader);
void DumpDataDirectories(const REMOTE_PE_HEADER_DATA& PEHeader);
void DumpSections(const REMOTE_PE_HEADER_DATA& PEHeader);

////////////////////////////////////////////////////////////////////////////////
// added command callbacks

bool cbDumpPEHeader(int argc, char* argv[])
{
    return DumpDispatch(argc, argv, DumpPEHeader);
}

bool cbDumpDOSHeader(int argc, char* argv[])
{
    return DumpDispatch(argc, argv, DumpDOSHeader);
}

bool cbDumpNTHeaders(int argc, char* argv[])
{
    return DumpDispatch(argc, argv, DumpNTHeaders);
}

bool cbDumpFileHeader(int argc, char* argv[])
{
    return DumpDispatch(argc, argv, DumpFileHeader);
}

bool cbDumpOptionalHeader(int argc, char* argv[])
{
    return DumpDispatch(argc, argv, DumpOptionalHeader);
}

bool cbDumpDataDirectories(int argc, char* argv[])
{
    return DumpDispatch(argc, argv, DumpDataDirectories);
}

bool cbDumpSections(int argc, char* argv[])
{
    return DumpDispatch(argc, argv, DumpSections);
}

////////////////////////////////////////////////////////////////////////////////
// command dispatcher

bool DumpDispatch(int argc, char* argv[], DUMP_PROC DumpProcedure)
{
    if (argc > 2)
    {
        PLOG("[%s] USAGE: %s [base address].\n", PLUGIN_NAME, argv[0]);
        return false;
    }

    // obtain pe header data for effective address
    REMOTE_PE_HEADER_DATA pe;
    const duint ea = argc == 2 ? DbgValFromString(argv[1]) : GetEffectiveBaseAddress();
    if (!FillPEHeaderData(ea, pe))
    {
        PLOG("[%s] %p does not point to a valid PE header.\n", PLUGIN_NAME, ea);
        return false;
    }

    // print module name if available
    char moduleName[MAX_MODULE_SIZE] = "";
    if (DbgGetModuleAt(ea, moduleName))
        PLOG("[%s] dumping %s at %p.\n", PLUGIN_NAME, moduleName, ea);
    else
        PLOG("[%s] dumping at %p.\n", PLUGIN_NAME, ea);
    
    DumpProcedure(pe);

    return true;
}

////////////////////////////////////////////////////////////////////////////////
// added commands

void DumpPEHeader(const REMOTE_PE_HEADER_DATA& PEHeader)
{
    DumpDOSHeader(PEHeader);
    DumpNTHeaders(PEHeader);
    DumpFileHeader(PEHeader);
    DumpOptionalHeader(PEHeader);
    DumpDataDirectories(PEHeader);
    DumpSections(PEHeader);
}

void DumpDOSHeader(const REMOTE_PE_HEADER_DATA& PEHeader)
{
    PLOG(delimMajor);
    PLOG("DOS HEADER\n");
    PLOG(delimMajor);
    PLOG("  e_magic:                    %16X  %.2s\n", PEHeader.dosHeader->e_magic, (char*)&PEHeader.dosHeader->e_magic);
    PLOG("  e_cblp:                     %16X\n", PEHeader.dosHeader->e_cblp);
    PLOG("  e_cp:                       %16X\n", PEHeader.dosHeader->e_cp);
    PLOG("  e_crlc:                     %16X\n", PEHeader.dosHeader->e_crlc);
    PLOG("  e_cparhdr:                  %16X\n", PEHeader.dosHeader->e_cparhdr);
    PLOG("  e_minalloc:                 %16X\n", PEHeader.dosHeader->e_minalloc);
    PLOG("  e_maxalloc:                 %16X\n", PEHeader.dosHeader->e_maxalloc);
    PLOG("  e_ss:                       %16X\n", PEHeader.dosHeader->e_ss);
    PLOG("  e_sp:                       %16X\n", PEHeader.dosHeader->e_sp);
    PLOG("  e_csum:                     %16X\n", PEHeader.dosHeader->e_csum);
    PLOG("  e_ip:                       %16X\n", PEHeader.dosHeader->e_ip);
    PLOG("  e_cs:                       %16X\n", PEHeader.dosHeader->e_cs);
    PLOG("  e_lfarlc:                   %16X\n", PEHeader.dosHeader->e_lfarlc);
    PLOG("  e_ovno:                     %16X\n", PEHeader.dosHeader->e_ovno);
    PLOG("  e_res:                           ");
    for (int i = 0; i < 4; i++)
        PLOG("%02X ", PEHeader.dosHeader->e_res[i]);
    PLOG("\n");
    PLOG("  e_oemid:                    %16X\n", PEHeader.dosHeader->e_oemid);
    PLOG("  e_oeminfo:                  %16X\n", PEHeader.dosHeader->e_oeminfo);
    PLOG("  e_res2:        ");
    for (int i = 0; i < 10; i++)
        PLOG("%02X ", PEHeader.dosHeader->e_res2[i]);
    PLOG("\n");
    PLOG("  e_lfanew:                   %16X  %p\n", PEHeader.dosHeader->e_lfanew, RVA_TO_ADDR_OR_ZERO(PEHeader.baseAddress, PEHeader.dosHeader->e_lfanew));
}

void DumpNTHeaders(const REMOTE_PE_HEADER_DATA& PEHeader)
{
    PLOG(delimMajor);
    PLOG("NT HEADERS\n");
    PLOG(delimMajor);
    PLOG("  Signature:                  %16X  %.2s\n", PEHeader.ntHeaders->Signature, (char*)&PEHeader.ntHeaders->Signature);
    PLOG("  FileHeader:                 %16p\n", PEHeader.baseAddress + ULONG_PTR(PEHeader.fileHeader) - ULONG_PTR(PEHeader.dosHeader));
    PLOG("  OptionalHeader:             %16p\n", PEHeader.baseAddress + ULONG_PTR(PEHeader.optionalHeader) - ULONG_PTR(PEHeader.dosHeader));
}

void DumpFileHeader(const REMOTE_PE_HEADER_DATA& PEHeader)
{
    char localTime[80] = "";
    ConvertEpochToLocalTimeString(PEHeader.fileHeader->TimeDateStamp, localTime, sizeof(localTime));

    PLOG(delimMajor);
    PLOG("FILE HEADER\n");
    PLOG(delimMajor);
    PLOG("  Machine:                    %16X  %s\n", PEHeader.fileHeader->Machine, pe_data_to_string::MachineArchitecture(PEHeader.fileHeader->Machine));
    PLOG("  NumberOfSections:           %16X\n", PEHeader.fileHeader->NumberOfSections);
    PLOG("  TimeDateStamp:              %16X  %s", PEHeader.fileHeader->TimeDateStamp, localTime);
    if (PEHeader.fileHeader->PointerToSymbolTable > 0)
        PLOG("  PointerToSymbolTable:       %16X  %p\n", PEHeader.fileHeader->PointerToSymbolTable, RVA_TO_ADDR_OR_ZERO(PEHeader.baseAddress, PEHeader.fileHeader->PointerToSymbolTable));
    else
        PLOG("  PointerToSymbolTable:       %16X\n", PEHeader.fileHeader->PointerToSymbolTable);
    PLOG("  NumberOfSymbols:            %16X\n", PEHeader.fileHeader->NumberOfSymbols);
    PLOG("  SizeOfOptionalHeader:       %16X\n", PEHeader.fileHeader->SizeOfOptionalHeader);
    PLOG("  Characteristics:            %16X  %s\n", PEHeader.fileHeader->Characteristics, pe_data_to_string::ImageFileCharacteristics(PEHeader.fileHeader->Characteristics).c_str());
}

void DumpOptionalHeader(const REMOTE_PE_HEADER_DATA& PEHeader)
{
    PLOG(delimMajor);
    PLOG("OPTIONAL HEADER\n");
    PLOG(delimMajor);
    PLOG("  Magic:                      %16X  %s\n", PEHeader.optionalHeader->Magic, pe_data_to_string::OptionalHeaderMagic(PEHeader.optionalHeader->Magic));
    PLOG("  MajorLinkerVersion:         %16X\n", PEHeader.optionalHeader->MajorLinkerVersion);
    PLOG("  MinorLinkerVersion:         %16X\n", PEHeader.optionalHeader->MinorLinkerVersion);
    PLOG("  SizeOfCode:                 %16X\n", PEHeader.optionalHeader->SizeOfCode);
    PLOG("  SizeOfInitializedData:      %16X\n", PEHeader.optionalHeader->SizeOfInitializedData);
    PLOG("  SizeOfUninitializedData:    %16X\n", PEHeader.optionalHeader->SizeOfUninitializedData);
    PLOG("  AddressOfEntryPoint:        %16X  %p\n", PEHeader.optionalHeader->AddressOfEntryPoint, RVA_TO_ADDR_OR_ZERO(PEHeader.baseAddress, PEHeader.optionalHeader->AddressOfEntryPoint));
    PLOG("  BaseOfCode:                 %16X  %p\n", PEHeader.optionalHeader->BaseOfCode, RVA_TO_ADDR_OR_ZERO(PEHeader.baseAddress, PEHeader.optionalHeader->BaseOfCode));
#ifndef _WIN64
    PLOG("  BaseOfData:                 %16X  %p\n", PEHeader.optionalHeader->BaseOfData, RVA_TO_ADDR_OR_ZERO(PEHeader.baseAddress, PEHeader.optionalHeader->BaseOfData));
#endif
    PLOG("  ImageBase:                  %16p\n", PEHeader.optionalHeader->ImageBase);
    PLOG("  SectionAlignment:           %16X\n", PEHeader.optionalHeader->SectionAlignment);
    PLOG("  FileAlignment:              %16X\n", PEHeader.optionalHeader->FileAlignment);
    PLOG("  MajorOperatingSystemVersion:%16X\n", PEHeader.optionalHeader->MajorOperatingSystemVersion);
    PLOG("  MinorOperatingSystemVersion:%16X\n", PEHeader.optionalHeader->MinorOperatingSystemVersion);
    PLOG("  MajorImageVersion:          %16X\n", PEHeader.optionalHeader->MajorImageVersion);
    PLOG("  MinorImageVersion:          %16X\n", PEHeader.optionalHeader->MinorImageVersion);
    PLOG("  MajorSubsystemVersion:      %16X\n", PEHeader.optionalHeader->MajorSubsystemVersion);
    PLOG("  MinorSubsystemVersion:      %16X\n", PEHeader.optionalHeader->MinorSubsystemVersion);
    PLOG("  Win32VersionValue:          %16X\n", PEHeader.optionalHeader->Win32VersionValue);
    PLOG("  SizeOfImage:                %16X\n", PEHeader.optionalHeader->SizeOfImage);
    PLOG("  SizeOfHeaders:              %16X\n", PEHeader.optionalHeader->SizeOfHeaders);
    PLOG("  CheckSum:                   %16X\n", PEHeader.optionalHeader->CheckSum);
    PLOG("  Subsystem:                  %16X  %s\n", PEHeader.optionalHeader->Subsystem, pe_data_to_string::OptionalHeaderSubsystem(PEHeader.optionalHeader->Subsystem));
    PLOG("  DllCharacteristics:         %16X  %s\n", PEHeader.optionalHeader->DllCharacteristics, pe_data_to_string::ImageDllCharacteristics(PEHeader.optionalHeader->DllCharacteristics).c_str());
    PLOG("  SizeOfStackReserve:         %16IX\n", PEHeader.optionalHeader->SizeOfStackReserve);
    PLOG("  SizeOfStackCommit:          %16IX\n", PEHeader.optionalHeader->SizeOfStackCommit);
    PLOG("  SizeOfHeapReserve:          %16IX\n", PEHeader.optionalHeader->SizeOfHeapReserve);
    PLOG("  SizeOfHeapCommit:           %16IX\n", PEHeader.optionalHeader->SizeOfHeapCommit);
    PLOG("  LoaderFlags:                %16X\n", PEHeader.optionalHeader->LoaderFlags);
    PLOG("  NumberOfRvaAndSizes:        %16X\n", PEHeader.optionalHeader->NumberOfRvaAndSizes);
}

void DumpDataDirectories(const REMOTE_PE_HEADER_DATA& PEHeader)
{
    PLOG(delimMajor);
    PLOG("DATA DIRECTORIES\n");
    PLOG(delimMajor);
#ifdef _WIN64
    PLOG("  Name                     VA              RVA      Size\n");
#else
    PLOG("  Name                 VA          RVA      Size\n");
#endif
    PLOG(delimMinor);

    for (unsigned int i = 0; i < PEHeader.dataDirectory.size() - 1; i++)
    {
        PIMAGE_DATA_DIRECTORY dataDirectory = PEHeader.dataDirectory[i];
        PLOG("  %-14s    %p  %8X  %8X\n",
            pe_data_to_string::DataDirectoryEntry(i),
            RVA_TO_ADDR_OR_ZERO(PEHeader.baseAddress, dataDirectory->VirtualAddress),
            dataDirectory->VirtualAddress,
            dataDirectory->Size);
    }
}

void DumpSections(const REMOTE_PE_HEADER_DATA& PEHeader)
{
    PLOG(delimMajor);
    PLOG("SECTIONS\n");
    PLOG(delimMajor);
    for (auto sectionHeader : PEHeader.sectionHeaders)
    {
        PLOG("%.8s\n", sectionHeader->Name);
        PLOG(delimMinor);
        PLOG("  VirtualSize:                        %8X  %X\n", sectionHeader->Misc.VirtualSize, ULONG_PTR(PAGE_ALIGN(sectionHeader->Misc.VirtualSize)) + PAGE_SIZE);
        PLOG("  VirtualAddress:                     %8X  %p\n", sectionHeader->VirtualAddress, RVA_TO_ADDR_OR_ZERO(PEHeader.baseAddress, sectionHeader->VirtualAddress));
        PLOG("  SizeOfRawData:                      %8X\n", sectionHeader->SizeOfRawData);
        PLOG("  PointerToRawData:                   %8X\n", sectionHeader->PointerToRawData);
        PLOG("  PointerToRelocations:               %8X\n", sectionHeader->PointerToRelocations);
        PLOG("  PointerToLinenumbers:               %8X\n", sectionHeader->PointerToLinenumbers);
        PLOG("  NumberOfRelocations:                %8X\n", sectionHeader->NumberOfRelocations);
        PLOG("  NumberOfLinenumbers:                %8X\n", sectionHeader->NumberOfLinenumbers);
        PLOG("  Characteristics:                    %8X  %s\n", sectionHeader->Characteristics, pe_data_to_string::ImageSectionCharacteristics(sectionHeader->Characteristics).c_str());
        PLOG(delimMinor);
    }
}

} // namespace

////////////////////////////////////////////////////////////////////////////////
// x64dbg

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

bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    typedef bool CommandCallback_t(int, char**);

    auto RegisterRequiredCommand = [](const char* CommandString, CommandCallback_t CommandCallback)
    {
        if (!_plugin_registercommand(pluginHandle, CommandString, CommandCallback, true))
        {
            PLOG("[" PLUGIN_NAME "]  failed to register command %s.\n", CommandString);
            return false;
        }
        return true;
    };

    if (!RegisterRequiredCommand(cmdDumpPEHeader, cbDumpPEHeader)) return false;
    if (!RegisterRequiredCommand(cmdDumpDOSHeader, cbDumpDOSHeader)) return false;
    if (!RegisterRequiredCommand(cmdDumpNTHeaders, cbDumpNTHeaders)) return false;
    if (!RegisterRequiredCommand(cmdDumpFileHeader, cbDumpFileHeader)) return false;
    if (!RegisterRequiredCommand(cmdDumpOptionalHeader, cbDumpOptionalHeader)) return false;
    if (!RegisterRequiredCommand(cmdDumpDataDirectories, cbDumpDataDirectories)) return false;
    if (!RegisterRequiredCommand(cmdDumpSections, cbDumpSections)) return false;

    return true;
}

bool pluginStop()
{
    _plugin_menuclear(hMenu);
    _plugin_unregistercommand(pluginHandle, cmdDumpPEHeader);
    _plugin_unregistercommand(pluginHandle, cmdDumpDOSHeader);
    _plugin_unregistercommand(pluginHandle, cmdDumpNTHeaders);
    _plugin_unregistercommand(pluginHandle, cmdDumpFileHeader);
    _plugin_unregistercommand(pluginHandle, cmdDumpOptionalHeader);
    _plugin_unregistercommand(pluginHandle, cmdDumpDataDirectories);
    _plugin_unregistercommand(pluginHandle, cmdDumpSections);
    return true;
}

void pluginSetup()
{
    _plugin_menuaddentry(hMenu, PLUGIN_MENU_ABOUT, "&About");
}
