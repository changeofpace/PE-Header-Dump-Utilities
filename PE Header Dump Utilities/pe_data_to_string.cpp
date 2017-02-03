#include "pe_data_to_string.h"

static const char* unknownDataString = "???";

////////////////////////////////////////////////////////////////////////////////
// individual fields

const char* pe_data_to_string::MachineArchitecture(WORD MachineCode)
{
    switch (MachineCode)
    {
    case IMAGE_FILE_MACHINE_I386:  return "I386";
    case IMAGE_FILE_MACHINE_IA64:  return "IA64";
    case IMAGE_FILE_MACHINE_AMD64: return "AMD64";
    }
    return unknownDataString;
}

const char* pe_data_to_string::OptionalHeaderMagic(WORD Magic)
{
    switch (Magic)
    {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC: return "HDR32";
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC: return "HDR64";
    case IMAGE_ROM_OPTIONAL_HDR_MAGIC:  return "ROM";
    }
    return unknownDataString;
}

const char* pe_data_to_string::OptionalHeaderSubsystem(WORD Subsystem)
{
    switch (Subsystem)
    {
    case IMAGE_SUBSYSTEM_UNKNOWN:                   return "UNKNOWN";
    case IMAGE_SUBSYSTEM_NATIVE:                    return "NATIVE";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:               return "WINDOWS_GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:               return "WINDOWS_CUI";
    case IMAGE_SUBSYSTEM_OS2_CUI:                   return "OS2_CUI";
    case IMAGE_SUBSYSTEM_POSIX_CUI:                 return "POSIX_CUI";
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:            return "NATIVE_WINDOWS";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:            return "WINDOWS_CE_GUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:           return "EFI_APPLICATION";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:   return "EFI_BOOT_SERVICE_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:        return "EFI_RUNTIME_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_ROM:                   return "EFI_ROM";
    case IMAGE_SUBSYSTEM_XBOX:                      return "XBOX";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:  return "WINDOWS_BOOT_APPLICATION";
    }
    return unknownDataString;
}

const char* pe_data_to_string::DataDirectoryEntry(WORD DataDirectoryEntry)
{
    switch (DataDirectoryEntry)
    {
    case IMAGE_DIRECTORY_ENTRY_EXPORT:          return "EXPORT";
    case IMAGE_DIRECTORY_ENTRY_IMPORT:          return "IMPORT";
    case IMAGE_DIRECTORY_ENTRY_RESOURCE:        return "RESOURCE";
    case IMAGE_DIRECTORY_ENTRY_EXCEPTION:       return "EXCEPTION";
    case IMAGE_DIRECTORY_ENTRY_SECURITY:        return "SECURITY";
    case IMAGE_DIRECTORY_ENTRY_BASERELOC:       return "BASERELOC";
    case IMAGE_DIRECTORY_ENTRY_DEBUG:           return "DEBUG";
    //case IMAGE_DIRECTORY_ENTRY_COPYRIGHT:       return "COPYRIGHT";  // (X86 usage)
    case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:    return "ARCHITECTURE";
    case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:       return "GLOBALPTR";
    case IMAGE_DIRECTORY_ENTRY_TLS:             return "TLS";
    case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:     return "LOAD_CONFIG";
    case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:    return "BOUND_IMPORT";
    case IMAGE_DIRECTORY_ENTRY_IAT:             return "IAT";
    case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:    return "DELAY_IMPORT";
    case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:  return "COM_DESCRIPTOR";
    }
    return unknownDataString;
}

////////////////////////////////////////////////////////////////////////////////
// enumerated flags

static void RemoveTrailingComma(std::string& s)
{
    if (s.size() > 0)
    {
        s.pop_back();
        s.pop_back();
    }
}

std::string pe_data_to_string::ImageFileCharacteristics(WORD Characteristics)
{
    std::string flags;
    if ((Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0)        flags += "RELOCS_STRIPPED, ";
    if ((Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0)       flags += "EXECUTABLE_IMAGE, ";
    if ((Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED) != 0)     flags += "LINE_NUMS_STRIPPED, ";
    if ((Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) != 0)    flags += "LOCAL_SYMS_STRIPPED, ";
    if ((Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM) != 0)      flags += "AGGRESIVE_WS_TRIM, ";
    if ((Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0)    flags += "LARGE_ADDRESS_AWARE, ";
    if ((Characteristics & IMAGE_FILE_BYTES_REVERSED_LO) != 0)      flags += "BYTES_REVERSED_LO, ";
    if ((Characteristics & IMAGE_FILE_32BIT_MACHINE) != 0)          flags += "32BIT_MACHINE, ";
    if ((Characteristics & IMAGE_FILE_DEBUG_STRIPPED) != 0)         flags += "DEBUG_STRIPPED, ";
    if ((Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) != 0)flags += "REMOVABLE_RUN_FROM_SWAP, ";
    if ((Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) != 0)      flags += "NET_RUN_FROM_SWAP, ";
    if ((Characteristics & IMAGE_FILE_SYSTEM) != 0)                 flags += "SYSTEM, ";
    if ((Characteristics & IMAGE_FILE_DLL) != 0)                    flags += "DLL, ";
    if ((Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) != 0)         flags += "UP_SYSTEM_ONLY, ";
    if ((Characteristics & IMAGE_FILE_BYTES_REVERSED_HI) != 0)      flags += "BYTES_REVERSED_HI, ";
    RemoveTrailingComma(flags);
    return flags;
}

std::string pe_data_to_string::ImageDllCharacteristics(WORD DllCharacteristics)
{
    std::string flags;
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0)          flags += "DYNAMIC_BASE, ";
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0)       flags += "FORCE_INTEGRITY, ";
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0)             flags += "NX_COMPAT, ";
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0)          flags += "NO_ISOLATION, ";
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0)                flags += "NO_SEH, ";
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND) != 0)               flags += "NO_BIND, ";
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) != 0)            flags += "WDM_DRIVER, ";
    if ((DllCharacteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) != 0) flags += "TERMINAL_SERVER_AWARE, ";
    RemoveTrailingComma(flags);
    return flags;
}

std::string pe_data_to_string::ImageSectionCharacteristics(DWORD Characteristics)
{
    std::string flags;
    if ((Characteristics & IMAGE_SCN_TYPE_NO_PAD) != 0)             flags += "TYPE_NO_PAD, ";
    if ((Characteristics & IMAGE_SCN_CNT_CODE) != 0)                flags += "CNT_CODE, ";
    if ((Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0)    flags += "CNT_INITIALIZED_DATA, ";
    if ((Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)  flags += "CNT_UNINITIALIZED_DATA, ";
    if ((Characteristics & IMAGE_SCN_LNK_OTHER) != 0)               flags += "LNK_OTHER, ";
    if ((Characteristics & IMAGE_SCN_LNK_INFO) != 0)                flags += "LNK_INFO, ";
    if ((Characteristics & IMAGE_SCN_LNK_REMOVE) != 0)              flags += "LNK_REMOVE, ";
    if ((Characteristics & IMAGE_SCN_LNK_COMDAT) != 0)              flags += "LNK_COMDAT, ";
    if ((Characteristics & IMAGE_SCN_NO_DEFER_SPEC_EXC) != 0)       flags += "NO_DEFER_SPEC_EXC, ";
    if ((Characteristics & IMAGE_SCN_GPREL) != 0)                   flags += "GPREL, ";
    if ((Characteristics & IMAGE_SCN_MEM_FARDATA) != 0)             flags += "MEM_FARDATA, ";
    if ((Characteristics & IMAGE_SCN_MEM_PURGEABLE) != 0)           flags += "MEM_PURGEABLE, ";
    if ((Characteristics & IMAGE_SCN_MEM_16BIT) != 0)               flags += "MEM_16BIT, ";
    if ((Characteristics & IMAGE_SCN_MEM_LOCKED) != 0)              flags += "MEM_LOCKED, ";
    if ((Characteristics & IMAGE_SCN_MEM_PRELOAD) != 0)             flags += "MEM_PRELOAD, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_1BYTES) != 0)            flags += "ALIGN_1BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_2BYTES) != 0)            flags += "ALIGN_2BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_4BYTES) != 0)            flags += "ALIGN_4BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_8BYTES) != 0)            flags += "ALIGN_8BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_16BYTES) != 0)           flags += "ALIGN_16BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_32BYTES) != 0)           flags += "ALIGN_32BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_64BYTES) != 0)           flags += "ALIGN_64BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_128BYTES) != 0)          flags += "ALIGN_128BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_256BYTES) != 0)          flags += "ALIGN_256BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_512BYTES) != 0)          flags += "ALIGN_512BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_1024BYTES) != 0)         flags += "ALIGN_1024BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_2048BYTES) != 0)         flags += "ALIGN_2048BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_4096BYTES) != 0)         flags += "ALIGN_4096BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_8192BYTES) != 0)         flags += "ALIGN_8192BYTES, ";
    if ((Characteristics & IMAGE_SCN_ALIGN_MASK) != 0)              flags += "ALIGN_MASK, ";
    if ((Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) != 0)         flags += "LNK_NRELOC_OVFL, ";
    if ((Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)         flags += "MEM_DISCARDABLE, ";
    if ((Characteristics & IMAGE_SCN_MEM_NOT_CACHED) != 0)          flags += "MEM_NOT_CACHED, ";
    if ((Characteristics & IMAGE_SCN_MEM_NOT_PAGED) != 0)           flags += "MEM_NOT_PAGED, ";
    if ((Characteristics & IMAGE_SCN_MEM_SHARED) != 0)              flags += "MEM_SHARED, ";
    if ((Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)             flags += "MEM_EXECUTE, ";
    if ((Characteristics & IMAGE_SCN_MEM_READ) != 0)                flags += "MEM_READ, ";
    if ((Characteristics & IMAGE_SCN_MEM_WRITE) != 0)               flags += "MEM_WRITE, ";
    RemoveTrailingComma(flags);
    return flags;
}
