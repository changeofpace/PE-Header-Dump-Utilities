#pragma once

#include <Windows.h>
#include <string>

namespace pe_data_to_string {

// individual fields
const char* MachineArchitecture(WORD MachineCode);
const char* OptionalHeaderMagic(WORD Magic);
const char* OptionalHeaderSubsystem(WORD Subsystem);
const char* DataDirectoryEntry(WORD DataDirectoryEntry);

// enumerated flags
std::string ImageFileCharacteristics(WORD Characteristics);
std::string ImageDllCharacteristics(WORD DllCharacteristics);
std::string ImageSectionCharacteristics(DWORD Characteristics);

} // pe_data_to_string