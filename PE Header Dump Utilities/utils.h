#pragma once

#include <Windows.h>
#include "pluginmain.h"

duint GetSelectedAddress();
duint GetActiveModuleImageBase();
duint GetEffectiveBaseAddress();
bool ConvertEpochToLocalTimeString(DWORD TimeDateStamp, char* LocalTimeString, SIZE_T BufferSize);
