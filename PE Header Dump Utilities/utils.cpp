#include "utils.h"
#include <time.h>

duint GetSelectedAddress()
{
    SELECTIONDATA selection;
    if (GuiSelectionGet(GUI_DISASSEMBLY, &selection))
        return selection.start;
    return 0;
}

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
        _snprintf_s(LocalTimeString, BufferSize, _TRUNCATE, "???");
        return false;
    }
    asctime_s(LocalTimeString, BufferSize, &newTime);
    return true;
}
