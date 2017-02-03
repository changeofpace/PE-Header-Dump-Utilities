#pragma once

#include "pluginmain.h"

#define PLUGIN_NAME "PE Header Dump Utilities"
#define PLUGIN_VERSION 1

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info);
bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();

