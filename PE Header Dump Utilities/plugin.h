#pragma once

#include "pluginmain.h"

//plugin data
#define PLUGIN_NAME "PE Header Dump Utilities"
#define PLUGIN_VERSION 1

//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();

#define plog(format, ...) _plugin_logprintf(format, __VA_ARGS__)

