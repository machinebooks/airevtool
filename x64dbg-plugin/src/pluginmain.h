#pragma once

// Fix ntstatus.h redefinition conflict — must come before windows.h
#define WIN32_NO_STATUS
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_NO_STATUS

// x64dbg bridge (the public API exposed by the debugger)
#include "../../../../x64dbg/src/bridge/bridgemain.h"

// x64dbg plugin API (PLUG_INITSTRUCT, CBTYPE, _plugin_registercallback, etc.)
#include "../../../../x64dbg/src/dbg/_plugins.h"

// Plugin export macro — standard DLL export with C linkage
#define PLUG_EXPORT extern "C" __declspec(dllexport)

// Plugin handle (set in pluginit, needed for _plugin_registercallback)
extern int g_pluginHandle;
