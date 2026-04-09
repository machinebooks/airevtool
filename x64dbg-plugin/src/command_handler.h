#pragma once
#pragma warning(disable: 4005)

#include "pluginmain.h"
#include <string>

class CommandHandler {
public:
    std::string handle(const std::string& requestJson);

private:
    std::string cmdStart(const char* path, const char* arch);
    std::string cmdStop();
    std::string cmdPause();
    std::string cmdRun();
    std::string cmdStepIn();
    std::string cmdStepOver();
    std::string cmdStepOut();

    std::string cmdBpSet(const char* address, const char* type);
    std::string cmdBpDelete(const char* address);
    std::string cmdBpList();

    std::string cmdMemRead(const char* address, duint size);
    std::string cmdMemMap();

    std::string cmdDisasm(const char* address, int count);
    std::string cmdDisasmRange(const char* start, const char* end);

    std::string cmdRegsGet();
    std::string cmdStateGet();
    std::string cmdModulesList();
    std::string cmdXrefFind(const char* address);
    std::string cmdRawCommand(const char* cmd);

    std::string ok(const std::string& id, const std::string& result);
    std::string err(const std::string& id, const std::string& error);
    duint  parseAddr(const char* s);
    std::string escapeJson(const std::string& s);
    std::string protToString(DWORD protect);
};
