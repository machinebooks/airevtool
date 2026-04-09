#include "command_handler.h"
#include <sstream>
#include <vector>
#include <algorithm>
#include <thread>

static std::string joinInstructionOperands(const DISASM_INSTR& instr) {
    std::ostringstream ss;
    for (int i = 0; i < instr.argcount && i < 3; i++) {
        if (instr.arg[i].mnemonic[0] == '\0')
            continue;
        if (ss.tellp() > 0)
            ss << ", ";
        ss << instr.arg[i].mnemonic;
    }
    return ss.str();
}

// Fire-and-forget: respond immediately, run cmd in background thread
static void asyncCmd(const char* cmd) {
    std::string cmdStr(cmd);
    std::thread([cmdStr]() {
        DbgCmdExecDirect(cmdStr.c_str());
    }).detach();
}

// Minimal JSON parser — we only need simple key extraction
// In production, replace with nlohmann/json or similar
static std::string jsonGet(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    // skip whitespace and colon
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) pos++;
    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
        // string value
        size_t start = pos + 1;
        size_t end = json.find('"', start);
        if (end == std::string::npos) return "";
        return json.substr(start, end - start);
    } else {
        // number/bool/null
        size_t start = pos;
        size_t end = json.find_first_of(",}", start);
        if (end == std::string::npos) end = json.size();
        std::string val = json.substr(start, end - start);
        // trim
        val.erase(0, val.find_first_not_of(" \t\r\n"));
        val.erase(val.find_last_not_of(" \t\r\n") + 1);
        return val;
    }
}

std::string CommandHandler::handle(const std::string& requestJson) {
    std::string id  = jsonGet(requestJson, "id");
    std::string cmd = jsonGet(requestJson, "cmd");

    // Extract args object substring
    std::string args = "";
    size_t argsPos = requestJson.find("\"args\"");
    if (argsPos != std::string::npos) {
        size_t braceStart = requestJson.find('{', argsPos);
        if (braceStart != std::string::npos) {
            int depth = 0; size_t i = braceStart;
            for (; i < requestJson.size(); i++) {
                if (requestJson[i] == '{') depth++;
                else if (requestJson[i] == '}') { if (--depth == 0) { i++; break; } }
            }
            args = requestJson.substr(braceStart, i - braceStart);
        }
    }

    // Dispatch — all cmd* helpers use "" as id placeholder
    std::string response;
    if      (cmd == "start")        response = cmdStart(jsonGet(args, "path").c_str(), jsonGet(args, "arch").c_str());
    else if (cmd == "stop")         response = cmdStop();
    else if (cmd == "pause")        response = cmdPause();
    else if (cmd == "run")          response = cmdRun();
    else if (cmd == "step_in")      response = cmdStepIn();
    else if (cmd == "step_over")    response = cmdStepOver();
    else if (cmd == "step_out")     response = cmdStepOut();
    else if (cmd == "bp_set")       response = cmdBpSet(jsonGet(args, "address").c_str(), jsonGet(args, "type").c_str());
    else if (cmd == "bp_delete")    response = cmdBpDelete(jsonGet(args, "address").c_str());
    else if (cmd == "bp_list")      response = cmdBpList();
    else if (cmd == "mem_read")     response = cmdMemRead(jsonGet(args, "address").c_str(), (duint)std::stoull(jsonGet(args, "size").empty() ? "0" : jsonGet(args, "size")));
    else if (cmd == "mem_map")      response = cmdMemMap();
    else if (cmd == "disasm")       response = cmdDisasm(jsonGet(args, "address").c_str(), std::stoi(jsonGet(args, "count").empty() ? "50" : jsonGet(args, "count")));
    else if (cmd == "disasm_range") response = cmdDisasmRange(jsonGet(args, "start").c_str(), jsonGet(args, "end").c_str());
    else if (cmd == "regs_get")     response = cmdRegsGet();
    else if (cmd == "state_get")    response = cmdStateGet();
    else if (cmd == "modules_list") response = cmdModulesList();
    else if (cmd == "xref_find")    response = cmdXrefFind(jsonGet(args, "address").c_str());
    else if (cmd == "cmd")          response = cmdRawCommand(jsonGet(args, "cmd").c_str());
    else                            return err(id, "Unknown command: " + cmd);

    // Inject the real request id into the response
    // All helpers produce: {"id":"","ok":... — replace the empty id
    const std::string emptyId = "\"id\":\"\"";
    const std::string realId  = "\"id\":\"" + id + "\"";
    size_t pos = response.find(emptyId);
    if (pos != std::string::npos)
        response.replace(pos, emptyId.size(), realId);

    return response;
}

// ── Debug control ────────────────────────────────────────────

std::string CommandHandler::cmdStart(const char* path, const char* arch) {
    char cmd[MAX_PATH + 64];
    snprintf(cmd, sizeof(cmd), "InitDebug \"%s\"", path);
    asyncCmd(cmd);  // non-blocking — x64dbg will emit paused event when ready
    return ok("", R"({"status":"started"})");
}

std::string CommandHandler::cmdStop() {
    asyncCmd("StopDebug");
    return ok("", "null");
}

std::string CommandHandler::cmdPause() {
    asyncCmd("pause");
    return ok("", "null");
}

std::string CommandHandler::cmdRun() {
    asyncCmd("run");
    return ok("", "null");
}

std::string CommandHandler::cmdStepIn() {
    asyncCmd("sti");
    return ok("", "null");
}

std::string CommandHandler::cmdStepOver() {
    asyncCmd("sto");
    return ok("", "null");
}

std::string CommandHandler::cmdStepOut() {
    asyncCmd("rtr");
    return ok("", "null");
}

// ── Breakpoints ──────────────────────────────────────────────

std::string CommandHandler::cmdBpSet(const char* address, const char* type) {
    duint addr = parseAddr(address);
    char cmd[256];
    if (strcmp(type, "hardware") == 0)
        snprintf(cmd, sizeof(cmd), "bph 0x%llX", (unsigned long long)addr);
    else if (strcmp(type, "memory") == 0)
        snprintf(cmd, sizeof(cmd), "bpm 0x%llX, r", (unsigned long long)addr);
    else
        snprintf(cmd, sizeof(cmd), "bp 0x%llX", (unsigned long long)addr);
    DbgCmdExecDirect(cmd);

    char result[256];
    snprintf(result, sizeof(result),
        R"({"address":"0x%llX","type":"%s","enabled":true,"hitCount":0})",
        (unsigned long long)addr, type);
    return ok("", result);
}

std::string CommandHandler::cmdBpDelete(const char* address) {
    duint addr = parseAddr(address);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bpc 0x%llX", (unsigned long long)addr);
    DbgCmdExecDirect(cmd);
    return ok("", "null");
}

std::string CommandHandler::cmdBpList() {
    BPMAP bpMap;
    int count = DbgGetBpList(bp_normal, &bpMap);
    std::ostringstream ss;
    ss << "[";
    for (int i = 0; i < count; i++) {
        if (i > 0) ss << ",";
        ss << R"({"address":"0x)" << std::hex << bpMap.bp[i].addr << R"(","enabled":)"
           << (bpMap.bp[i].enabled ? "true" : "false")
           << R"(,"hitCount":)" << std::dec << bpMap.bp[i].hitCount << "}";
    }
    ss << "]";
    if (bpMap.bp) BridgeFree(bpMap.bp);
    return ok("", ss.str());
}

// ── Memory ───────────────────────────────────────────────────

std::string CommandHandler::cmdMemRead(const char* address, duint size) {
    duint addr = parseAddr(address);
    if (size > 64 * 1024) size = 64 * 1024;  // cap at 64KB

    std::vector<unsigned char> buf(size);
    bool ok_read = DbgMemRead(addr, buf.data(), size);  // 3-arg API

    if (!ok_read) return err("", "Failed to read memory");

    std::ostringstream ss;
    ss << R"({"bytes":[)";
    for (duint i = 0; i < size; i++) {
        if (i > 0) ss << ",";
        ss << (int)buf[i];
    }
    ss << "]}";
    return ok("", ss.str());
}

std::string CommandHandler::cmdMemMap() {
    MEMMAP memMap;
    bool success = DbgMemMap(&memMap);
    if (!success) return err("", "Failed to get memory map");

    std::ostringstream ss;
    ss << "[";
    for (int i = 0; i < memMap.count; i++) {
        if (i > 0) ss << ",";
        MEMPAGE& page = memMap.page[i];
        char module[MAX_MODULE_SIZE] = {};
        DbgGetModuleAt((duint)(uintptr_t)page.mbi.BaseAddress, module);

        ss << "{\"baseAddress\":\"0x" << std::hex << (duint)page.mbi.BaseAddress << "\""
           << ",\"size\":" << std::dec << page.mbi.RegionSize
           << ",\"protection\":\"" << protToString(page.mbi.Protect) << "\""
           << ",\"type\":\"" << (page.mbi.Type == MEM_IMAGE ? "image" : page.mbi.Type == MEM_MAPPED ? "mapped" : "private") << "\""
           << ",\"moduleName\":\"" << (module[0] ? escapeJson(module) : "") << "\""
           << "}";
    }
    ss << "]";
    if (memMap.page) BridgeFree(memMap.page);
    return ok("", ss.str());
}

// ── Disassembly ──────────────────────────────────────────────

std::string CommandHandler::cmdDisasm(const char* address, int count) {
    duint addr = parseAddr(address);
    std::ostringstream ss;
    ss << "[";
    bool first = true;

    for (int i = 0; i < count; i++) {
        DISASM_INSTR instr = {};
        DbgDisasmAt(addr, &instr);  // returns void
        if (!first) ss << ",";
        first = false;

        // Use the fast decoder only for the instruction size, then read the
        // real opcode bytes from memory. Serializing BASIC_INSTRUCTION_INFO
        // directly produces incorrect bytes because it is metadata, not the
        // instruction buffer itself.
        BASIC_INSTRUCTION_INFO bii = {};
        DbgDisasmFastAt(addr, &bii);
        duint instSize = bii.size > 0 ? (duint)bii.size : 1;
        if (instSize > 16)
            instSize = 16;

        std::vector<unsigned char> raw(instSize, 0);
        bool okRead = DbgMemRead(addr, raw.data(), instSize);

        char hexBytes[64] = {};
        size_t offset = 0;
        if (okRead) {
            for (duint b = 0; b < instSize && offset + 4 < sizeof(hexBytes); b++) {
                int written = sprintf_s(hexBytes + offset, sizeof(hexBytes) - offset, "%02X ", raw[b]);
                if (written <= 0)
                    break;
                offset += (size_t)written;
            }
        }

        std::string instructionText = instr.instruction;
        std::string mnemonic = instructionText;
        size_t splitPos = instructionText.find_first_of(" \t");
        if (splitPos != std::string::npos) {
            mnemonic = instructionText.substr(0, splitPos);
        }

        std::string operands = joinInstructionOperands(instr);
        if (operands.empty() && splitPos != std::string::npos) {
            size_t operandStart = instructionText.find_first_not_of(" \t", splitPos);
            if (operandStart != std::string::npos)
                operands = instructionText.substr(operandStart);
        }

        char label[MAX_LABEL_SIZE] = {};
        std::string disasmComment;
        if (DbgGetLabelAt(addr, SEG_DEFAULT, label) && label[0] != '\0')
            disasmComment = label;

        ss << "{\"address\":\"0x" << std::hex << addr << "\""
           << ",\"bytes\":\"" << hexBytes << "\""
           << ",\"mnemonic\":\"" << escapeJson(mnemonic) << "\""
           << ",\"operands\":\"" << escapeJson(operands) << "\""
           << ",\"comment\":\"" << escapeJson(disasmComment) << "\""
           << "}";

        addr += bii.size > 0 ? bii.size : 1;
    }
    ss << "]";
    return ok("", ss.str());
}

std::string CommandHandler::cmdDisasmRange(const char* start, const char* end) {
    duint startAddr = parseAddr(start);
    duint endAddr   = parseAddr(end);
    int maxCount = (int)((endAddr - startAddr) / 1) + 1;
    if (maxCount > 2000) maxCount = 2000;
    return cmdDisasm(start, maxCount);
}

// ── Registers ────────────────────────────────────────────────

std::string CommandHandler::cmdRegsGet() {
    REGDUMP_AVX512 regs = {};
    if (!DbgGetRegDumpEx(&regs, sizeof(regs))) return err("", "Failed to get registers");

    std::ostringstream ss;
    ss << "[";

#ifdef _WIN64
    auto addReg = [&](const char* name, unsigned long long val, bool first) {
        if (!first) ss << ",";
        char hex[32]; snprintf(hex, sizeof(hex), "0x%016llX", val);
        ss << "{\"name\":\"" << name << "\",\"value\":\"" << hex << "\",\"size\":64}";
    };
    addReg("RAX", regs.regcontext.cax, true);
    addReg("RBX", regs.regcontext.cbx, false);
    addReg("RCX", regs.regcontext.ccx, false);
    addReg("RDX", regs.regcontext.cdx, false);
    addReg("RSI", regs.regcontext.csi, false);
    addReg("RDI", regs.regcontext.cdi, false);
    addReg("RSP", regs.regcontext.csp, false);
    addReg("RBP", regs.regcontext.cbp, false);
    addReg("RIP", regs.regcontext.cip, false);
    addReg("R8",  regs.regcontext.r8,  false);
    addReg("R9",  regs.regcontext.r9,  false);
    addReg("R10", regs.regcontext.r10, false);
    addReg("R11", regs.regcontext.r11, false);
    addReg("R12", regs.regcontext.r12, false);
    addReg("R13", regs.regcontext.r13, false);
    addReg("R14", regs.regcontext.r14, false);
    addReg("R15", regs.regcontext.r15, false);
    // EFLAGS
    char flagHex[32]; snprintf(flagHex, sizeof(flagHex), "0x%08X", (unsigned)regs.regcontext.eflags);
    ss << ",{\"name\":\"RFLAGS\",\"value\":\"" << flagHex << "\",\"size\":32}";
#else
    auto addReg = [&](const char* name, unsigned long val, bool first) {
        if (!first) ss << ",";
        char hex[16]; snprintf(hex, sizeof(hex), "0x%08lX", val);
        ss << "{\"name\":\"" << name << "\",\"value\":\"" << hex << "\",\"size\":32}";
    };
    addReg("EAX", regs.regcontext.cax, true);
    addReg("EBX", regs.regcontext.cbx, false);
    addReg("ECX", regs.regcontext.ccx, false);
    addReg("EDX", regs.regcontext.cdx, false);
    addReg("ESI", regs.regcontext.csi, false);
    addReg("EDI", regs.regcontext.cdi, false);
    addReg("ESP", regs.regcontext.csp, false);
    addReg("EBP", regs.regcontext.cbp, false);
    addReg("EIP", regs.regcontext.cip, false);
    char flagHex[16]; snprintf(flagHex, sizeof(flagHex), "0x%08lX", (unsigned long)regs.regcontext.eflags);
    ss << ",{\"name\":\"EFLAGS\",\"value\":\"" << flagHex << "\",\"size\":32}";
#endif

    ss << "]";
    return ok("", ss.str());
}

// ── State ────────────────────────────────────────────────────

std::string CommandHandler::cmdStateGet() {
    std::string regs = cmdRegsGet();
    // Extract result from ok() wrapper
    // {"id":"","ok":true,"result":...}
    size_t rpos = regs.find("\"result\":");
    std::string regsResult = (rpos != std::string::npos) ? regs.substr(rpos + 9, regs.size() - rpos - 10) : "[]";

    std::ostringstream ss;
    ss << "{\"registers\":" << regsResult
       << ",\"session\":{\"status\":\"" << (DbgIsDebugging() ? "paused" : "idle") << "\"}"
       << ",\"breakpoints\":[]"
       << ",\"memoryMap\":[]"
       << ",\"callStack\":[]}";
    return ok("", ss.str());
}

// ── Modules ──────────────────────────────────────────────────

std::string CommandHandler::cmdModulesList() {
    // Use DbgGetModuleList or iterate via DbgMemMap
    return ok("", "[]");
}

std::string CommandHandler::cmdXrefFind(const char* address) {
    return ok("", "[]");
}

// ── Raw command ───────────────────────────────────────────────

std::string CommandHandler::cmdRawCommand(const char* cmd) {
    asyncCmd(cmd);
    return ok("", "\"executed\"");
}

// ── Helpers ───────────────────────────────────────────────────

std::string CommandHandler::ok(const std::string& id, const std::string& result) {
    return "{\"id\":\"" + id + "\",\"ok\":true,\"result\":" + result + "}";
}

std::string CommandHandler::err(const std::string& id, const std::string& error) {
    return "{\"id\":\"" + id + "\",\"ok\":false,\"error\":\"" + escapeJson(error) + "\"}";
}

duint CommandHandler::parseAddr(const char* s) {
    if (!s || !*s) return 0;
    // DbgEval(expr, bool* success) — returns the value directly
    bool ok = false;
    duint val = DbgEval(s, &ok);
    if (!ok || !val) {
        try { val = (duint)std::stoull(s, nullptr, 16); } catch (...) {}
    }
    return val;
}

std::string CommandHandler::escapeJson(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    return out;
}

std::string CommandHandler::protToString(DWORD protect) {
    // Strip PAGE_GUARD and PAGE_NOCACHE flags
    protect &= ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    switch (protect) {
        case PAGE_READONLY:          return "R";
        case PAGE_READWRITE:         return "RW";
        case PAGE_WRITECOPY:         return "WC";
        case PAGE_EXECUTE:           return "X";
        case PAGE_EXECUTE_READ:      return "RX";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_EXECUTE_WRITECOPY: return "RWX";
        case PAGE_NOACCESS:          return "NA";
        default:                     return "?";
    }
}
