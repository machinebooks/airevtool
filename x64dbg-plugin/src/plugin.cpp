/**
 * AIrevPlugin — x64dbg plugin bridge for AIrevtool
 *
 * Exposes a WebSocket server on ws://127.0.0.1:27042
 * AIrevtool (Electron) connects and sends JSON commands.
 *
 * Protocol:
 *   Request:  {"id":"r1","cmd":"disasm","args":{"address":"0x401000","count":50}}
 *   Response: {"id":"r1","ok":true,"result":[...]}
 *   Event:    {"event":"paused","data":{"reason":"breakpoint","address":"0x401234"}}
 */

#pragma warning(disable: 4005)  // suppress ntstatus redefinition warnings

#define PLUGIN_NAME "AIrevPlugin"
#define PLUGIN_VERSION 1

#include "pluginmain.h"
#include "websocket_server.h"
#include "command_handler.h"
#include <string>
#include <thread>

// ── Globals ──────────────────────────────────────────────────

int g_pluginHandle = 0;
static WebSocketServer* g_server  = nullptr;
static CommandHandler*  g_handler = nullptr;
static std::thread      g_serverThread;

// ── Forward declarations for callbacks ───────────────────────

static void cbPauseDebug(CBTYPE cbType, void* info);
static void cbBreakpoint(CBTYPE cbType, void* info);
static void cbException(CBTYPE cbType, void* info);
static void cbDebugEvent(CBTYPE cbType, void* info);
static void cbStopDebug(CBTYPE cbType, void* info);
static void cbLogged(CBTYPE cbType, void* info);

// ── Plugin entry points ──────────────────────────────────────

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion    = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, sizeof(initStruct->pluginName),
              PLUGIN_NAME, _TRUNCATE);
    g_pluginHandle = initStruct->pluginHandle;

    _plugin_logprintf("[AIrevPlugin] Initializing (version %d)\n", PLUGIN_VERSION);

    g_handler = new CommandHandler();
    g_server  = new WebSocketServer(27042, g_handler);

    g_serverThread = std::thread([] { g_server->run(); });

    _plugin_logprintf("[AIrevPlugin] WebSocket server started on ws://127.0.0.1:27042\n");
    return true;
}

PLUG_EXPORT bool plugstop()
{
    _plugin_logprintf("[AIrevPlugin] Stopping\n");

    // Unregister callbacks
    _plugin_unregistercallback(g_pluginHandle, CB_PAUSEDEBUG);
    _plugin_unregistercallback(g_pluginHandle, CB_BREAKPOINT);
    _plugin_unregistercallback(g_pluginHandle, CB_EXCEPTION);
    _plugin_unregistercallback(g_pluginHandle, CB_DEBUGEVENT);
    _plugin_unregistercallback(g_pluginHandle, CB_STOPDEBUG);

    if (g_server)  { g_server->stop(); }
    if (g_serverThread.joinable()) g_serverThread.join();
    delete g_server;  g_server  = nullptr;
    delete g_handler; g_handler = nullptr;
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    // Register debug event callbacks
    _plugin_registercallback(g_pluginHandle, CB_PAUSEDEBUG,  cbPauseDebug);
    _plugin_registercallback(g_pluginHandle, CB_BREAKPOINT,  cbBreakpoint);
    _plugin_registercallback(g_pluginHandle, CB_EXCEPTION,   cbException);
    _plugin_registercallback(g_pluginHandle, CB_DEBUGEVENT,  cbDebugEvent);
    _plugin_registercallback(g_pluginHandle, CB_STOPDEBUG,   cbStopDebug);

    _plugin_logprintf("[AIrevPlugin] Callbacks registered\n");
}

// ── Debug event callbacks ────────────────────────────────────

static void cbPauseDebug(CBTYPE, void*)
{
    if (!g_server || !g_server->hasClients()) return;
    duint rip = DbgValFromString("cip");
    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"event\":\"paused\",\"data\":{\"reason\":\"debug_event\",\"address\":\"0x%llX\"}}",
        (unsigned long long)rip);
    g_server->broadcast(buf);
}

static void cbBreakpoint(CBTYPE, void* info)
{
    if (!g_server || !g_server->hasClients()) return;
    auto* bp = static_cast<PLUG_CB_BREAKPOINT*>(info);
    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"event\":\"paused\",\"data\":{\"reason\":\"breakpoint\",\"address\":\"0x%llX\"}}",
        (unsigned long long)bp->breakpoint->addr);
    g_server->broadcast(buf);
}

static void cbException(CBTYPE, void* info)
{
    if (!g_server || !g_server->hasClients()) return;
    auto* ex = static_cast<PLUG_CB_EXCEPTION*>(info);
    duint rip = DbgValFromString("cip");
    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"event\":\"paused\",\"data\":{\"reason\":\"exception\",\"code\":\"0x%08X\",\"address\":\"0x%llX\"}}",
        ex->Exception->ExceptionRecord.ExceptionCode,
        (unsigned long long)rip);
    g_server->broadcast(buf);
}

static void cbDebugEvent(CBTYPE, void* info)
{
    if (!g_server || !g_server->hasClients()) return;
    auto* ev = static_cast<PLUG_CB_DEBUGEVENT*>(info);
    if (ev->DebugEvent->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
        g_server->broadcast("{\"event\":\"stopped\",\"data\":{\"reason\":\"exit\"}}");
    }
}

static void cbStopDebug(CBTYPE, void*)
{
    if (!g_server || !g_server->hasClients()) return;
    g_server->broadcast("{\"event\":\"stopped\",\"data\":{\"reason\":\"stop\"}}");
}

static void cbLogged(CBTYPE, void* info)
{
    // Optional: forward x64dbg log to AIrevtool
    // Skipped to reduce noise
    (void)info;
}
