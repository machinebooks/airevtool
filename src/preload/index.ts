import { contextBridge, ipcRenderer } from 'electron'
import { IPC } from '../shared/types'
import type { AIMessage, LMStudioConfig, Finding, AnalysisStartOptions, DisasmGraphUpdate } from '../shared/types'

// ── Expose safe IPC bridge to renderer ──────────────────────

contextBridge.exposeInMainWorld('api', {
  // Debugger
  dbg: {
    start:       (path: string, arch: 'x64' | 'x32') => ipcRenderer.invoke(IPC.DBG_START, path, arch),
    stop:        () => ipcRenderer.invoke(IPC.DBG_STOP),
    pause:       () => ipcRenderer.invoke(IPC.DBG_PAUSE),
    resume:      () => ipcRenderer.invoke(IPC.DBG_RESUME),
    stepIn:      () => ipcRenderer.invoke(IPC.DBG_STEP_IN),
    stepOver:    () => ipcRenderer.invoke(IPC.DBG_STEP_OVER),
    stepOut:     () => ipcRenderer.invoke(IPC.DBG_STEP_OUT),
    setBP:       (addr: string, type: 'software' | 'hardware' | 'memory') => ipcRenderer.invoke(IPC.DBG_BP_SET, addr, type),
    deleteBP:    (addr: string) => ipcRenderer.invoke(IPC.DBG_BP_DELETE, addr),
    breakpoints: () => ipcRenderer.invoke(IPC.DBG_BP_LIST),
    readMem:     (addr: string, size: number) => ipcRenderer.invoke(IPC.DBG_MEM_READ, addr, size),
    memMap:      () => ipcRenderer.invoke(IPC.DBG_MEM_MAP),
    disasm:      (addr: string, count: number) => ipcRenderer.invoke(IPC.DBG_DISASM, addr, count),
    registers:   () => ipcRenderer.invoke(IPC.DBG_REGS),
    state:       () => ipcRenderer.invoke(IPC.DBG_STATE),
    command:     (cmd: string) => ipcRenderer.invoke(IPC.DBG_COMMAND, cmd),
    connect:     () => ipcRenderer.invoke('dbg:connect'),
    isConnected: () => ipcRenderer.invoke('dbg:connected'),

    onPaused:    (cb: (info: unknown) => void) => {
      ipcRenderer.on(IPC.DBG_EVENT_PAUSED, (_, info) => cb(info))
      return () => ipcRenderer.removeAllListeners(IPC.DBG_EVENT_PAUSED)
    },
    onStopped:   (cb: (info: unknown) => void) => {
      ipcRenderer.on(IPC.DBG_EVENT_STOPPED, (_, info) => cb(info))
      return () => ipcRenderer.removeAllListeners(IPC.DBG_EVENT_STOPPED)
    },
    onLog:       (cb: (msg: string) => void) => {
      ipcRenderer.on(IPC.DBG_EVENT_LOG, (_, msg) => cb(msg))
      return () => ipcRenderer.removeAllListeners(IPC.DBG_EVENT_LOG)
    },
  },

  // LM Studio
  lm: {
    getConfig:   () => ipcRenderer.invoke(IPC.LM_CONFIG_GET),
    setConfig:   (cfg: Partial<LMStudioConfig>) => ipcRenderer.invoke(IPC.LM_CONFIG_SET, cfg),
    models:      () => ipcRenderer.invoke(IPC.LM_MODELS),
    embedModels: () => ipcRenderer.invoke(IPC.LM_EMBED_MODELS),
    chat:        (messages: AIMessage[]) => ipcRenderer.invoke(IPC.LM_CHAT, messages),
  },

  // Agents
  agents: {
    start:      (options: AnalysisStartOptions) => ipcRenderer.invoke(IPC.AGENT_START, options),
    stop:       () => ipcRenderer.invoke(IPC.AGENT_STOP),
    status:     () => ipcRenderer.invoke(IPC.AGENT_STATUS),
    taskQueue:  () => ipcRenderer.invoke(IPC.AGENT_TASK_QUEUE),

    onLog:      (cb: (data: { agentId: string; log: unknown }) => void) => {
      ipcRenderer.on(IPC.AGENT_LOG, (_, data) => cb(data))
      return () => ipcRenderer.removeAllListeners(IPC.AGENT_LOG)
    },
    onFinding:  (cb: (finding: unknown) => void) => {
      ipcRenderer.on(IPC.AGENT_FINDING, (_, finding) => cb(finding))
      return () => ipcRenderer.removeAllListeners(IPC.AGENT_FINDING)
    },
    onStatus:   (cb: (status: unknown) => void) => {
      ipcRenderer.on(IPC.AGENT_STATUS, (_, status) => cb(status))
      return () => ipcRenderer.removeAllListeners(IPC.AGENT_STATUS)
    },
    onDisasmGraph: (cb: (update: DisasmGraphUpdate) => void) => {
      ipcRenderer.on(IPC.AGENT_DISASM_GRAPH_UPDATE, (_, update) => cb(update as DisasmGraphUpdate))
      return () => ipcRenderer.removeAllListeners(IPC.AGENT_DISASM_GRAPH_UPDATE)
    },
  },

  // Sessions
  sessions: {
    create:     (targetPath: string) => ipcRenderer.invoke(IPC.SESSION_NEW, targetPath),
    openFolder: (sessionId: string) => ipcRenderer.invoke(IPC.SESSION_OPEN_FOLDER, sessionId),
    list:       () => ipcRenderer.invoke(IPC.SESSION_LIST),
    save:       (session: unknown) => ipcRenderer.invoke(IPC.SESSION_SAVE, session),
  },

  // Findings
  findings: {
    update:     (finding: unknown) => ipcRenderer.invoke(IPC.FINDING_UPDATE, finding),
    confirm:    (id: string) => ipcRenderer.invoke(IPC.FINDING_CONFIRM, id),
    generatePoc:(finding: Finding) => ipcRenderer.invoke(IPC.FINDING_POC, finding),
    export:     (sessionId: string, format: 'json' | 'markdown' | 'html') =>
                  ipcRenderer.invoke(IPC.FINDING_EXPORT, sessionId, format),
  },

  reports: {
    latest:     (sessionId: string) => ipcRenderer.invoke(IPC.REPORT_LATEST, sessionId),
    openPath:   (filePath: string) => ipcRenderer.invoke(IPC.REPORT_OPEN_PATH, filePath),
    onGenerated:(cb: (report: unknown) => void) => {
      ipcRenderer.on(IPC.REPORT_GENERATED, (_, report) => cb(report))
      return () => ipcRenderer.removeAllListeners(IPC.REPORT_GENERATED)
    },
  },

  // Native dialogs
  dialog: {
    openFile: (): Promise<string | null> => ipcRenderer.invoke('dialog:open-file'),
  },
})

// ── Type augmentation for renderer ──────────────────────────
export type API = typeof import('./index')
