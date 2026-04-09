import { app, BrowserWindow, ipcMain, shell, dialog } from 'electron'
import { join } from 'path'
import { X64DbgBridge } from './x64dbg-bridge'
import { LMStudioClient } from './lmstudio-client'
import { AgentOrchestrator } from './agents/orchestrator'
import { Database } from './db/database'
import { ReportFileService } from './report-file-service'
import { IPC } from '../shared/types'
import type {
  LMStudioConfig,
  AIMessage,
  DebugSession,
  Finding,
  AnalysisStartOptions,
} from '../shared/types'

// ── Globals ─────────────────────────────────────────────────

let mainWindow: BrowserWindow | null = null
let dbgBridge: X64DbgBridge
let lmClient: LMStudioClient
let orchestrator: AgentOrchestrator
let database: Database
let reportFileService: ReportFileService

const DEV = !app.isPackaged

// ── Window ───────────────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 900,
    minWidth: 1200,
    minHeight: 700,
    title: 'AIrevtool — AI Binary Analysis',
    backgroundColor: '#0d0d0d',
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0d0d0d',
      symbolColor: '#c9d1d9',
      height: 32,
    },
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  })

  if (DEV) {
    mainWindow.loadURL('http://localhost:5173')
  } else {
    mainWindow.loadFile(join(__dirname, '../../dist/index.html'))
  }

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url)
    return { action: 'deny' }
  })

  mainWindow.on('closed', () => { mainWindow = null })
}

// ── App lifecycle ────────────────────────────────────────────

app.whenReady().then(async () => {
  // Init subsystems
  database = new Database()
  await database.init()

  lmClient = new LMStudioClient()
  reportFileService = new ReportFileService()

  dbgBridge = new X64DbgBridge()
  dbgBridge.on('paused', (info) => {
    mainWindow?.webContents.send(IPC.DBG_EVENT_PAUSED, info)
  })
  dbgBridge.on('stopped', (info) => {
    mainWindow?.webContents.send(IPC.DBG_EVENT_STOPPED, info)
    orchestrator?.onDebugStopped(info)
  })
  dbgBridge.on('log', (msg) => {
    mainWindow?.webContents.send(IPC.DBG_EVENT_LOG, msg)
  })

  orchestrator = new AgentOrchestrator(lmClient, dbgBridge, database, reportFileService)
  orchestrator.on('agent-log', (agentId, log) => {
    mainWindow?.webContents.send(IPC.AGENT_LOG, { agentId, log })
  })
  orchestrator.on('finding', (finding) => {
    mainWindow?.webContents.send(IPC.AGENT_FINDING, finding)
    database.saveFinding(finding)
  })
  orchestrator.on('status', (status) => {
    mainWindow?.webContents.send(IPC.AGENT_STATUS, status)
  })
  orchestrator.on('report-generated', (report) => {
    mainWindow?.webContents.send(IPC.REPORT_GENERATED, report)
  })

  registerIPC()
  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  dbgBridge?.stop()
  orchestrator?.stopAll()
  if (process.platform !== 'darwin') app.quit()
})

// ── IPC Handlers ─────────────────────────────────────────────

// Validate hex address: optional 0x prefix, 1–16 hex digits
function isValidAddress(addr: string): boolean {
  return /^(0x)?[0-9a-fA-F]{1,16}$/.test(addr)
}

// x64dbg script commands allowed from the renderer
const DBG_COMMAND_ALLOWLIST = new Set([
  'anal', 'bp', 'bph', 'bpm', 'bpx', 'bd', 'be', 'bc', 'bpc', 'bpd', 'bpe',
  'g', 'p', 't', 'sti', 'sto', 'run', 'pause', 'ret',
  'log', 'msg', 'comment', 'lbl', 'symfollow',
  'disasm', 'd', 'dump', 'find', 'findall', 'ref', 'xref',
  'yara', 'asm', 'efl', 'cfl',
])

function isAllowedDbgCommand(cmd: string): boolean {
  if (typeof cmd !== 'string' || cmd.length === 0 || cmd.length > 512) return false
  const name = cmd.trim().split(/\s+/)[0].toLowerCase()
  return DBG_COMMAND_ALLOWLIST.has(name)
}

function registerIPC() {
  // ── Debugger control — all swallow errors when not connected ──
  const tryDbg = <T>(fn: () => Promise<T>) => fn().catch(() => null)

  ipcMain.handle(IPC.DBG_START, async (_, targetPath: string, arch: 'x64' | 'x32') => {
    if (typeof targetPath !== 'string' || targetPath.length === 0) return null
    return tryDbg(() => dbgBridge.startSession(targetPath, arch))
  })

  ipcMain.handle(IPC.DBG_STOP, async () => {
    return tryDbg(() => dbgBridge.stopSession())
  })

  ipcMain.handle(IPC.DBG_PAUSE, async () => {
    return tryDbg(() => dbgBridge.pause())
  })

  ipcMain.handle(IPC.DBG_RESUME, async () => {
    return tryDbg(() => dbgBridge.resume())
  })

  ipcMain.handle(IPC.DBG_STEP_IN, async () => {
    return tryDbg(() => dbgBridge.stepIn())
  })

  ipcMain.handle(IPC.DBG_STEP_OVER, async () => {
    return tryDbg(() => dbgBridge.stepOver())
  })

  ipcMain.handle(IPC.DBG_STEP_OUT, async () => {
    return tryDbg(() => dbgBridge.stepOut())
  })

  ipcMain.handle(IPC.DBG_BP_SET, async (_, address: string, type: 'software' | 'hardware' | 'memory') => {
    return dbgBridge.setBreakpoint(address, type)
  })

  ipcMain.handle(IPC.DBG_BP_DELETE, async (_, address: string) => {
    return dbgBridge.deleteBreakpoint(address)
  })

  ipcMain.handle(IPC.DBG_BP_LIST, async () => {
    return dbgBridge.listBreakpoints()
  })

  ipcMain.handle(IPC.DBG_MEM_READ, async (_, address: string, size: number) => {
    if (!isValidAddress(address)) return null
    const safeSize = Math.max(1, Math.min(Math.floor(size), 1024 * 1024))
    return dbgBridge.readMemory(address, safeSize)
  })

  ipcMain.handle(IPC.DBG_MEM_MAP, async () => {
    return dbgBridge.getMemoryMap()
  })

  ipcMain.handle(IPC.DBG_DISASM, async (_, address: string, count: number) => {
    if (!isValidAddress(address)) return null
    const safeCount = Math.max(1, Math.min(Math.floor(count), 10_000))
    return dbgBridge.disassemble(address, safeCount)
  })

  ipcMain.handle(IPC.DBG_REGS, async () => {
    return dbgBridge.getRegisters()
  })

  ipcMain.handle(IPC.DBG_STATE, async () => {
    return dbgBridge.getState()
  })

  ipcMain.handle(IPC.DBG_COMMAND, async (_, cmd: string) => {
    if (!isAllowedDbgCommand(cmd)) return null
    return dbgBridge.sendCommand(cmd)
  })

  // ── LM Studio ──
  ipcMain.handle(IPC.LM_CONFIG_GET, async () => {
    return lmClient.getConfig()
  })

  ipcMain.handle(IPC.LM_CONFIG_SET, async (_, config: Partial<LMStudioConfig>) => {
    const updated = lmClient.setConfig(config)
    // If embedding model changed, propagate to orchestrator RAG
    if (config.embeddingModel) {
      orchestrator.setEmbedModel(config.embeddingModel)
    }
    return updated
  })

  ipcMain.handle(IPC.LM_MODELS, async () => {
    return lmClient.listModels()
  })

  ipcMain.handle(IPC.LM_EMBED_MODELS, async () => {
    // Return all models — user picks which are for embedding
    return lmClient.listModels()
  })

  ipcMain.handle(IPC.LM_CHAT, async (_, messages: AIMessage[]) => {
    return lmClient.chat(messages)
  })

  // ── Agents ──
  ipcMain.handle(IPC.AGENT_START, async (_, options: AnalysisStartOptions) => {
    return orchestrator.startAnalysis(options)
  })

  ipcMain.handle(IPC.AGENT_STOP, async () => {
    return orchestrator.stopAll()
  })

  ipcMain.handle(IPC.AGENT_STATUS, async () => {
    return orchestrator.getStatus()
  })

  ipcMain.handle(IPC.AGENT_TASK_QUEUE, async () => {
    return orchestrator.getTaskQueue()
  })

  // ── Sessions ──
  ipcMain.handle(IPC.SESSION_NEW, async (_, targetPath: string) => {
    return database.createSession(targetPath)
  })

  ipcMain.handle(IPC.SESSION_LIST, async () => {
    return database.listSessions()
  })

  ipcMain.handle(IPC.SESSION_SAVE, async (_, session: unknown) => {
    return database.saveSession(session)
  })

  // ── Findings ──
  ipcMain.handle(IPC.FINDING_UPDATE, async (_, finding: unknown) => {
    return database.saveFinding(finding)
  })

  ipcMain.handle(IPC.FINDING_CONFIRM, async (_, findingId: string) => {
    return database.confirmFinding(findingId)
  })

  ipcMain.handle(IPC.FINDING_POC, async (_, finding: Finding) => {
    return orchestrator.generateFindingProofOfConcept(finding)
  })

  ipcMain.handle(IPC.FINDING_EXPORT, async (_, sessionId: string, format: 'json' | 'markdown' | 'html') => {
    const findings = await database.getFindings(sessionId)
    return orchestrator.exportReport(findings, format)
  })

  ipcMain.handle(IPC.REPORT_LATEST, async (_, sessionId: string) => {
    return database.getLatestReport(sessionId)
  })

  ipcMain.handle(IPC.REPORT_OPEN_PATH, async (_, filePath: string) => {
    if (!filePath) return { ok: false, error: 'Missing file path' }
    const result = await shell.openPath(filePath)
    return result ? { ok: false, error: result } : { ok: true }
  })

  // ── File dialog ──
  ipcMain.handle('dialog:open-file', async () => {
    if (!mainWindow) return null
    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'Select Binary to Analyze',
      properties: ['openFile'],
      filters: [
        { name: 'Executables', extensions: ['exe', 'dll', 'sys', 'drv', 'ocx', 'scr'] },
        { name: 'All Files', extensions: ['*'] },
      ],
    })
    return result.canceled ? null : result.filePaths[0]
  })

  // ── x64dbg connection status ──
  ipcMain.handle('dbg:connect', async () => {
    try {
      await dbgBridge.connect()
      return { connected: true }
    } catch (err) {
      return { connected: false, error: String(err) }
    }
  })

  ipcMain.handle('dbg:connected', async () => {
    return { connected: dbgBridge.isConnected() }
  })
}
