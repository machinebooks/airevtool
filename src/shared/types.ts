// ============================================================
// AIrevtool — Shared Types
// Used by both main process and renderer
// ============================================================

// ── Debugger / x64dbg ──────────────────────────────────────

export interface MemoryRegion {
  baseAddress: string   // hex string e.g. "0x00400000"
  size: number
  protection: string    // "R", "RW", "RX", "RWX", etc.
  type: string          // "image", "mapped", "private"
  moduleName?: string
}

export interface DisasmInstruction {
  address: string
  bytes: string
  mnemonic: string
  operands: string
  comment?: string
}

export interface Register {
  name: string
  value: string   // hex
  size: number    // bits
}

export interface Breakpoint {
  address: string
  type: 'software' | 'hardware' | 'memory'
  enabled: boolean
  condition?: string
  hitCount: number
}

export interface DebugSession {
  pid: number
  targetPath: string
  targetArch: 'x64' | 'x32'
  status: 'idle' | 'running' | 'paused' | 'stopped'
  startedAt: Date
}

export interface DebugState {
  session: DebugSession | null
  registers: Register[]
  callStack: CallFrame[]
  memoryMap: MemoryRegion[]
  breakpoints: Breakpoint[]
}

export interface CallFrame {
  address: string
  functionName: string
  moduleName: string
  offset: number
}

// ── LM Studio / AI ─────────────────────────────────────────

export interface LMStudioConfig {
  baseUrl: string         // default: "http://localhost:12345"
  model: string           // analysis model
  embeddingModel: string  // embedding model for RAG
  maxTokens: number
  temperature: number
  contextWindow: number
}

export interface AIMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

export interface AIResponse {
  content: string
  tokensUsed: number
  model: string
  finishReason: string
}

// ── Agent System ────────────────────────────────────────────

export type AgentType = 'memory' | 'disasm' | 'vulnerability' | 'report' | 'orchestrator'

export type AgentStatus = 'idle' | 'running' | 'waiting' | 'error' | 'completed'

export interface AgentState {
  id: string
  type: AgentType
  status: AgentStatus
  currentTask: string
  progress: number      // 0-100
  lastUpdate: Date
  findings: Finding[]
  logs: AgentLog[]
}

export interface AgentLog {
  timestamp: Date
  level: 'info' | 'warn' | 'error' | 'debug'
  message: string
}

export interface AgentTask {
  id: string
  agentType: AgentType
  priority: 'critical' | 'high' | 'normal' | 'low'
  payload: MemoryAnalysisTask | DisasmAnalysisTask | VulnScanTask | ReportTask
  status: 'queued' | 'running' | 'completed' | 'failed'
  createdAt: Date
  completedAt?: Date
}

export interface MemoryAnalysisTask {
  regions: MemoryRegion[]
  targetAddress?: string
  depth: 'shallow' | 'deep'
}

export interface DisasmAnalysisTask {
  startAddress: string
  endAddress?: string
  instructions: DisasmInstruction[]
  functionName?: string
}

export interface VulnScanTask {
  context: string        // accumulated analysis context
  targetModule: string
  previousFindings: Finding[]
}

export interface ReportTask {
  sessionId: string
  findings: Finding[]
  targetInfo: TargetInfo
}

export interface AnalysisStartOptions {
  sessionId: string
  analystPrompt?: string
}

// ── Vulnerability Findings ──────────────────────────────────

export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type VulnCategory =
  | 'buffer_overflow'
  | 'use_after_free'
  | 'format_string'
  | 'integer_overflow'
  | 'null_deref'
  | 'race_condition'
  | 'heap_corruption'
  | 'stack_overflow'
  | 'injection'
  | 'logic_error'
  | 'memory_leak'
  | 'uninitialized_memory'
  | 'arbitrary_write'
  | 'arbitrary_read'
  | 'other'

export interface Finding {
  id: string
  sessionId?: string
  severity: VulnSeverity
  category: VulnCategory
  title: string
  description: string
  address?: string
  moduleName?: string
  offset?: number
  codeContext: DisasmInstruction[]
  memoryContext?: string
  agentAnalysis: string
  exploitability: 'confirmed' | 'likely' | 'possible' | 'unlikely'
  cveReferences?: string[]
  cwe?: string
  cvssScore?: number
  impact?: string
  remediation?: string
  proofOfConcept?: string
  proofOfConceptGeneratedAt?: Date
  createdAt: Date
  confirmed: boolean
}

export interface ReportArtifact {
  id: string
  sessionId: string
  title: string
  format: 'markdown' | 'html' | 'json'
  content: string
  markdownPath?: string
  pdfPath?: string
  createdAt: Date
}

// ── Analysis Session ────────────────────────────────────────

export interface TargetInfo {
  path: string
  arch: 'x64' | 'x32'
  fileSize: number
  md5: string
  sha256: string
  pdbPath?: string
  modules: ModuleInfo[]
}

export interface ModuleInfo {
  name: string
  baseAddress: string
  size: number
  path: string
  hasDebugInfo: boolean
  isProtected: boolean
}

export interface AnalysisSession {
  id: string
  name: string
  targetInfo: TargetInfo
  status: 'active' | 'paused' | 'completed'
  agents: AgentState[]
  findings: Finding[]
  createdAt: Date
  updatedAt: Date
}

// ── IPC Channel names ───────────────────────────────────────

export const IPC = {
  // Debugger control
  DBG_START:           'dbg:start',
  DBG_STOP:            'dbg:stop',
  DBG_PAUSE:           'dbg:pause',
  DBG_RESUME:          'dbg:resume',
  DBG_STEP_IN:         'dbg:step-in',
  DBG_STEP_OVER:       'dbg:step-over',
  DBG_STEP_OUT:        'dbg:step-out',
  DBG_BP_SET:          'dbg:bp-set',
  DBG_BP_DELETE:       'dbg:bp-delete',
  DBG_BP_LIST:         'dbg:bp-list',
  DBG_MEM_READ:        'dbg:mem-read',
  DBG_MEM_MAP:         'dbg:mem-map',
  DBG_DISASM:          'dbg:disasm',
  DBG_REGS:            'dbg:regs',
  DBG_STATE:           'dbg:state',
  DBG_COMMAND:         'dbg:command',
  // Events from main → renderer
  DBG_EVENT_PAUSED:    'dbg:event:paused',
  DBG_EVENT_STOPPED:   'dbg:event:stopped',
  DBG_EVENT_LOG:       'dbg:event:log',

  // Agent control
  AGENT_START:         'agent:start',
  AGENT_STOP:          'agent:stop',
  AGENT_STATUS:        'agent:status',
  AGENT_LOG:           'agent:log',
  AGENT_FINDING:       'agent:finding',
  AGENT_TASK_QUEUE:    'agent:task-queue',

  // LM Studio
  LM_CONFIG_GET:       'lm:config-get',
  LM_CONFIG_SET:       'lm:config-set',
  LM_MODELS:           'lm:models',
  LM_CHAT:             'lm:chat',
  LM_EMBED_MODELS:     'lm:embed-models',

  // Session
  SESSION_NEW:         'session:new',
  SESSION_OPEN:        'session:open',
  SESSION_SAVE:        'session:save',
  SESSION_LIST:        'session:list',

  // Findings
  FINDING_UPDATE:      'finding:update',
  FINDING_CONFIRM:     'finding:confirm',
  FINDING_POC:         'finding:poc',
  FINDING_EXPORT:      'finding:export',

  // Reports
  REPORT_LATEST:       'report:latest',
  REPORT_GENERATED:    'report:generated',
  REPORT_OPEN_PATH:    'report:open-path',
} as const
