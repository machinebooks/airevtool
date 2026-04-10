import { useState, useEffect, useCallback } from 'react'
import { Toolbar } from './components/Toolbar'
import { DisasmView } from './components/DisasmView'
import { MemoryView } from './components/MemoryView'
import { RegistersView } from './components/RegistersView'
import { AgentDashboard } from './components/AgentDashboard'
import { FindingsPanel } from './components/FindingsPanel'
import { ChatPanel } from './components/ChatPanel'
import { LogPanel } from './components/LogPanel'
import { StatusBar } from './components/StatusBar'
import { SettingsPanel } from './components/SettingsPanel'
import type {
  AnalysisStartOptions,
  DebugState,
  AgentState,
  Finding,
  AgentLog,
  DisasmGraphEdge,
  DisasmGraphNode,
  MemoryRegion,
  Breakpoint,
  ReportArtifact,
} from '../shared/types'
import './styles/app.css'

export default function App() {
  // Session state — independent of x64dbg connection
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [targetPath, setTargetPath] = useState<string>('')
  const [arch, setArch] = useState<'x64' | 'x32'>('x64')

  // x64dbg state
  const [dbgConnected, setDbgConnected] = useState(false)
  const [dbgState, setDbgState] = useState<DebugState | null>(null)
  const [dbgLogs, setDbgLogs] = useState<string[]>([])
  const [memoryRegions, setMemoryRegions] = useState<MemoryRegion[]>([])
  const [disasmNodes, setDisasmNodes] = useState<DisasmGraphNode[]>([])
  const [disasmEdges, setDisasmEdges] = useState<DisasmGraphEdge[]>([])
  const [breakpoints, setBreakpoints] = useState<Breakpoint[]>([])

  // Agent state
  const [agentStates, setAgentStates] = useState<AgentState[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [agentLogs, setAgentLogs] = useState<{ agentId: string; log: AgentLog }[]>([])
  const [agentsRunning, setAgentsRunning] = useState(false)
  const [latestReport, setLatestReport] = useState<ReportArtifact | null>(null)
  const [showAnalyzePrompt, setShowAnalyzePrompt] = useState(false)
  const [analysisPrompt, setAnalysisPrompt] = useState('')

  // UI
  const [activePanel, setActivePanel] = useState<'disasm' | 'memory' | 'agents' | 'findings' | 'chat' | 'settings'>('agents')

  const api = (window as unknown as { api: ReturnType<typeof buildApi> }).api

  const currentInstructionAddress = dbgState?.registers.find(r => r.name === 'RIP' || r.name === 'EIP')?.value

  const refreshDebuggerSnapshot = useCallback(async (focusAddress?: string) => {
    if (!dbgConnected) return

    try {
      const [stateResult, memoryResult, breakpointResult] = await Promise.all([
        api.dbg.state(),
        api.dbg.memMap().catch(() => []),
        api.dbg.breakpoints().catch(() => []),
      ])

      const nextState = stateResult as DebugState
      const nextMemoryMap = memoryResult as MemoryRegion[]
      const nextBreakpoints = breakpointResult as Breakpoint[]
      const instructionAddress = focusAddress
        ?? nextState.registers.find(r => r.name === 'RIP' || r.name === 'EIP')?.value

      setDbgState({
        ...nextState,
        memoryMap: nextMemoryMap,
        breakpoints: nextBreakpoints,
      })
      setMemoryRegions(nextMemoryMap)
      setBreakpoints(nextBreakpoints)

      if (!instructionAddress) return
    } catch {
      setDbgConnected(false)
    }
  }, [api.dbg, dbgConnected])

  // ── Subscribe to events ──────────────────────────────────────

  useEffect(() => {
    const unsubPaused = api.dbg.onPaused(async (info) => {
      const address = typeof info === 'object' && info !== null && 'address' in info
        ? String((info as { address?: unknown }).address ?? '')
        : undefined
      await refreshDebuggerSnapshot(address)
    })

    const unsubStopped = api.dbg.onStopped(() => {
      setDbgConnected(false)
      setDbgState(null)
      setMemoryRegions([])
      setDisasmNodes([])
      setDisasmEdges([])
      setBreakpoints([])
    })

    const unsubLog = api.dbg.onLog((msg) => {
      setDbgLogs(prev => [...prev.slice(-500), msg as string])
    })

    const unsubAgentLog = api.agents.onLog((data) => {
      setAgentLogs(prev => [...prev.slice(-1000), data as { agentId: string; log: AgentLog }])
    })

    const unsubFinding = api.agents.onFinding((finding) => {
      const nextFinding = finding as Finding
      setFindings(prev => {
        const next = prev.filter(item => item.id !== nextFinding.id)
        return [nextFinding, ...next]
      })
    })

    const unsubStatus = api.agents.onStatus((status) => {
      const states = status as AgentState[]
      setAgentStates(states)
      setAgentsRunning(states.some(a => a.status === 'running' || a.status === 'waiting'))
    })

    const unsubDisasmGraph = api.agents.onDisasmGraph((update) => {
      setDisasmNodes(prev => mergeGraphNodes(prev, update.nodes))
      setDisasmEdges(prev => mergeGraphEdges(prev, update.edges))
    })

    const unsubReport = api.reports.onGenerated((report) => {
      setLatestReport(report as ReportArtifact)
      setAgentLogs(prev => [
        ...prev.slice(-999),
        {
          agentId: 'report',
          log: {
            timestamp: new Date(),
            level: 'info',
            message: `Final report generated: ${(report as ReportArtifact).title}`,
          },
        },
      ])
    })

    return () => {
      unsubPaused(); unsubStopped(); unsubLog()
      unsubAgentLog(); unsubFinding(); unsubStatus(); unsubReport(); unsubDisasmGraph()
    }
  }, [api.agents, api.dbg, refreshDebuggerSnapshot])

  useEffect(() => {
    if (!sessionId) {
      setLatestReport(null)
      return
    }

    api.reports.latest(sessionId)
      .then(report => setLatestReport((report as ReportArtifact | null) ?? null))
      .catch(() => setLatestReport(null))
  }, [api.reports, sessionId])

  useEffect(() => {
    if (!dbgConnected || !sessionId) return

    const timer = window.setInterval(() => {
      refreshDebuggerSnapshot().catch(() => {})
    }, 2500)

    return () => window.clearInterval(timer)
  }, [dbgConnected, refreshDebuggerSnapshot, sessionId])

  useEffect(() => {
    if (!dbgConnected) return
    if (activePanel !== 'disasm' && activePanel !== 'memory') return
    refreshDebuggerSnapshot().catch(() => {})
  }, [activePanel, dbgConnected, refreshDebuggerSnapshot])

  // ── Handlers ─────────────────────────────────────────────────

  const handleBrowse = useCallback(async () => {
    const path = await api.dialog.openFile()
    if (path) setTargetPath(path)
  }, [])

  const handleLoadTarget = useCallback(async () => {
    if (!targetPath) return

    setDisasmNodes([])
    setDisasmEdges([])

    // 1. Create session regardless of x64dbg connection
    const session = await api.sessions.create(targetPath) as { id: string }
    setSessionId(session.id)

    // 2. Try to connect to x64dbg plugin and launch target
    try {
      const connection = await api.dbg.connect() as { connected?: boolean }
      if (!connection?.connected) throw new Error('x64dbg unavailable')
      setDbgConnected(true)
      await api.dbg.start(targetPath, arch)
    } catch {
      // x64dbg not running — session still active, agents can run without live debugging
      setDbgConnected(false)
    }
  }, [api.dbg, targetPath, arch])

  const handleStartAgents = useCallback(async () => {
    if (!sessionId || agentsRunning) return
    setShowAnalyzePrompt(true)
  }, [agentsRunning, sessionId])

  const handleConfirmStartAgents = useCallback(async () => {
    if (!sessionId) return
    setAgentsRunning(true)
    setShowAnalyzePrompt(false)
    setDisasmNodes([])
    setDisasmEdges([])
    try {
      const options: AnalysisStartOptions = {
        sessionId,
        analystPrompt: analysisPrompt.trim() || undefined,
      }
      await api.agents.start(options)
    } catch {
      setAgentsRunning(false)
    }
  }, [analysisPrompt, api.agents, sessionId])

  const handleStopAgents = useCallback(async () => {
    await api.agents.stop()
    setAgentsRunning(false)
  }, [api.agents])

  const handleStop = useCallback(async () => {
    try { await api.dbg.stop() } catch {}
    await api.agents.stop()
    setDbgConnected(false)
    setDbgState(null)
    setMemoryRegions([])
    setDisasmNodes([])
    setDisasmEdges([])
    setBreakpoints([])
    setAgentsRunning(false)
    setSessionId(null)
    setTargetPath('')
  }, [api.agents, api.dbg])

  const handleOpenSessionFolder = useCallback(async () => {
    if (!sessionId) return
    await api.sessions.openFolder(sessionId).catch(() => {})
  }, [api.sessions, sessionId])

  const handleFindingUpdated = useCallback((updatedFinding: Finding) => {
    setFindings(prev => {
      const next = prev.map(finding => finding.id === updatedFinding.id ? updatedFinding : finding)
      return next.some(finding => finding.id === updatedFinding.id) ? next : [updatedFinding, ...next]
    })
  }, [])

  const criticalCount = findings.filter(f => f.severity === 'critical').length
  const highCount     = findings.filter(f => f.severity === 'high').length
  const highlightedAddresses = Array.from(new Set([
    ...findings.map(f => f.address).filter((address): address is string => Boolean(address)),
    ...agentStates.flatMap(agent => {
      const matches = agent.currentTask.match(/0x[0-9a-f]+/gi)
      return matches ?? []
    }),
  ]))

  return (
    <div className="app">
      <Toolbar
        sessionId={sessionId}
        targetPath={targetPath}
        arch={arch}
        dbgConnected={dbgConnected}
        agentsRunning={agentsRunning}
        agentStates={agentStates}
        onBrowse={handleBrowse}
        onArchChange={setArch}
        onLoad={handleLoadTarget}
        onOpenSessionFolder={handleOpenSessionFolder}
        onStop={handleStop}
        onPause={() => api.dbg.pause().catch(() => {})}
        onResume={() => api.dbg.resume().catch(() => {})}
        onStepIn={() => api.dbg.stepIn().catch(() => {})}
        onStepOver={() => api.dbg.stepOver().catch(() => {})}
        onStepOut={() => api.dbg.stepOut().catch(() => {})}
        onStartAgents={handleStartAgents}
        onStopAgents={handleStopAgents}
      />

      <div className="workspace">
        <nav className="side-nav">
          {([
            { id: 'agents',   icon: '🤖', label: 'Agents' },
            { id: 'findings', icon: '🔍', label: 'Findings', badge: criticalCount + highCount },
            { id: 'chat',     icon: '💬', label: 'Chat' },
            { id: 'disasm',   icon: '⚡', label: 'Disasm' },
            { id: 'memory',   icon: '🧠', label: 'Memory' },
            { id: 'settings', icon: '⚙', label: 'Config' },
          ] as const).map(tab => (
            <button
              key={tab.id}
              className={`nav-tab ${activePanel === tab.id ? 'active' : ''}`}
              onClick={() => setActivePanel(tab.id)}
            >
              <span className="nav-icon">{tab.icon}</span>
              <span className="nav-label">{tab.label}</span>
              {'badge' in tab && tab.badge > 0 && (
                <span className="nav-badge">{tab.badge}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="content">
          <div className="content-main">
            {activePanel === 'disasm' && (
              <DisasmView
                nodes={disasmNodes}
                edges={disasmEdges}
                currentAddress={currentInstructionAddress}
                breakpoints={breakpoints}
              />
            )}
            {activePanel === 'memory' && (
              <MemoryView
                regions={memoryRegions}
                currentAddress={currentInstructionAddress}
                highlightedAddresses={highlightedAddresses}
              />
            )}
            {activePanel === 'agents' && (
              <AgentDashboard agents={agentStates} logs={agentLogs} />
            )}
            {activePanel === 'findings' && (
              <FindingsPanel
                findings={findings}
                sessionId={sessionId}
                latestReport={latestReport}
                onFindingUpdated={handleFindingUpdated}
                onOpenSessionFolder={handleOpenSessionFolder}
              />
            )}
            {activePanel === 'chat' && (
              <ChatPanel findings={findings} latestReport={latestReport} />
            )}
            {activePanel === 'settings' && (
              <SettingsPanel />
            )}
          </div>

          <div className="sidebar-right">
            <RegistersView registers={dbgState?.registers ?? []} />
            <LogPanel logs={dbgLogs} title="Debugger Log" />
          </div>
        </div>
      </div>

      <StatusBar
        sessionId={sessionId}
        targetPath={targetPath}
        dbgConnected={dbgConnected}
        dbgState={dbgState}
        agentStates={agentStates}
        findingCount={findings.length}
        criticalCount={criticalCount}
      />

      {showAnalyzePrompt && (
        <div className="modal-overlay">
          <div className="modal-card">
            <div className="modal-title">Adjust Analysis Prompt</div>
            <div className="modal-subtitle">
              Add optional analyst guidance to steer memory, disassembly, classification, exploit development, and report generation.
            </div>
            <textarea
              className="analysis-prompt-input"
              value={analysisPrompt}
              onChange={event => setAnalysisPrompt(event.target.value)}
              placeholder="Example: Prioritize likely RCE paths, exploit primitives, 0-day candidates, and crash-to-control-flow opportunities. Do not include remediation."
              autoFocus
            />
            <div className="modal-actions">
              <button onClick={() => setShowAnalyzePrompt(false)}>Cancel</button>
              <button className="primary" onClick={handleConfirmStartAgents}>Start Analysis</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// dummy helper for typing only
function buildApi() { return (window as unknown as { api: unknown }).api as never }

function mergeGraphNodes(current: DisasmGraphNode[], incoming: DisasmGraphNode[]): DisasmGraphNode[] {
  const map = new Map(current.map(node => [node.id, node]))
  for (const node of incoming) {
    const existing = map.get(node.id)
    map.set(node.id, existing ? { ...existing, ...node, flags: node.flags.length > 0 ? node.flags : existing.flags } : node)
  }
  return [...map.values()]
}

function mergeGraphEdges(current: DisasmGraphEdge[], incoming: DisasmGraphEdge[]): DisasmGraphEdge[] {
  const map = new Map(current.map(edge => [edge.id, edge]))
  for (const edge of incoming) {
    map.set(edge.id, edge)
  }
  return [...map.values()]
}
