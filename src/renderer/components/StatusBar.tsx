import type { DebugState, AgentState } from '../../shared/types'

interface Props {
  sessionId: string | null
  targetPath: string
  dbgConnected: boolean
  dbgState: DebugState | null
  agentStates: AgentState[]
  findingCount: number
  criticalCount: number
}

export function StatusBar({ sessionId, targetPath, dbgConnected, dbgState, agentStates, findingCount, criticalCount }: Props) {
  const agentsRunning = agentStates.filter(a => a.status === 'running' || a.status === 'waiting').length
  const waitingAgents = agentStates.filter(a => a.status === 'waiting').length
  const fileName = targetPath ? targetPath.split(/[/\\]/).pop() : null
  const dbgStatus = dbgState?.session?.status

  return (
    <div className="status-bar">
      {/* Session */}
      <div className="status-item">
        <span className={`dot ${sessionId ? 'dot-green' : 'dot-gray'}`} />
        <span>{sessionId ? (fileName ?? 'session active') : 'no session'}</span>
      </div>

      <span className="status-sep">|</span>

      {/* x64dbg */}
      <div className="status-item">
        <span className={`dot ${dbgConnected ? 'dot-green' : 'dot-gray'}`} />
        <span style={{ color: dbgConnected ? 'var(--text-primary)' : 'var(--text-muted)' }}>
          {dbgConnected
            ? `x64dbg · ${dbgStatus ?? 'connected'}`
            : 'x64dbg not connected'}
        </span>
      </div>

      <span className="status-sep">|</span>

      {/* Agents */}
      <div className="status-item">
        <span className={`dot ${agentsRunning > 0 ? 'dot-blue' : 'dot-gray'}`} />
        <span>
          {agentsRunning > 0
            ? `${agentsRunning} active · ${waitingAgents > 0 ? `${waitingAgents} waiting on model` : 'processing'}`
            : 'agents idle'}
        </span>
      </div>

      <span className="status-sep">|</span>

      {/* Findings */}
      <div className="status-item">
        <span style={{ color: 'var(--text-muted)' }}>findings:</span>
        <span style={{ color: criticalCount > 0 ? 'var(--accent-red)' : 'var(--text-primary)' }}>
          {findingCount}
        </span>
        {criticalCount > 0 && (
          <span style={{ color: 'var(--accent-red)', fontWeight: 700 }}>({criticalCount} critical)</span>
        )}
      </div>

      {agentStates.length > 0 && (
        <>
          <span className="status-sep">|</span>
          <div className="status-item" style={{ gap: 10, flexWrap: 'wrap' }}>
            {agentStates.map(agent => (
              <AgentSummary key={agent.id} agent={agent} />
            ))}
          </div>
        </>
      )}

      {/* Right: LM Studio */}
      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--text-muted)' }}>
        <span className="dot dot-green" />
        LM Studio :12345
      </div>
    </div>
  )
}

function AgentSummary({ agent }: { agent: AgentState }) {
  const dotClass =
    agent.status === 'running'   ? 'dot dot-blue'   :
    agent.status === 'completed' ? 'dot dot-green'  :
    agent.status === 'error'     ? 'dot dot-red'    :
    agent.status === 'waiting'   ? 'dot dot-orange' : 'dot dot-gray'

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--text-muted)' }}>
      <span className={dotClass} />
      <span>{agent.type}</span>
      {(agent.status === 'running' || agent.status === 'waiting') && agent.progress > 0 && (
        <span style={{ color: 'var(--accent-blue)' }}>{agent.progress}%</span>
      )}
    </span>
  )
}
